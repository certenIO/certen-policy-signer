/**
 * Contract tests for the api-gateway external-signing seam (the optional vendor adapter).
 *
 * The fake gateway below enforces the REAL gateway's semantics, taken from its source:
 *   - X-API-Key (ck_live_…) required, 401 otherwise
 *   - POST /v1/sign returns 201 with signing_data.data_for_signature + submit_url
 *   - the VOTE is fixed at /v1/sign time (it is folded into the preimage; approve != reject)
 *   - the caller's public_key selects the preimage — omit it and you get bytes for the wrong key
 *   - a sign request is SINGLE-USE: replaying it 404s, and a failed submit consumes it too
 *
 * The point of these tests is that our client cannot quietly violate any of those and still look fine.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import nacl from 'tweetnacl';
import { GatewayClient, GatewayVoteBackend } from '../src/vote/adapters/certen-gateway.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { logger } from '../src/logger.js';
import { VotableTx } from '../src/vote/backend.js';

const silent = logger.child({ level: 'silent' });
const API_KEY = 'ck_live_test_key';
const IDENTITY = 'acc://org.acme';
const TX = 'ab'.repeat(32);
const SIGNER = new LocalSigner(new Uint8Array(32).fill(4));

const tx: VotableTx = { txHash: TX, signerUrl: 'acc://org.acme/book/1', signerVersion: 1, rawTransaction: {}, lastUsedOn: 0, account: 'acc://alice.acme/data' };

/** Server-side state, so tests can assert what the gateway actually saw. */
let signCalls: any[] = [];
let submitCalls: any[] = [];
let requests = new Map<string, { consumed: boolean; vote: string; publicKey: string }>();
let failNextSubmits = 0;         // simulate a stale key-page version -> 502
let pendingList: string[] = [];
let server: http.Server;
let port = 0;

/** The digest the gateway would hand back: distinct per (tx, vote, key) — as on the real network. */
const preimageFor = (txHash: string, vote: string, pk: string) =>
  createHash('sha256').update(`${txHash}.${vote}.${pk}`).digest('hex');

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    const send = (code: number, obj: unknown) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
    const url = new URL(req.url!, 'http://x');

    if (req.headers['x-api-key'] !== API_KEY) return send(401, { error: 'Authentication required' });

    if (req.method === 'GET' && url.pathname === '/v1/pending') {
      return send(200, { actions: pendingList.map((h) => ({ id: randomUUID(), tx_hash: h })), pagination: { limit: 500, offset: 0, total: pendingList.length } });
    }

    if (req.method === 'POST' && url.pathname === '/v1/sign') {
      signCalls.push(body);
      if (body.type !== 'pending_tx' || !body.target_id) return send(400, { error: 'type/target_id required' });
      const id = randomUUID();
      const pk = String(body.public_key ?? 'IDENTITY_DEFAULT_KEY');
      requests.set(id, { consumed: false, vote: String(body.vote ?? 'approve'), publicKey: pk });
      return send(201, {
        sign_request_id: id,
        status: 'signing_required',
        signing_data: {
          data_for_signature: preimageFor(String(body.target_id), String(body.vote ?? 'approve'), pk),
          transaction_hash: String(body.target_id),
          signer_url: body.signer_url ?? 'acc://org.acme/book/1',
          signer_version: 1,
          timestamp: 1700000000000000,
        },
        submit_url: `/v1/sign/${id}/signature`,
      });
    }

    const m = /^\/v1\/sign\/([0-9a-f-]{36})\/signature$/.exec(url.pathname);
    if (req.method === 'POST' && m) {
      const row = requests.get(m[1]);
      if (!row || row.consumed) return send(404, { error: 'sign request not found or already used' });
      row.consumed = true;                       // single-use, pass OR fail
      submitCalls.push({ id: m[1], ...body });
      if (!/^[a-f0-9]{128}$/.test(body.signature ?? '')) return send(400, { error: 'signature must be 128 hex' });
      if (failNextSubmits > 0) { failNextSubmits--; return send(502, { error: 'Failed to submit signature' }); }
      return send(200, { status: 'signed', tx_hash: TX, signature_count: 1, is_ready: true, awaiting_authorities: [] });
    }
    send(404, { error: 'not found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as any).port;
});
afterAll(() => server.close());
beforeEach(() => { signCalls = []; submitCalls = []; requests = new Map(); failNextSubmits = 0; pendingList = []; });

const client = (key = API_KEY) => new GatewayClient({ url: `http://127.0.0.1:${port}`, apiKey: key, identity: IDENTITY }, silent);
const backend = (key = API_KEY) => new GatewayVoteBackend(client(key), singleKeyring(SIGNER), silent);

describe('gateway seam: casting a vote', () => {
  it('approves: asks by tx hash, signs the bytes it is given, hands back a valid signature', async () => {
    const r = await backend().cast(tx, 'approve');
    expect(r.ok).toBe(true);

    expect(signCalls).toHaveLength(1);
    expect(signCalls[0]).toMatchObject({ type: 'pending_tx', target_id: TX, identity: IDENTITY, vote: 'approve' });

    // The signature must verify against OUR key over the exact digest the gateway asked for.
    const pub = await SIGNER.publicKey();
    const digest = preimageFor(TX, 'approve', Buffer.from(pub).toString('hex'));
    const sig = Buffer.from(submitCalls[0].signature, 'hex');
    expect(nacl.sign.detached.verify(Buffer.from(digest, 'hex'), sig, pub)).toBe(true);
    expect(submitCalls[0].public_key).toBe(Buffer.from(pub).toString('hex'));
  });

  it('declares our public key — otherwise the gateway computes the preimage for the WRONG key', async () => {
    await backend().cast(tx, 'approve');
    const pub = Buffer.from(await SIGNER.publicKey()).toString('hex');
    expect(signCalls[0].public_key).toBe(pub);   // not left to the identity's default binding
  });

  it('sends the vote at /v1/sign time: reject is a DIFFERENT preimage, not a flag on the same one', async () => {
    await backend().cast(tx, 'reject');
    expect(signCalls[0].vote).toBe('reject');

    const pub = await SIGNER.publicKey();
    const approveDigest = preimageFor(TX, 'approve', Buffer.from(pub).toString('hex'));
    const rejectDigest = preimageFor(TX, 'reject', Buffer.from(pub).toString('hex'));
    expect(rejectDigest).not.toBe(approveDigest);
    // we signed the REJECT bytes
    expect(nacl.sign.detached.verify(Buffer.from(rejectDigest, 'hex'), Buffer.from(submitCalls[0].signature, 'hex'), pub)).toBe(true);
  });

  it('recovers from a stale-version 502 by getting FRESH signing data (the old request is spent)', async () => {
    failNextSubmits = 1;
    const r = await backend().cast(tx, 'approve');
    expect(r.ok).toBe(true);
    expect(signCalls).toHaveLength(2);                        // asked again rather than replaying
    expect(submitCalls[0].id).not.toBe(submitCalls[1].id);    // a NEW sign request, not the consumed one
  });

  it('gives up (without signing anything else) when the gateway keeps failing', async () => {
    failNextSubmits = 99;
    const r = await backend().cast(tx, 'approve');
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/502|exhausted/);
  });

  it('REFUSES to sign when the gateway hands back a different transaction than we decided on', async () => {
    // A gateway that returns signing data for another tx must not get a signature out of us.
    const evil = new GatewayVoteBackend(
      { requestSigningData: async () => ({
          signRequestId: 'x', dataForSignature: 'ff'.repeat(32), transactionHash: 'cd'.repeat(32),  // <- not ours
          signerUrl: '', signerVersion: 1, timestamp: 0, submitUrl: '/v1/sign/x/signature',
        }),
        submitSignature: async () => ({ ok: true }),
      } as any,
      singleKeyring(SIGNER), silent,
    );
    const r = await evil.cast(tx, 'approve');
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/mismatch/i);
  });

  it('fails closed on a bad API key rather than pretending to have voted', async () => {
    const r = await backend('ck_live_wrong').cast(tx, 'approve');
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/401/);
  });
});

describe('gateway seam: discovery is a supplement, not a replacement', () => {
  it('reads tx hashes out of the gateway pending list', async () => {
    pendingList = [TX, 'cd'.repeat(32)];
    expect(await client().listPending()).toEqual([TX, 'cd'.repeat(32)]);
  });

  it('returns nothing (rather than throwing) when the gateway is unreachable, so on-chain discovery still runs', async () => {
    const dead = new GatewayClient({ url: 'http://127.0.0.1:1', apiKey: API_KEY, identity: IDENTITY, timeoutMs: 300 }, silent);
    await expect(dead.listPending()).resolves.toEqual([]);
  });
});
