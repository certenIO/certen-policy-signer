/**
 * Two parts of the integrator-facing policy contract:
 *
 *   1. `pending` — the engine saying "not decided yet" without spending a signature.
 *   2. Configurable signed-channel headers, so an integrator is not made to emit another vendor's names.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { HttpPolicyClient, DEFAULT_SIGNATURE_HEADER, DEFAULT_TIMESTAMP_HEADER, LEGACY_SIGNATURE_HEADER } from '../src/policy/policy.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Resolver } from '../src/resolver.js';
import { MemoryStore } from '../src/store/store.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { logger } from '../src/logger.js';
import { PolicyRequest, Decision } from '../src/types.js';

const silent = logger.child({ level: 'silent' });

let server: http.Server;
let port = 0;
let handler: (body: string, headers: http.IncomingHttpHeaders, res: http.ServerResponse) => void;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => handler(Buffer.concat(chunks).toString('utf8'), req.headers, res));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as any).port;
});
afterAll(() => server.close());

const url = () => `http://127.0.0.1:${port}/decision`;
const REQ: PolicyRequest = {
  requestId: 'r1', txHash: 'ab'.repeat(32), account: 'acc://a.acme/data',
  actionSummary: 'Transfer 4000 wei', value: '4000', expiresAt: new Date(0).toISOString(),
};

describe('a policy engine may answer "pending"', () => {
  it('is accepted as a valid decision rather than rejected as malformed', async () => {
    handler = (_b, _h, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'pending', reason: 'awaiting step-up auth' }));
    };
    const d = await new HttpPolicyClient({ url: url() }).decide(REQ);
    expect(d.decision).toBe('pending');
    expect(d.reason).toBe('awaiting step-up auth');
  });

  it('still rejects a genuinely malformed decision, and names what it got', async () => {
    handler = (_b, _h, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'maybe' }));
    };
    await expect(new HttpPolicyClient({ url: url() }).decide(REQ)).rejects.toThrow(/"maybe"/);
  });
});

describe('"pending" withholds the signature without recording a failure', () => {
  const TX = 'cd'.repeat(32);
  const PAGE = 'acc://o.acme/book/1';

  /** An orchestrator wired to an engine that returns a fixed decision. */
  function harness(decision: Decision, store = new MemoryStore(), acc = new MockAccumulateClient()) {
    acc.addPending(TX, {
      principal: 'acc://x.acme/tokens',
      body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '10' }] },
    });
    const orch = new Orchestrator({
      accumulate: acc,
      keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7)), PAGE),
      policy: new MockPolicyClient(decision),
      store,
      resolver: new Resolver(acc),
      logger: silent,
      // submit_reject_vote on, so "signed nothing" is a real claim: a deny here WOULD have submitted.
      options: { submitRejectVote: true },
    });
    return { orch, store, acc };
  }

  it('signs nothing at all — not an approve, not a reject', async () => {
    const { orch, acc } = harness({ decision: 'pending', reason: 'user has not completed the challenge' });
    await orch.handle({ txHash: TX, signerUrl: PAGE });
    expect(acc.submissions).toHaveLength(0);
  });

  it('leaves the request awaiting policy, so the next poll asks again', async () => {
    const { orch, store } = harness({ decision: 'pending' });
    await orch.handle({ txHash: TX, signerUrl: PAGE });
    expect((await store.get(TX))?.status).toBe('awaiting_policy');
  });

  it('records no error — waiting is not a fault, and must not mask a real one', async () => {
    const { orch, store } = harness({ decision: 'pending' });
    await orch.handle({ txHash: TX, signerUrl: PAGE });
    expect((await store.get(TX))?.lastError).toBeUndefined();
  });

  it('does not count as a failed attempt', async () => {
    const { orch, store } = harness({ decision: 'pending' });
    await orch.handle({ txHash: TX, signerUrl: PAGE });
    expect((await store.get(TX))?.attempts).toBe(0);
  });

  it('writes no receipt — nothing was decided, so there is nothing to attest', async () => {
    const { orch, store } = harness({ decision: 'pending' });
    await orch.handle({ txHash: TX, signerUrl: PAGE });
    expect(await store.getReceipt(TX)).toBeUndefined();
  });

  it('a later approve on the same tx still signs — pending is not terminal', async () => {
    const { orch, store, acc } = harness({ decision: 'pending' });
    await orch.handle({ txHash: TX, signerUrl: PAGE });
    expect(acc.submissions).toHaveLength(0);

    // Same store and chain state, engine now decides. This is the sequence an async challenge produces.
    const { orch: approving } = harness({ decision: 'approve', reason: 'challenge passed' }, store, acc);
    await approving.handle({ txHash: TX, signerUrl: PAGE });
    expect(acc.submissions).toHaveLength(1);
    expect((await store.get(TX))?.status).toBe('signed');
  });
});

describe('signed-channel header names are configurable', () => {
  const SECRET = 's3cret';
  const sign = (raw: string, ts = String(Date.now())) =>
    `t=${ts},v1=${createHmac('sha256', SECRET).update(`${ts}.${raw}`).digest('hex')}`;

  it('sends the neutral default header names', async () => {
    let seen: http.IncomingHttpHeaders = {};
    handler = (_b, h, res) => {
      seen = h;
      const raw = JSON.stringify({ decision: 'approve' });
      res.writeHead(200, { 'content-type': 'application/json', [DEFAULT_SIGNATURE_HEADER]: sign(raw) });
      res.end(raw);
    };
    await new HttpPolicyClient({ url: url(), hmacSecret: SECRET }).decide(REQ);
    expect(seen[DEFAULT_SIGNATURE_HEADER]).toMatch(/^t=\d+,v1=[a-f0-9]+$/);
    expect(seen[DEFAULT_TIMESTAMP_HEADER]).toMatch(/^\d+$/);
    expect(seen[LEGACY_SIGNATURE_HEADER]).toBeUndefined();
  });

  it('sends whatever header names the engine expects', async () => {
    let seen: http.IncomingHttpHeaders = {};
    handler = (_b, h, res) => {
      seen = h;
      const raw = JSON.stringify({ decision: 'approve' });
      res.writeHead(200, { 'content-type': 'application/json', 'x-acme-sig': sign(raw) });
      res.end(raw);
    };
    await new HttpPolicyClient({
      url: url(), hmacSecret: SECRET, signatureHeader: 'x-acme-sig', timestampHeader: 'x-acme-ts',
    }).decide(REQ);
    expect(seen['x-acme-sig']).toBeDefined();
    expect(seen['x-acme-ts']).toBeDefined();
  });

  it('still accepts the legacy response header, so an existing engine keeps working', async () => {
    const legacy: string[] = [];
    handler = (_b, _h, res) => {
      const raw = JSON.stringify({ decision: 'approve' });
      res.writeHead(200, { 'content-type': 'application/json', [LEGACY_SIGNATURE_HEADER]: sign(raw) });
      res.end(raw);
    };
    const d = await new HttpPolicyClient({
      url: url(), hmacSecret: SECRET, onLegacyHeader: (h) => legacy.push(h),
    }).decide(REQ);
    expect(d.decision).toBe('approve');
    expect(legacy).toEqual([LEGACY_SIGNATURE_HEADER]);   // surfaced once, as a deprecation
  });

  it('a wrong MAC under the configured header is still rejected — fail-closed is unchanged', async () => {
    handler = (_b, _h, res) => {
      res.writeHead(200, { 'content-type': 'application/json', [DEFAULT_SIGNATURE_HEADER]: `t=${Date.now()},v1=${'0'.repeat(64)}` });
      res.end(JSON.stringify({ decision: 'approve' }));
    };
    await expect(new HttpPolicyClient({ url: url(), hmacSecret: SECRET }).decide(REQ))
      .rejects.toThrow(/bad response auth/);
  });
});
