/**
 * AGT-F130 (gate run 1, world 10, 2026-11-22): a KEYED seat (its page holds the policy key) whose decision service answers `pending`
 * because two officers approve an above-cap payment with their OWN ed25519 keys through officer intake, delegated via the principal's
 * officers page. The seat casts no machine vote. When the officers' signatures land and execute the transaction, the seat's request must
 * END with a receipt stating the people's act, relayed by this signer -- with the time THIS intake submitted the threshold-completing
 * signature -- instead of sitting `awaiting_policy` for ever with no receipt.
 *
 * Driven through `buildOfficerIntake` (the wiring the FULL signer and the intake-only process both use) over a fake Accumulate client.
 * Every key is generated in memory by node:crypto and never written; every party, page and string is FICTIONAL.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import http from 'node:http';
import { createHash, generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { buildOfficerIntake } from '../src/intake-only.js';
import { officerAuthMessage } from '../src/officer/auth.js';
import { createServer } from '../src/server.js';
import { MemoryStore, FileStore, humanRecordId, type Store } from '../src/store/store.js';
import { bytesToHex, concatBytes, hexToBytes } from '../src/accumulate/signing.js';
import { memoryPauseStore } from '../src/binding/pause-store.js';
import { withDisplay } from '../src/display.js';
import { advanceAwaitingHuman, advancePersonalPath, type IntakeSubmission } from '../src/officer/landed.js';
import type { PageState } from '../src/ops/rotate.js';
import type { ChainSignature, TxSignatures } from '../src/accumulate/client.js';
import type { Config } from '../src/config.js';
import type { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import type { DecoderRegistry } from '../src/decode/registry.js';

const silent = pino({ level: 'silent' });

const SEAT = 'acc://fict-principal-f130.acme/book/2';        // the keyed seat's page: holds the policy key, casts nothing here
const OFFICERS = 'acc://fict-principal-f130.acme/book/3';    // the officers page: 2 of 2 delegate seats (the officers' books)
const O1_BOOK = 'acc://fict-officer-a-f130.acme/book';
const O2_BOOK = 'acc://fict-officer-b-f130.acme/book';
const O1 = `${O1_BOOK}/1`;
const O2 = `${O2_BOOK}/1`;
const PRINCIPAL = 'acc://fict-agent-f130.acme/data';
const POLICY_KEY = 'cc'.repeat(32);
const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());

interface Ed { priv: KeyObject; raw: Uint8Array; keyHash: string }
function newEd(): Ed {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = new Uint8Array(Buffer.from((publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url'));
  return { priv: privateKey, raw, keyHash: bytesToHex(sha(raw)) };
}
const edSign = (o: Ed, msg: Uint8Array) => new Uint8Array(nodeSign(null, msg, o.priv));

type Sig = ChainSignature;
/** A fake Accumulate client: pages as the v3 query returns them, one pending tx, a signature set that grows on submit. */
class FakeAcc {
  pages = new Map<string, { version: number; acceptThreshold: number; rejectThreshold?: number; keys: Array<{ publicKeyHash?: string; delegate?: string }> }>();
  pending = new Map<string, { principal: string; body: unknown }>();
  sigs = new Map<string, Sig[]>();
  submitCalledAt: number[] = [];
  /** Delay before a signature-set read answers: the landing is noticed well after the submission. */
  readDelayMs = 0;
  async query(url: string) {
    const p = this.pages.get(url.toLowerCase());
    if (!p) throw new Error(`FICTIONAL: no account ${url}`);
    return { account: { type: 'keyPage', url, ...p } };
  }
  async getPendingTx(hash: string, principal: string) {
    const t = this.pending.get(hash);
    if (!t || t.principal.toLowerCase() !== principal.toLowerCase()) return { found: false };
    return { found: true, principal: t.principal, body: t.body, rawTransaction: { header: { principal: t.principal }, body: t.body } };
  }
  async getSignerInfo(page: string) { return { version: this.pages.get(page.toLowerCase())?.version ?? 1, lastUsedOn: 0 }; }
  async getTxSignatures(hash: string): Promise<TxSignatures> {
    if (this.readDelayMs) await new Promise((r) => setTimeout(r, this.readDelayMs));
    return { status: 'delivered', delivered: true, signatures: [...(this.sigs.get(hash) ?? [])] };
  }
  async submit(envelope: any) {
    this.submitCalledAt.push(Date.now());
    let s = envelope.signatures[0];
    const delegators: string[] = [];
    while (s.type === 'delegated') { delegators.push(String(s.delegator)); s = s.signature; }
    const hash = String(s.transactionHash);
    const list = this.sigs.get(hash) ?? [];
    list.push({ type: s.type, publicKeyHash: bytesToHex(sha(hexToBytes(s.publicKey))), delegators, hops: [...delegators].reverse(), signer: String(s.signer), vote: s.vote === 'reject' || s.vote === 1 ? 'reject' : 'approve' });
    this.sigs.set(hash, list);
    return { ok: true };
  }
}

function listen(s: http.Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as { port: number }).port)));
}
function call(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: unknown) {
  return new Promise<{ status: number; json: any }>((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => resolve({ status: res.statusCode!, json: t ? JSON.parse(t) : null }));
    });
    r.on('error', reject);
    if (body !== undefined) r.write(JSON.stringify(body));
    r.end();
  });
}

const PREP = '/relay/officer-signature/prepare';
const cfgFor = (): Config => ({
  officer_intake: { enabled: true, human_pages: [OFFICERS], landed_timeout_ms: 2_000 },
  decoders: { labels: {}, evm_abi: [] },
} as unknown as Config);
const noDecoders = { decode: () => { throw new Error('FICTIONAL: no decoder needed, the request is stored'); } } as unknown as DecoderRegistry;

/** A signer process: the store, the intake built by `buildOfficerIntake` (the full signer's wiring), and its HTTP server. */
async function boot(acc: FakeAcc, store: Store) {
  const intake = buildOfficerIntake(cfgFor(), acc as unknown as RawAccumulateClient, store, noDecoders, silent);
  await intake.restore();
  const server = createServer({ officerIntake: intake.handle, orchestrator: {} as any, store, keyring: {} as any, accumulate: {} as any, pause: memoryPauseStore(), logger: silent });
  const port = await listen(server);
  return { server, port };
}

/** An officer signs `vote` on `tx` through the intake: prepare (delegated auth), sign the Accumulate ed25519 preimage, submit. */
async function officerSigns(port: number, o: Ed, page: string, tx: string, vote: 'approve' | 'reject') {
  const ts = Date.now();
  const auth = `v1 key=${bytesToHex(o.raw)},ts=${ts},sig=${bytesToHex(edSign(o, officerAuthMessage('POST', PREP, String(ts))))},page=${page},delegators=${OFFICERS}`;
  const prep = await call(port, 'POST', PREP, { 'x-officer-auth': auth }, { ref: tx, page, delegators: [OFFICERS], vote });
  expect(prep.status, JSON.stringify(prep.json)).toBe(200);
  const sig = edSign(o, sha(concatBytes(hexToBytes(prep.json.sigMdHash), hexToBytes(prep.json.txHash))));
  const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: bytesToHex(sig) });
  expect(r.status, JSON.stringify(r.json)).toBe(200);
  expect(r.json.status).toBe('landed');
}

let o1: Ed, o2: Ed;
beforeAll(() => { o1 = newEd(); o2 = newEd(); });

function world(tx: string, opts: { rejectThreshold?: number } = {}) {
  const acc = new FakeAcc();
  acc.pages.set(SEAT.toLowerCase(), { version: 1, acceptThreshold: 1, keys: [{ publicKeyHash: POLICY_KEY }] });
  acc.pages.set(OFFICERS.toLowerCase(), { version: 1, acceptThreshold: 2, ...(opts.rejectThreshold ? { rejectThreshold: opts.rejectThreshold } : {}), keys: [{ delegate: O1_BOOK }, { delegate: O2_BOOK }] });
  acc.pages.set(O1.toLowerCase(), { version: 1, acceptThreshold: 1, keys: [{ publicKeyHash: o1.keyHash }] });
  acc.pages.set(O2.toLowerCase(), { version: 1, acceptThreshold: 1, keys: [{ publicKeyHash: o2.keyHash }] });
  acc.pending.set(tx, { principal: PRINCIPAL, body: { type: 'writeData', entry: { type: 'doubleHash', data: ['00'] } } });
  return acc;
}

/** The keyed seat's request as the orchestrator leaves it on the personal path: `awaiting_policy`, a pending hold, no receipt. */
async function seatHeld(store: Store, tx: string) {
  await store.savePolicyRequest(withDisplay({ requestId: 'f130', txHash: tx, account: PRINCIPAL, actionSummary: 'Pay 40,000 ftUSD to Vendor A (FICTIONAL)', expiresAt: '2026-12-01T00:00:00Z', bodyType: 'writeData' }));
  await store.create({
    txHash: tx, signerUrl: SEAT, account: PRINCIPAL, status: 'awaiting_policy', attempts: 0, createdAt: 1, updatedAt: 1, operationId: 'op-f130',
    pending: { reason: 'awaiting_personal_signature (FICTIONAL)', versions: {}, since: '2026-11-22T02:58:00.000Z', lastEvaluatedAt: '2026-11-22T02:59:00.000Z', evaluations: 3, history: [] },
  } as never);
}

describe('AGT-F130: the full signer records the people\'s act on a keyed seat held on the personal path', () => {
  it('officer 1 alone: counted, request stays open, no receipt; officer 2 completes the threshold: request signed with a personal-path receipt', async () => {
    const TX = '4558c004'.repeat(8);
    const acc = world(TX);
    const store = new MemoryStore();
    await seatHeld(store, TX);
    const p = await boot(acc, store);
    try {
      await officerSigns(p.port, o1, O1, TX, 'approve');
      const after1 = await store.get(TX);
      expect(after1?.status).toBe('awaiting_policy');
      expect(after1?.humanSignatures).toEqual([{ seat: `delegate:${O1_BOOK}`, publicKeyHash: o1.keyHash, type: 'ed25519', delegators: [OFFICERS], vote: 'approve' }]);
      expect(await store.getReceipt(TX)).toBeUndefined();

      acc.readDelayMs = 80; // the landing of officer 2's signature is noticed well after it was sent
      await officerSigns(p.port, o2, O2, TX, 'approve');
      const done = await store.get(TX);
      expect(done?.status).toBe('signed');
      expect(done?.pending).toBeUndefined();
      expect(done?.pendingFinal).toMatchObject({ outcome: 'personal:approve', reason: 'awaiting_personal_signature (FICTIONAL)' });
      expect(done?.humanSignatures?.map((s) => s.publicKeyHash).sort()).toEqual([o1.keyHash, o2.keyHash].sort());

      const rc = (await store.getReceipt(TX))!;
      expect(rc).toMatchObject({
        txHash: TX, operationId: 'op-f130', vote: 'approve',
        signedBy: { page: O1, signatureType: 'ed25519', publicKeyHash: o1.keyHash, delegators: [OFFICERS] },
        policyEvidence: { personalSignature: { page: OFFICERS, vote: 'approve', relayedBy: 'this-signer', completingKeyHash: o2.keyHash } },
      });
      expect(rc.humanSignatures).toHaveLength(2);
      expect(rc.signatureHash).toBeUndefined();   // no machine signature
      expect(rc.decision).toBeUndefined();        // the engine decided nothing
      expect(rc.humanOverride).toBeUndefined();
      // submittedAt is when THIS intake sent officer 2's (the threshold-completing) signature -- not when the landing was noticed.
      expect(typeof rc.submittedAt).toBe('number');
      expect(rc.submittedAt!).toBeLessThanOrEqual(acc.submitCalledAt[1]!);
      expect(rc.submittedAt!).toBeGreaterThan(acc.submitCalledAt[0]!);
      expect(rc.recordedAt! - rc.submittedAt!).toBeGreaterThanOrEqual(80);
      // the time is persisted per prepare in the intake state
      const subs = (await store.listIntakeRecords('submission')) as unknown as IntakeSubmission[];
      expect(subs.find((s) => s.keyHash === o2.keyHash)?.submittedAt).toBe(rc.submittedAt);
      // and nothing was submitted for the seat's own page: only the two officers' signatures
      expect(acc.sigs.get(TX)!.map((s) => s.publicKeyHash).sort()).toEqual([o1.keyHash, o2.keyHash].sort());
    } finally { p.server.close(); }
  });

  it('a restart between the two officers keeps officer 1\'s submission time; the receipt still names officer 2\'s', async () => {
    const TX = '5a5a5a5a'.repeat(8);
    const acc = world(TX);
    const path = join(mkdtempSync(join(tmpdir(), 'f130-')), 'state.json');
    const s1 = new FileStore(path);
    await seatHeld(s1, TX);
    const a = await boot(acc, s1);
    await officerSigns(a.port, o1, O1, TX, 'approve');
    a.server.close();

    const s2 = new FileStore(path);
    const kept = (await s2.listIntakeRecords('submission')) as unknown as IntakeSubmission[];
    expect(kept.map((k) => k.keyHash)).toEqual([o1.keyHash]);
    const b = await boot(acc, s2);
    try {
      await officerSigns(b.port, o2, O2, TX, 'approve');
      expect((await s2.get(TX))?.status).toBe('signed');
      const rc = (await s2.getReceipt(TX))!;
      expect(rc.policyEvidence).toMatchObject({ personalSignature: { relayedBy: 'this-signer', completingKeyHash: o2.keyHash } });
      expect(rc.submittedAt).toBe(((await s2.listIntakeRecords('submission')) as unknown as IntakeSubmission[]).find((s) => s.keyHash === o2.keyHash)!.submittedAt);
    } finally { b.server.close(); }
  });

  it('two rejections meeting the reject threshold end the request rejected, with a personal reject receipt', async () => {
    const TX = '6b6b6b6b'.repeat(8);
    const acc = world(TX);
    const store = new MemoryStore();
    await seatHeld(store, TX);
    const p = await boot(acc, store);
    try {
      await officerSigns(p.port, o1, O1, TX, 'reject');
      expect((await store.get(TX))?.status).toBe('awaiting_policy');
      await officerSigns(p.port, o2, O2, TX, 'reject');
      expect((await store.get(TX))?.status).toBe('rejected');
      expect(await store.getReceipt(TX)).toMatchObject({ vote: 'reject', policyEvidence: { personalSignature: { page: OFFICERS, vote: 'reject' } } });
    } finally { p.server.close(); }
  });

  it('a human-only seat on the officers page is still advanced exactly as before (G-69) by the same hook', async () => {
    const TX = '7c7c7c7c'.repeat(8);
    const acc = world(TX);
    const store = new MemoryStore();
    await store.savePolicyRequest(withDisplay({ requestId: 'h', txHash: TX, account: PRINCIPAL, actionSummary: 'FICTIONAL', expiresAt: '2026-12-01T00:00:00Z', bodyType: 'writeData' }));
    const KEY = humanRecordId(TX, OFFICERS);
    await store.create({ txHash: TX, recordId: KEY, signerUrl: OFFICERS, account: PRINCIPAL, status: 'awaiting_human', attempts: 0, createdAt: 1, updatedAt: 1 } as never);
    const p = await boot(acc, store);
    try {
      await officerSigns(p.port, o1, O1, TX, 'approve');
      expect((await store.get(KEY))?.status).toBe('awaiting_human');
      await officerSigns(p.port, o2, O2, TX, 'approve');
      expect((await store.get(KEY))?.status).toBe('signed');
      const rc = (await store.getReceipt(KEY))!;
      expect(rc).toMatchObject({ vote: 'approve', signedBy: { page: OFFICERS } });
      expect(rc.policyEvidence?.personalSignature).toBeUndefined();
    } finally { p.server.close(); }
  });
});

describe('AGT-F130: advancePersonalPath, unit', () => {
  const TX = '8d'.repeat(32);
  const pages: Record<string, PageState> = {
    [OFFICERS]: { version: 1, threshold: 2, rejectThreshold: 0, keyHashes: [], entries: [{ keyHash: null, delegate: O1_BOOK }, { keyHash: null, delegate: O2_BOOK }] } as PageState,
    [O1]: { version: 1, threshold: 1, rejectThreshold: 0, keyHashes: ['a1'.repeat(32)], entries: [{ keyHash: 'a1'.repeat(32), delegate: null }] } as PageState,
    [O2]: { version: 1, threshold: 1, rejectThreshold: 0, keyHashes: ['a2'.repeat(32)], entries: [{ keyHash: 'a2'.repeat(32), delegate: null }] } as PageState,
  };
  const readPage = async (pg: string) => { const s = pages[pg]; if (!s) throw new Error(`FICTIONAL: no page ${pg}`); return s; };
  const sig = (k: string, signer: string, vote: 'approve' | 'reject' = 'approve'): Sig => ({ type: 'ed25519', publicKeyHash: k, delegators: [OFFICERS], hops: [OFFICERS], signer, vote });
  const sub = (k: string, page: string, at: number, vote: 'approve' | 'reject' = 'approve'): IntakeSubmission => ({ prepareId: `p-${k.slice(0, 4)}`, txHash: TX, keyHash: k, page, delegators: [OFFICERS], vote, submittedAt: at });
  const landed = (k: string, page: string, at: number, subs: IntakeSubmission[], vote: 'approve' | 'reject' = 'approve') =>
    ({ txHash: TX, authority: OFFICERS, page, delegators: [OFFICERS], keyHash: k, vote, submittedAt: at, submissions: subs });
  const A1 = 'a1'.repeat(32), A2 = 'a2'.repeat(32);
  const keyed = async (store: MemoryStore, extra: Record<string, unknown> = {}) =>
    store.create({ txHash: TX, signerUrl: SEAT, account: PRINCIPAL, status: 'awaiting_policy', attempts: 0, createdAt: 1, updatedAt: 1, ...extra } as never);

  it('the threshold-completing submission is the one whose time is recorded, whichever officer\'s landing is noticed first', async () => {
    const store = new MemoryStore();
    await keyed(store);
    const subs = [sub(A1, O1, 1_000), sub(A2, O2, 2_000)];
    const deps = { store, readPage, getTxSignatures: async () => ({ status: 'delivered', delivered: true, signatures: [sig(A2, O2), sig(A1, O1)] }), now: () => 9_999 };
    // officer 1's landing is noticed only after both are on chain: still officer 2's submission completed the threshold
    await advancePersonalPath(deps, landed(A1, O1, 1_000, subs));
    expect((await store.get(TX))?.status).toBe('signed');
    expect(await store.getReceipt(TX)).toMatchObject({ submittedAt: 2_000, policyEvidence: { personalSignature: { completingKeyHash: A2 } } });
  });

  it('a decisive signature this intake did not submit: the request ends (the people decided) but no relay time is claimed', async () => {
    const store = new MemoryStore();
    await keyed(store);
    const deps = { store, readPage, getTxSignatures: async () => ({ status: 'delivered', delivered: true, signatures: [sig(A1, O1), sig(A2, O2)] }) };
    await advancePersonalPath(deps, landed(A2, O2, 2_000, [sub(A2, O2, 2_000)]));
    expect((await store.get(TX))?.status).toBe('signed');
    const rc = (await store.getReceipt(TX))!;
    expect(rc.submittedAt).toBeUndefined();
    expect(rc.policyEvidence).toMatchObject({ personalSignature: { page: OFFICERS, vote: 'approve', relayedBy: 'not-determined' } });
  });

  it('opposite of the vote the engine decided (a prior receipt with decision deny): recorded as an override, as advanceAwaitingHuman does', async () => {
    const store = new MemoryStore();
    await keyed(store);
    await store.saveReceipt({ txHash: TX, decision: 'deny', reason: 'FICTIONAL refusal', policyEvidence: { blockedBy: 'decision_binding' } });
    const subs = [sub(A1, O1, 1_000), sub(A2, O2, 2_000)];
    const deps = { store, readPage, getTxSignatures: async () => ({ status: 'delivered', delivered: true, signatures: [sig(A1, O1), sig(A2, O2)] }) };
    await advancePersonalPath(deps, landed(A2, O2, 2_000, subs));
    const req = (await store.get(TX))!;
    expect(req).toMatchObject({ status: 'signed', humanOverride: { owed: 'reject', cast: 'approve' }, lastError: 'human_override: owed reject, cast approve' });
    // existing receipt fields kept, the people's act added
    expect(await store.getReceipt(TX)).toMatchObject({ decision: 'deny', reason: 'FICTIONAL refusal', vote: 'approve', humanOverride: { owed: 'reject', cast: 'approve' }, policyEvidence: { blockedBy: 'decision_binding', personalSignature: { vote: 'approve' } } });
  });

  it('never touches a request of another book, a decided request, or a human-only record', async () => {
    const store = new MemoryStore();
    await store.create({ txHash: TX, signerUrl: 'acc://fict-other-f130.acme/book/1', status: 'awaiting_policy', attempts: 0, createdAt: 1, updatedAt: 1 } as never);
    const deps = { store, readPage, getTxSignatures: async () => ({ status: 'delivered', delivered: true, signatures: [sig(A1, O1), sig(A2, O2)] }) };
    expect(await advancePersonalPath(deps, landed(A2, O2, 2_000, [sub(A1, O1, 1), sub(A2, O2, 2)]))).toEqual([]);
    expect((await store.get(TX))?.status).toBe('awaiting_policy');
    expect(await store.getReceipt(TX)).toBeUndefined();

    const s2 = new MemoryStore();
    await s2.create({ txHash: TX, signerUrl: SEAT, status: 'signed', attempts: 0, createdAt: 1, updatedAt: 1 } as never);
    const KEY = humanRecordId(TX, OFFICERS);
    await s2.create({ txHash: TX, recordId: KEY, signerUrl: OFFICERS, status: 'awaiting_human', attempts: 0, createdAt: 1, updatedAt: 1 } as never);
    await advancePersonalPath({ ...deps, store: s2 }, landed(A2, O2, 2_000, [sub(A1, O1, 1), sub(A2, O2, 2)]));
    expect(await s2.getReceipt(TX)).toBeUndefined();
    expect(await s2.getReceipt(KEY)).toBeUndefined();   // the human-only record is advanceAwaitingHuman's, unchanged here
    expect((await advanceAwaitingHuman({ ...deps, store: s2 }, TX, OFFICERS))?.status).toBe('signed');
  });

  it('waits for a policy poll holding the request lock, so the poll cannot write awaiting_policy over the ended request', async () => {
    const store = new MemoryStore();
    await keyed(store);
    expect(store.tryLock(TX)).toBe(true);
    const deps = { store, readPage, getTxSignatures: async () => ({ status: 'delivered', delivered: true, signatures: [sig(A1, O1), sig(A2, O2)] }), lockPollMs: 5 };
    const running = advancePersonalPath(deps, landed(A2, O2, 2, [sub(A1, O1, 1), sub(A2, O2, 2)]));
    await new Promise((r) => setTimeout(r, 30));
    expect((await store.get(TX))?.status).toBe('awaiting_policy');   // not touched while the poll holds it
    await store.update(TX, { status: 'awaiting_policy' });           // the poll's own write
    store.unlock(TX);
    await running;
    expect((await store.get(TX))?.status).toBe('signed');
  });
});
