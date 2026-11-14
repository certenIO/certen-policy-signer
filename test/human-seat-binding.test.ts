/**
 * DAX-MERGE-2: what exists only when G-69 (human-only seats, `awaiting_human`) and DAX-4S (bound decisions, single-use nonces,
 * the persisted pause) are in ONE signer. Neither line had these behaviours: a human-only page is a seat (top-level binding binds it,
 * a pause with no scope pauses it), a decision for it is bound BEFORE it is recorded as `awaiting_human` and the record carries the
 * binding, and a human-only seat cannot be combined with the wrapper mode. Then the shared record-key rule (workKey ?? recordId ??
 * txHash) in the store and the request routes. FICTIONAL parties; temp directories only.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { effectiveSeats, loadConfig } from '../src/config.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { Resolver } from '../src/resolver.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { LocalSigner } from '../src/signer/signer.js';
import { FileStore, MemoryStore, humanRecordId, keyOf } from '../src/store/store.js';
import { memoryPauseStore } from '../src/binding/pause-store.js';
import { createServer } from '../src/server.js';
import { ADDR, APPROVER, H, KEY, POLICY, SEAT, intentBody, leg } from './support/binding-fixtures.js';
import { NOW_S, SIGNER, TX, approveFor, requestHashOf, rig, silent, tmp } from './support/binding-rig.js';
import type { PolicyRequest, Receipt, SigningRequest } from '../src/types.js';

const BASE = intentBody();
const HID = humanRecordId(TX, SIGNER);
const OP = { scope: 'seat' as const, id: SEAT, by: 'seat:fic-operator', reason: 'FICTIONAL: stop deciding now' };

describe('a human-only seat that requires binding: the decision is bound before it is recorded (N1, N2, N3)', () => {
  it('a bound approve: awaiting_human, the receipt carries the binding, the nonce is spent, nothing is submitted', async () => {
    const r = rig({ body: BASE, humanOnly: true, reply: approveFor(BASE) });
    const row = await r.handle();
    expect(row).toMatchObject({ status: 'awaiting_human', decision: 'approve', recordId: HID });
    expect(r.acc.submissions).toHaveLength(0);
    expect(r.nonces.list()).toEqual([H('nonce-fixed')]);
    const receipt = await r.store.getReceipt(HID);
    expect(receipt?.binding).toMatchObject({ requestHash: requestHashOf(BASE), nonce: H('nonce-fixed'), seat: SEAT, approver: APPROVER, policyHash: POLICY, policyPinned: true, grantHash: null });
    expect(receipt?.binding?.decisionHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(receipt?.policyEvidence).toMatchObject({ awaitingHumanSignature: { page: SIGNER, vote: 'approve' } });
    expect(receipt?.vote).toBeUndefined();
  });

  it('a bound deny with submit_reject_vote: awaiting_human (a person casts the reject), the receipt carries the binding', async () => {
    const r = rig({ body: BASE, humanOnly: true, submitRejectVote: true, reply: approveFor(BASE, {}, 'deny') });
    const row = await r.handle();
    expect(row).toMatchObject({ status: 'awaiting_human', decision: 'deny', recordId: HID });
    expect(r.acc.submissions).toHaveLength(0);
    const receipt = await r.store.getReceipt(HID);
    expect(receipt?.policyEvidence).toMatchObject({ awaitingHumanSignature: { page: SIGNER, vote: 'reject' } });
    expect(receipt?.binding).toMatchObject({ requestHash: requestHashOf(BASE), nonce: H('nonce-fixed'), seat: SEAT });
    expect(r.nonces.list()).toEqual([H('nonce-fixed')]);
  });

  it('the same decision again after a restart is refused (decision_replayed): nothing new is recorded as awaiting_human', async () => {
    const first = rig({ body: BASE, humanOnly: true, reply: approveFor(BASE) });
    expect((await first.handle()).status).toBe('awaiting_human');
    const again = rig({ dir: first.dir, body: BASE, humanOnly: true, reply: approveFor(BASE) }); // a restart: new process, new store, same state directory
    const row = await again.handle();
    expect(row).toMatchObject({ status: 'awaiting_policy', lastError: 'binding: decision_replayed', recordId: HID });
    expect((await again.store.getReceipt(HID))?.policyEvidence).toMatchObject({ blockedBy: 'decision_binding', reason: 'decision_replayed' });
    expect((await again.store.getReceipt(HID))?.policyEvidence?.['awaitingHumanSignature']).toBeUndefined();
  });

  it('a decision for a mutated request is refused (request_mismatch): no awaiting_human, nothing spent', async () => {
    const mutated = intentBody({ legs: [leg({ to: ADDR.vendorB })] });
    const r = rig({ body: mutated, humanOnly: true, reply: approveFor(BASE) });
    const row = await r.handle();
    expect(row).toMatchObject({ status: 'awaiting_policy', lastError: 'binding: request_mismatch' });
    expect(r.nonces.list()).toEqual([]);
    expect(r.acc.submissions).toHaveLength(0);
  });

  it('an unbound (legacy) reply on a bound human-only seat is refused (decision_malformed), not recorded as awaiting_human', async () => {
    const r = rig({ body: BASE, humanOnly: true, reply: () => ({ decision: 'approve', reason: 'legacy' }) });
    const row = await r.handle();
    expect(row).toMatchObject({ status: 'awaiting_policy', lastError: 'binding: decision_malformed' });
    expect(r.nonces.list()).toEqual([]);
  });

  it('once awaiting_human a later poll does not ask the engine again, so no second decision and no second nonce is needed', async () => {
    const r = rig({ body: BASE, humanOnly: true, reply: approveFor(BASE) });
    const decide = vi.spyOn(r.policy, 'decide');
    await r.handle();
    expect((await r.handle()).status).toBe('awaiting_human');
    expect(decide).toHaveBeenCalledTimes(1);
    expect(r.nonces.list()).toEqual([H('nonce-fixed')]);
  });

  it('a paused seat records no awaiting_human and spends no nonce; after the resume the same decision is recorded (N5)', async () => {
    const r = rig({ body: BASE, humanOnly: true, reply: approveFor(BASE) });
    await r.pauses.set(OP);
    const held = await r.handle();
    expect(held).toMatchObject({ status: 'awaiting_policy', lastError: 'paused' });
    expect(await r.store.getReceipt(HID)).toBeUndefined();
    expect(r.nonces.list()).toEqual([]);
    await r.pauses.resume(OP);
    expect((await r.handle()).status).toBe('awaiting_human');
  });

  it('a seat that configures no binding keeps the unbound human-only flow (G-69 as it was)', async () => {
    const r = rig({ body: BASE, humanOnly: true, rules: null, reply: () => ({ decision: 'approve', reason: 'FICTIONAL rule' }) });
    expect(await r.handle()).toMatchObject({ status: 'awaiting_human', recordId: HID });
    expect((await r.store.getReceipt(HID))?.binding).toBeUndefined();
  });
});

describe('a human-only seat and the wrapper mode cannot be combined (N6)', () => {
  it('the orchestrator refuses to be built with both', () => {
    const acc = new MockAccumulateClient();
    expect(() => new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))), policy: new MockPolicyClient({ decision: 'approve' }),
      store: new MemoryStore(), resolver: new Resolver(acc), logger: silent, humanOnlyPages: [SIGNER],
      wrapper: { ourBook: 'acc://o.acme/book', ourPage: SIGNER, isEnrolledWrapperPage: async () => false, wrapperBooks: async () => [] },
    })).toThrow(/human-only seats and wrapper mode cannot be combined/);
  });
});

describe('config: a human-only page is a seat (N4, N6)', () => {
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
  const HP = 'acc://summit-inspection-tcl1.acme/book/1';
  const KP = 'acc://summit-inspection-tcl1.acme/book/2';
  const GOOD = `binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400 }`;
  function load(wallet: string, extra = '', model = '') {
    const dir = tmp();
    dirs.push(dir);
    const p = join(dir, 'c.yaml');
    writeFileSync(p, `wallet:
  org_id: "summit-inspection-tcl1 (FICTIONAL)"
  accumulate_endpoints: ["http://127.0.0.1:1/v3"]
${wallet}
${model}
policy:
  url: "http://127.0.0.1:9099/decision"
officer_intake:
  enabled: true
  human_pages: ["${HP}"]
store:
  path: "${join(dir, 'store.json').replace(/\\/g, '/')}"
${extra}`);
    return loadConfig(p);
  }
  const human = `  human_scopes:\n    - { page: "${HP}" }`;

  it('the top-level binding applies to a human-only page and its seat is derived, like a keyed scope', () => {
    const cfg = load(human, GOOD);
    expect(effectiveSeats(cfg)).toEqual([{ page: HP, seat: 'seat:summit-inspection-tcl1.acme-book-1', binding: expect.objectContaining({ max_window_seconds: 5400, require_grant: false }) }]);
  });

  it('a human-only page can name its seat and carry its own binding; beside a keyed scope both are seats', () => {
    const keyed = `  scopes:\n    - { page: "${KP}", seat: "seat:keyed", key: { provider: "local", local: { allow_ephemeral: true } } }`;
    const cfg = load(`${keyed}\n  human_scopes:\n    - { page: "${HP}", seat: "seat:board", binding: { authorized_approvers: ["${KEY('b')}"], max_window_seconds: 3600 } }`);
    const seats = effectiveSeats(cfg);
    expect(seats.map((s) => [s.page, s.seat])).toEqual([[KP, 'seat:keyed'], [HP, 'seat:board']]);
    expect(seats[1]?.binding).toMatchObject({ authorized_approvers: [KEY('b')], max_window_seconds: 3600 });
    expect(seats[0]?.binding).toBeUndefined();
  });

  it('a seat id shared by a keyed scope and a human-only page, a display name as a seat, and a bad binding are refused at boot', () => {
    const keyed = `  scopes:\n    - { page: "${KP}", seat: "seat:same", key: { provider: "local", local: { allow_ephemeral: true } } }`;
    expect(() => load(`${keyed}\n  human_scopes:\n    - { page: "${HP}", seat: "seat:same" }`)).toThrow(/two scopes/);
    expect(() => load(`  human_scopes:\n    - { page: "${HP}", seat: "Board" }`)).toThrow(/seat:<name>/);
    expect(() => load(`  human_scopes:\n    - { page: "${HP}", binding: { authorized_approvers: ["Alice Officer"], max_window_seconds: 3600 } }`)).toThrow(/never a display name/);
  });

  it('human-only seats with attachment_model: wrapper are refused at boot', () => {
    expect(() => load(`${human}\n  attachment_model: wrapper`)).toThrow(/human-only/);
  });
});

describe('the store files a row under workKey ?? recordId ?? txHash (N7)', () => {
  const HASH = 'cd'.repeat(32);
  const PAGE = 'acc://summit-inspection-tcl1.acme/book/1';
  const PATH_KEY = `${HASH}:${'ab'.repeat(8)}`;
  const row = (extra: Partial<SigningRequest>): SigningRequest => ({ txHash: HASH, signerUrl: PAGE, status: 'discovered', attempts: 0, createdAt: 1, updatedAt: 1, ...extra });
  const pr = (): PolicyRequest => ({ requestId: 'r1', txHash: HASH, signerUrl: PAGE } as unknown as PolicyRequest);
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

  it('keyOf: workKey, then recordId, then txHash', () => {
    expect(keyOf({ txHash: HASH })).toBe(HASH);
    expect(keyOf({ txHash: HASH, recordId: 'r' })).toBe('r');
    expect(keyOf({ txHash: HASH, recordId: 'r', workKey: 'w' })).toBe('w');
  });

  it('a keyed row, a human-only row and a wrapper path row of one transaction each keep their own receipts, and a file reload keeps all of it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'merge2-store-'));
    dirs.push(dir);
    const path = join(dir, 'store.json');
    const s = new FileStore(path);
    const hid = humanRecordId(HASH, PAGE);
    await s.create(row({}));
    await s.create(row({ recordId: hid }));
    await s.create(row({ workKey: PATH_KEY }));
    await s.saveReceipt({ txHash: HASH, reason: 'keyed' } as Receipt);
    await s.saveReceipt({ txHash: HASH, recordId: hid, reason: 'human 1' } as Receipt);
    await s.saveReceipt({ txHash: HASH, recordId: hid, reason: 'human 2' } as Receipt);
    await s.saveReceipt({ txHash: HASH, workKey: PATH_KEY, reason: 'path' } as Receipt);
    await s.savePolicyRequest(pr());
    await s.savePolicyRequest(pr(), hid);
    await s.savePolicyRequest(pr(), PATH_KEY);
    // an update never moves a row under another key
    await s.update(hid, { status: 'awaiting_human', recordId: 'other' as string });
    const again = new FileStore(path);
    expect((await again.get(hid))?.status).toBe('awaiting_human');
    expect((await again.get(hid))?.recordId).toBe(hid);
    expect((await again.listForTx(HASH)).map((r) => keyOf(r)).sort()).toEqual([HASH, hid].sort()); // never the wrapper path row
    expect((await again.getReceipt(HASH))?.reason).toBe('keyed');
    expect((await again.getReceipt(hid))?.reason).toBe('human 2');
    expect((await again.getReceipts(hid)).map((r) => r.seq)).toEqual([2, 3]);
    expect((await again.getReceipt(PATH_KEY))?.reason).toBe('path');
    expect(await again.getPolicyRequest(hid)).toBeDefined();
    expect(await again.getPolicyRequest(PATH_KEY)).toBeDefined();
    expect((await again.getPolicyRequest(HASH))?.txHash).toBe(HASH);
  });

  it('a state file written by the G-69 build before the merge (a parallel policyRequestKeys list) loads its human-keyed requests under their keys', () => {
    const dir = mkdtempSync(join(tmpdir(), 'merge2-legacy-'));
    dirs.push(dir);
    const path = join(dir, 'store.json');
    const hid = humanRecordId(HASH, PAGE);
    writeFileSync(path, JSON.stringify({
      requests: [row({}), row({ recordId: hid, status: 'awaiting_human' })],
      receipts: [{ txHash: HASH, recordId: hid, reason: 'legacy' }],
      policyRequests: [{ ...pr(), requestId: 'keyed' }, { ...pr(), requestId: 'human' }],
      policyRequestKeys: [HASH, hid],
    }));
    const s = new FileStore(path);
    return Promise.all([s.get(hid), s.getPolicyRequest(HASH), s.getPolicyRequest(hid), s.getReceipt(hid)]).then(([h, k, hp, hr]) => {
      expect(h?.status).toBe('awaiting_human');
      expect(k?.requestId).toBe('keyed');
      expect(hp?.requestId).toBe('human');
      expect(hr?.reason).toBe('legacy');
      expect(readFileSync(path, 'utf8')).toContain('policyRequestKeys'); // not rewritten until the next mutation
    });
  });
});

describe('GET and retry of /v1/requests/:key by work key and by bare hash (N8)', () => {
  const HASH = 'ef'.repeat(32);
  const KEYED = 'acc://summit-inspection-tcl1.acme/book/2';
  const HUMAN = 'acc://summit-inspection-tcl1.acme/book/1';
  const PATH_KEY = `${HASH}:${'12'.repeat(8)}`;
  const ADMIN = 'fic-admin-key-0000';
  const servers: http.Server[] = [];
  afterEach(() => { for (const s of servers.splice(0)) s.close(); });

  async function boot() {
    const store = new MemoryStore();
    const base = { txHash: HASH, status: 'awaiting_policy' as const, attempts: 0, createdAt: 1, updatedAt: 1 };
    await store.create({ ...base, signerUrl: KEYED });
    await store.create({ ...base, signerUrl: HUMAN, recordId: humanRecordId(HASH, HUMAN), status: 'awaiting_human' });
    await store.create({ ...base, signerUrl: KEYED, workKey: PATH_KEY, delegators: ['acc://w.acme/book/1'], principal: 'acc://p.acme/tokens' });
    await store.saveReceipt({ txHash: HASH, reason: 'keyed' } as Receipt);
    await store.saveReceipt({ txHash: HASH, recordId: humanRecordId(HASH, HUMAN), reason: 'human' } as Receipt);
    await store.saveReceipt({ txHash: HASH, workKey: PATH_KEY, reason: 'path' } as Receipt);
    const handled: Array<Record<string, unknown>> = [];
    const orchestrator = { handleAll: async (ref: Record<string, unknown>) => { handled.push(ref); return []; } };
    const server = createServer({ orchestrator: orchestrator as never, store, keyring: {} as never, accumulate: {} as never, pause: memoryPauseStore(), logger: silent, adminApiKey: ADMIN });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    servers.push(server);
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const call = async (method: string, path: string) => {
      const r = await fetch(url + path, { method, headers: { 'x-api-key': ADMIN } });
      return { status: r.status, json: (await r.json()) as any };
    };
    return { call, handled };
  }

  it('GET by a work key answers that one row and its receipt', async () => {
    const { call } = await boot();
    const r = await call('GET', `/v1/requests/${PATH_KEY}`);
    expect(r.status).toBe(200);
    expect(r.json.request.workKey).toBe(PATH_KEY);
    expect(r.json.receipt.reason).toBe('path');
    expect(r.json.seats).toHaveLength(1);
  });

  it('GET by a bare hash answers the keyed seat first and every page-keyed row under seats, never a wrapper path row', async () => {
    const { call } = await boot();
    const r = await call('GET', `/v1/requests/${HASH}`);
    expect(r.status).toBe(200);
    expect(r.json.request.signerUrl).toBe(KEYED);
    expect(r.json.receipt.reason).toBe('keyed');
    expect(r.json.seats.map((s: any) => [s.page, s.receipt.reason]).sort()).toEqual([[HUMAN, 'human'], [KEYED, 'keyed']].sort());
  });

  it('an unknown hash and an unknown work key are 404', async () => {
    const { call } = await boot();
    expect((await call('GET', `/v1/requests/${'aa'.repeat(32)}`)).status).toBe(404);
    expect((await call('GET', `/v1/requests/${HASH}:${'99'.repeat(8)}`)).status).toBe(404);
  });

  it('retry by a bare hash hands every page-keyed row to the orchestrator; by a work key, that row with its wrapper hint', async () => {
    const { call, handled } = await boot();
    expect((await call('POST', `/v1/requests/${HASH}/retry`)).status).toBe(202);
    expect(handled.map((h) => h['signerUrl']).sort()).toEqual([HUMAN, KEYED].sort());
    handled.length = 0;
    expect((await call('POST', `/v1/requests/${PATH_KEY}/retry`)).status).toBe(202);
    expect(handled).toEqual([{ txHash: HASH, signerUrl: KEYED, principal: 'acc://p.acme/tokens', wrapperBook: 'acc://w.acme/book' }]);
  });
});

void NOW_S;
