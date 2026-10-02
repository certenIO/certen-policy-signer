/**
 * G-65: the signer refuses a key-page change that would brick the page.
 *
 * Unit tests for the simulator / validator (every updateKeyPage operation type, delegates, ordering, the
 * edge cases), then the two wired paths that live outside the relay and officer intake: the admin
 * governance route (POST /v1/admin/key-page -> applyKeyPageOp) and the machine vote (Orchestrator) on a
 * pending updateKeyPage. All pages, keys and parties are FICTIONAL.
 */
import { describe, it, expect, vi } from 'vitest';
import http from 'node:http';
import pino from 'pino';
import {
  checkKeyPageChange, operationsFromKeyPageOps, simulateKeyPageOps, validateKeyPageChange, simPageFrom,
  type KeyPageOperation, type SimPage,
} from '../src/ops/keypage-guard.js';
import { applyKeyPageOp } from '../src/ops/keypage.js';
import type { PageState } from '../src/ops/rotate.js';
import { extractGovernance } from '../src/decode/facts.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { createServer } from '../src/server.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient, type PolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';

const silent = pino({ level: 'silent' });
const A = 'aa'.repeat(32);
const B = 'bb'.repeat(32);
const C = 'cc'.repeat(32);
const D = 'dd'.repeat(32);
const BOOK_X = 'acc://fictional-officer-x-tcl1.acme/book';
const BOOK_Y = 'acc://fictional-officer-y-tcl1.acme/book';

const page = (entries: Array<string | { delegate: string }>, accept = 1, reject = 0, response = 0): SimPage => ({
  entries: entries.map((e) => (typeof e === 'string' ? { keyHash: e, delegate: null } : { keyHash: null, delegate: e.delegate })),
  acceptThreshold: accept, rejectThreshold: reject, responseThreshold: response,
});

describe('simulateKeyPageOps: each operation type', () => {
  it('add: a key and a delegate each add one entry', () => {
    const r = simulateKeyPageOps(page([A]), [{ type: 'add', keyHash: B }, { type: 'add', delegate: BOOK_X }]);
    expect(r.ok && r.result.entryCount).toBe(3);
  });

  it('add: a duplicate key, or a duplicate delegate under a different spelling, is refused', () => {
    expect(simulateKeyPageOps(page([A]), [{ type: 'add', keyHash: A.toUpperCase() }])).toMatchObject({ ok: false, refusal: { reason: 'duplicate_entry', opIndex: 0 } });
    expect(simulateKeyPageOps(page([A, { delegate: BOOK_X }]), [{ type: 'add', delegate: BOOK_X.toUpperCase().replace('ACC://', 'acc://') + '/' }]))
      .toMatchObject({ ok: false, refusal: { reason: 'duplicate_entry' } });
    // Two adds of the same key in one body: the second is the duplicate.
    expect(simulateKeyPageOps(page([A]), [{ type: 'add', keyHash: B }, { type: 'add', keyHash: B }])).toMatchObject({ ok: false, refusal: { reason: 'duplicate_entry', opIndex: 1 } });
  });

  it('remove: a key or a delegate; one not on the page is refused', () => {
    const ok = simulateKeyPageOps(page([A, B, { delegate: BOOK_X }]), [{ type: 'remove', keyHash: B }, { type: 'remove', delegate: BOOK_X }]);
    expect(ok.ok && ok.result.entryCount).toBe(1);
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'remove', keyHash: C }])).toMatchObject({ ok: false, refusal: { reason: 'entry_not_on_page', opIndex: 0, entry: { keyHash: C } } });
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'remove', delegate: BOOK_Y }])).toMatchObject({ ok: false, refusal: { reason: 'entry_not_on_page', entry: { delegate: BOOK_Y } } });
  });

  it('remove lowers the accept threshold to the entry count, as the executor does', () => {
    const r = simulateKeyPageOps(page([A, B, C], 3), [{ type: 'remove', keyHash: C }]);
    expect(r).toMatchObject({ ok: true, result: { entryCount: 2, acceptThreshold: 2, acceptThresholdLowered: true } });
  });

  it('update: replaces an entry in place; old entry missing or new entry already present is refused', () => {
    const r = simulateKeyPageOps(page([A, B], 2), [{ type: 'update', oldKeyHash: A, newKeyHash: C }]);
    expect(r).toMatchObject({ ok: true, result: { entryCount: 2, acceptThreshold: 2 } });
    expect(r.ok && r.result.entries.map((e) => e.keyHash)).toEqual([C, B]);
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'update', oldKeyHash: C, newKeyHash: D }])).toMatchObject({ ok: false, refusal: { reason: 'entry_not_on_page' } });
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'update', oldKeyHash: A, newKeyHash: B }])).toMatchObject({ ok: false, refusal: { reason: 'duplicate_entry' } });
    // A key seat can be turned into a delegate seat.
    const toDelegate = simulateKeyPageOps(page([A, B]), [{ type: 'update', oldKeyHash: A, newDelegate: BOOK_X }]);
    expect(toDelegate.ok && toDelegate.result.entries[0]).toEqual({ keyHash: null, delegate: BOOK_X });
  });

  it('setThreshold: == entries is allowed; > entries and 0 are refused with the numbers', () => {
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'setThreshold', threshold: 2 }])).toMatchObject({ ok: true, result: { acceptThreshold: 2 } });
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'setThreshold', threshold: 3 }]))
      .toMatchObject({ ok: false, refusal: { reason: 'threshold_exceeds_entries', threshold: 3, entries: 2, opIndex: 0 } });
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'setThreshold', threshold: 0 }])).toMatchObject({ ok: false, refusal: { reason: 'threshold_below_one' } });
  });

  it('setRejectThreshold / setResponseThreshold: == entries allowed, > entries refused', () => {
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'setRejectThreshold', threshold: 2 }, { type: 'setResponseThreshold', threshold: 2 }]))
      .toMatchObject({ ok: true, result: { rejectThreshold: 2, responseThreshold: 2 } });
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'setRejectThreshold', threshold: 3 }]))
      .toMatchObject({ ok: false, refusal: { reason: 'reject_threshold_exceeds_entries', threshold: 3, entries: 2 } });
    expect(simulateKeyPageOps(page([A, B]), [{ type: 'setResponseThreshold', threshold: 3 }]))
      .toMatchObject({ ok: false, refusal: { reason: 'response_threshold_exceeds_entries', threshold: 3, entries: 2 } });
  });

  it('updateAllowed changes no entry and no threshold', () => {
    expect(simulateKeyPageOps(page([A, B], 2), [{ type: 'updateAllowed', allow: ['sendTokens'], deny: [] }]))
      .toMatchObject({ ok: true, result: { entryCount: 2, acceptThreshold: 2 } });
  });

  it('an unrecognized, unknown or malformed operation is refused rather than guessed at', () => {
    expect(simulateKeyPageOps(page([A]), [{ type: 'add', unrecognized: true }])).toMatchObject({ ok: false, refusal: { reason: 'unrecognized_operation' } });
    expect(simulateKeyPageOps(page([A]), [{ type: 'burnThePage' }])).toMatchObject({ ok: false, refusal: { reason: 'unrecognized_operation' } });
    expect(simulateKeyPageOps(page([A]), [{ type: 'add', keyHash: 'not-hex' }])).toMatchObject({ ok: false, refusal: { reason: 'unrecognized_operation' } });
    expect(simulateKeyPageOps(page([A]), [{ type: 'setThreshold' }])).toMatchObject({ ok: false, refusal: { reason: 'unrecognized_operation' } });
    expect(simulateKeyPageOps(page([A]), [null as unknown as KeyPageOperation])).toMatchObject({ ok: false, refusal: { reason: 'unrecognized_operation' } });
  });
});

describe('validateKeyPageChange: the end state', () => {
  it('delegates count as entries', () => {
    expect(validateKeyPageChange(page([A, { delegate: BOOK_X }]), [{ type: 'setThreshold', threshold: 2 }]).ok).toBe(true);
    expect(validateKeyPageChange(page([A, { delegate: BOOK_X }]), [{ type: 'add', delegate: BOOK_Y }, { type: 'setThreshold', threshold: 3 }]).ok).toBe(true);
  });

  it('threshold == entries is allowed', () => {
    expect(validateKeyPageChange(page([A, B, C], 3), [{ type: 'updateAllowed', allow: [], deny: [] }]).ok).toBe(true);
  });

  it('removing the last key is refused (no entries)', () => {
    expect(validateKeyPageChange(page([A]), [{ type: 'remove', keyHash: A }])).toMatchObject({ ok: false, refusal: { reason: 'no_entries', entries: 0 } });
    expect(validateKeyPageChange(page([{ delegate: BOOK_X }]), [{ type: 'remove', delegate: BOOK_X }])).toMatchObject({ ok: false, refusal: { reason: 'no_entries' } });
  });

  it('remove + setThreshold in one body are evaluated in order', () => {
    // remove first: 1 entry left, then threshold 2 is refused at the second operation.
    expect(validateKeyPageChange(page([A, B]), [{ type: 'remove', keyHash: B }, { type: 'setThreshold', threshold: 2 }]))
      .toMatchObject({ ok: false, refusal: { reason: 'threshold_exceeds_entries', opIndex: 1, threshold: 2, entries: 1 } });
    // threshold first: 2 of 2 is fine, then the remove lowers it to 1 of 1 (the executor's behaviour).
    expect(validateKeyPageChange(page([A, B]), [{ type: 'setThreshold', threshold: 2 }, { type: 'remove', keyHash: B }]))
      .toMatchObject({ ok: true, after: { entryCount: 1, acceptThreshold: 1 } });
    // add then raise is fine; raise then add is refused (SetThreshold measures the page as it is at that op).
    expect(validateKeyPageChange(page([A, B]), [{ type: 'add', keyHash: C }, { type: 'setThreshold', threshold: 3 }]).ok).toBe(true);
    expect(validateKeyPageChange(page([A, B]), [{ type: 'setThreshold', threshold: 3 }, { type: 'add', keyHash: C }]))
      .toMatchObject({ ok: false, refusal: { reason: 'threshold_exceeds_entries', opIndex: 0 } });
  });

  it('replacing the only key (remove then add) is allowed: a stored 0 threshold is enforced as one', () => {
    expect(validateKeyPageChange(page([A]), [{ type: 'remove', keyHash: A }, { type: 'add', keyHash: B }]))
      .toMatchObject({ ok: true, after: { entryCount: 1, effectiveAcceptThreshold: 1 } });
  });

  it('a reject/response threshold left above the entries by a remove is refused (not lowered: v1 does not)', () => {
    expect(validateKeyPageChange(page([A, B, C], 1, 3), [{ type: 'remove', keyHash: C }]))
      .toMatchObject({ ok: false, refusal: { reason: 'reject_threshold_exceeds_entries', threshold: 3, entries: 2 } });
    expect(validateKeyPageChange(page([A, B, C], 1, 0, 3), [{ type: 'remove', keyHash: C }]))
      .toMatchObject({ ok: false, refusal: { reason: 'response_threshold_exceeds_entries', threshold: 3, entries: 2 } });
  });

  it('a page already bricked is not passed by a change that leaves it bricked', () => {
    expect(validateKeyPageChange(page([A, B], 3), [{ type: 'updateAllowed', allow: [], deny: [] }]))
      .toMatchObject({ ok: false, refusal: { reason: 'threshold_exceeds_entries', threshold: 3, entries: 2 } });
  });

  it('works on the decoder output for an on-chain body', () => {
    const body = { type: 'updateKeyPage', operation: [{ type: 'remove', entry: { keyHash: B } }, { type: 'setThreshold', threshold: 2 }] };
    const g = extractGovernance(body, 'acc://fictional-bank-tcl1.acme/book/2')!;
    expect(validateKeyPageChange(page([A, B]), g.operations)).toMatchObject({ ok: false, refusal: { reason: 'threshold_exceeds_entries' } });
  });
});

describe('operationsFromKeyPageOps', () => {
  it('maps every typed governance op; rotate-key needs our key hash', () => {
    expect(operationsFromKeyPageOps([
      { op: 'add-key', keyHash: A }, { op: 'remove-key', keyHash: B }, { op: 'add-delegate', delegate: BOOK_X },
      { op: 'remove-delegate', delegate: BOOK_Y }, { op: 'set-threshold', threshold: 2 }, { op: 'rotate-key', newKeyHash: C },
    ], A)).toEqual([
      { type: 'add', keyHash: A }, { type: 'remove', keyHash: B }, { type: 'add', delegate: BOOK_X },
      { type: 'remove', delegate: BOOK_Y }, { type: 'setThreshold', threshold: 2 }, { type: 'update', oldKeyHash: A, newKeyHash: C },
    ]);
    expect(operationsFromKeyPageOps([{ op: 'rotate-key', newKeyHash: C }])[0]).toMatchObject({ unrecognized: true });
  });
});

describe('checkKeyPageChange: reads the page now, fails closed', () => {
  const st: PageState = { version: 1, threshold: 1, keyHashes: [A, B], entries: [{ keyHash: A, delegate: null }, { keyHash: B, delegate: null }] };

  it('reads the page on every call (no cache) and validates against it', async () => {
    const read = vi.fn(async () => st);
    expect((await checkKeyPageChange(read, 'acc://p.acme/book/1', [{ type: 'setThreshold', threshold: 2 }])).ok).toBe(true);
    expect(await checkKeyPageChange(read, 'acc://p.acme/book/1', [{ type: 'setThreshold', threshold: 3 }]))
      .toMatchObject({ ok: false, refusal: { reason: 'threshold_exceeds_entries', page: 'acc://p.acme/book/1', threshold: 3, entries: 2 } });
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('page_unreadable when the read throws, returns nothing usable, or there is no reader', async () => {
    const ops: KeyPageOperation[] = [{ type: 'setThreshold', threshold: 1 }];
    expect(await checkKeyPageChange(async () => { throw new Error('FICTIONAL 502'); }, 'acc://p.acme/book/1', ops)).toMatchObject({ ok: false, refusal: { reason: 'page_unreadable' } });
    expect(await checkKeyPageChange(async () => ({}) as PageState, 'acc://p.acme/book/1', ops)).toMatchObject({ ok: false, refusal: { reason: 'page_unreadable' } });
    expect(await checkKeyPageChange(undefined, 'acc://p.acme/book/1', ops)).toMatchObject({ ok: false, refusal: { reason: 'page_unreadable' } });
  });

  it('simPageFrom carries the reject and response thresholds (absent = 0)', () => {
    expect(simPageFrom({ ...st, rejectThreshold: 2 })).toMatchObject({ acceptThreshold: 1, rejectThreshold: 2, responseThreshold: 0 });
  });
});

/* ------------------------------------------------------------------ */
/* Wired: applyKeyPageOp and POST /v1/admin/key-page                   */
/* ------------------------------------------------------------------ */

const OUR_PAGE = 'acc://fictional-org-tcl1.acme/book/1';
function fakeAcc(account: Record<string, unknown> | (() => never)) {
  const submitted: unknown[] = [];
  return {
    submitted,
    query: vi.fn(async () => (typeof account === 'function' ? account() : { account })),
    getSignerInfo: vi.fn(async () => ({ version: 1, lastUsedOn: 0, creditBalance: 100 })),
    submit: vi.fn(async (env: unknown) => { submitted.push(env); return { ok: true }; }),
  } as any;
}
const keys = (...h: string[]) => h.map((publicKeyHash) => ({ publicKeyHash }));

describe('applyKeyPageOp (admin route and relay governance both run through it)', () => {
  const signer = new LocalSigner(new Uint8Array(32).fill(7));

  it('refuses a remove that leaves the reject threshold above the entries; nothing is signed', async () => {
    const acc = fakeAcc({ version: 3, acceptThreshold: 1, rejectThreshold: 2, keys: keys(A, B) });
    const r = await applyKeyPageOp({ accumulate: acc, signer, logger: silent, page: OUR_PAGE }, { op: 'remove-key', keyHash: B }, 500);
    expect(r).toMatchObject({ ok: false, refusal: { reason: 'reject_threshold_exceeds_entries', threshold: 2, entries: 1, page: OUR_PAGE } });
    expect(acc.submitted).toHaveLength(0);
  });

  it('throws page_unreadable when the page cannot be read; nothing is signed', async () => {
    const acc = fakeAcc(() => { throw new Error('FICTIONAL node down'); });
    await expect(applyKeyPageOp({ accumulate: acc, signer, logger: silent, page: OUR_PAGE }, { op: 'set-threshold', threshold: 1 }, 500))
      .rejects.toMatchObject({ refusal: { reason: 'page_unreadable' } });
    expect(acc.submitted).toHaveLength(0);
  });

  it('a valid change still goes through', async () => {
    // A 2-of-3 page: the change is submitted and held for further signatures, so nothing waits on a confirmation.
    const acc = fakeAcc({ version: 3, acceptThreshold: 2, keys: keys(A, B, C) });
    const r = await applyKeyPageOp({ accumulate: acc, signer, logger: silent, page: OUR_PAGE }, { op: 'set-threshold', threshold: 3 }, 50);
    expect(r).toMatchObject({ ok: true, awaitingConsent: true });
    expect(r.refusal).toBeUndefined();
    expect(acc.submitted).toHaveLength(1);
  });
});

function listen(s: http.Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as { port: number }).port)));
}
function call(port: number, path: string, headers: Record<string, string>, body: unknown) {
  return new Promise<{ status: number; json: any }>((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method: 'POST', path, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => resolve({ status: res.statusCode!, json: t ? JSON.parse(t) : null }));
    });
    r.on('error', reject);
    r.write(JSON.stringify(body));
    r.end();
  });
}

describe('POST /v1/admin/key-page', () => {
  const GOV = 'fictional-governance-key-0000';
  async function serve(acc: any) {
    const signer = new LocalSigner(new Uint8Array(32).fill(7));
    const keyring = singleKeyring(signer, OUR_PAGE);
    const server = createServer({
      orchestrator: {} as any, store: new MemoryStore(), keyring, accumulate: acc, pause: { paused: false }, logger: silent,
      adminApiKey: 'fictional-admin-key-00000', governanceAdminKey: GOV,
      keyPage: (op, p) => applyKeyPageOp({ accumulate: acc, signer, logger: silent, page: p ?? OUR_PAGE }, op, 50),
    });
    return { server, port: await listen(server) };
  }

  it('refuses a bricking change with 400 and the structured reason; nothing submitted', async () => {
    const acc = fakeAcc({ version: 3, acceptThreshold: 1, responseThreshold: 2, keys: keys(A, B) });
    const { server, port } = await serve(acc);
    try {
      const r = await call(port, '/v1/admin/key-page', { 'x-api-key': 'fictional-admin-key-00000', 'x-governance-key': GOV }, { op: 'remove-key', keyHash: B });
      expect(r.status).toBe(400);
      expect(r.json.refusal).toMatchObject({ reason: 'response_threshold_exceeds_entries', threshold: 2, entries: 1 });
      expect(acc.submitted).toHaveLength(0);
    } finally { server.close(); }
  });

  it('refuses with 503 page_unreadable when the page cannot be read', async () => {
    const acc = fakeAcc(() => { throw new Error('FICTIONAL node down'); });
    const { server, port } = await serve(acc);
    try {
      const r = await call(port, '/v1/admin/key-page', { 'x-api-key': 'fictional-admin-key-00000', 'x-governance-key': GOV }, { op: 'set-threshold', threshold: 1 });
      expect(r.status).toBe(503);
      expect(r.json).toMatchObject({ ok: false, error: 'page_unreadable', submitted: [] });
      expect(acc.submitted).toHaveLength(0);
    } finally { server.close(); }
  });
});

/* ------------------------------------------------------------------ */
/* Wired: the machine vote on a pending updateKeyPage                  */
/* ------------------------------------------------------------------ */

describe('machine vote on a pending updateKeyPage', () => {
  const TX = 'e7'.repeat(32);
  const PAGE = 'acc://fictional-bank-tcl1.acme/book/2';
  const twoKeys: PageState = { version: 4, threshold: 1, keyHashes: [A, B], entries: [{ keyHash: A, delegate: null }, { keyHash: B, delegate: null }] };

  function run(operation: unknown[], o: { readPage?: (p: string) => Promise<PageState>; policy?: PolicyClient; submitRejectVote?: boolean } = {}) {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body: { type: 'updateKeyPage', operation }, principal: PAGE });
    const store = new MemoryStore();
    const orchestrator = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), PAGE),
      policy: o.policy ?? new MockPolicyClient({ decision: 'approve', reason: 'FICTIONAL rule: governance auto-approve' }),
      store, resolver: new Resolver(acc), logger: silent,
      ...('readPage' in o ? { readPage: o.readPage } : { readPage: async () => twoKeys }),
      options: { submitRejectVote: o.submitRejectVote ?? false },
    });
    return { acc, store, go: () => orchestrator.handle({ txHash: TX, signerUrl: PAGE }) };
  }

  it('an approve that would brick the page is withheld: rejected, no signature, receipt says why', async () => {
    const { acc, store, go } = run([{ type: 'setThreshold', threshold: 3 }]);
    const r = await go();
    expect(r.status).toBe('rejected');
    expect(r.lastError).toBe('keypage_guard: threshold_exceeds_entries');
    expect(acc.submissions).toHaveLength(0);
    const receipt = await store.getReceipt(TX);
    expect(receipt).toMatchObject({ decision: 'approve', policyEvidence: { blockedBy: 'keypage_guard', keyPageRefusal: { reason: 'threshold_exceeds_entries', threshold: 3, entries: 2, page: PAGE } } });
    expect(receipt?.vote).toBeUndefined();
  });

  it('remove + setThreshold in one body: refused when the order bricks it', async () => {
    const { acc, go } = run([{ type: 'remove', entry: { keyHash: B } }, { type: 'setThreshold', threshold: 2 }]);
    expect((await go()).status).toBe('rejected');
    expect(acc.submissions).toHaveLength(0);
  });

  it('an unreadable page withholds the vote and stays retryable (never assumes a page state)', async () => {
    const { acc, go } = run([{ type: 'setThreshold', threshold: 2 }], { readPage: async () => { throw new Error('FICTIONAL node down'); } });
    const r = await go();
    expect(r).toMatchObject({ status: 'awaiting_policy', lastError: 'keypage_guard: page_unreadable' });
    expect(acc.submissions).toHaveLength(0);
  });

  it('no page reader configured: withheld the same way', async () => {
    const { acc, go } = run([{ type: 'setThreshold', threshold: 2 }], { readPage: undefined });
    expect((await go())).toMatchObject({ status: 'awaiting_policy', lastError: 'keypage_guard: page_unreadable' });
    expect(acc.submissions).toHaveLength(0);
  });

  it('an operation the decoder could not read is refused', async () => {
    const { acc, go } = run([{ type: 'add', entry: {} }]);
    expect((await go())).toMatchObject({ status: 'rejected', lastError: 'keypage_guard: unrecognized_operation' });
    expect(acc.submissions).toHaveLength(0);
  });

  it('a valid change is still approved and signed', async () => {
    const { acc, go } = run([{ type: 'add', entry: { keyHash: C } }, { type: 'setThreshold', threshold: 3 }]);
    expect((await go()).status).toBe('signed');
    expect(acc.submissions).toHaveLength(1);
  });

  it('a deny still casts the reject vote it asked for (a reject cannot brick anything)', async () => {
    const { acc, go } = run([{ type: 'setThreshold', threshold: 3 }], { policy: new MockPolicyClient({ decision: 'deny', reason: 'FICTIONAL' }), submitRejectVote: true });
    expect((await go()).status).toBe('rejected');
    expect(acc.submissions).toHaveLength(1);
    expect((acc.submissions[0] as any).signatures[0].vote).toBe('reject');
  });

  it('a non-governance body is untouched by the guard', async () => {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://fictional-payee-tcl1.acme/tokens', amount: '1' }] }, principal: 'acc://fictional-payer-tcl1.acme/tokens' });
    const read = vi.fn(async () => twoKeys);
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), PAGE),
      policy: new MockPolicyClient({ decision: 'approve' }), store: new MemoryStore(), resolver: new Resolver(acc), logger: silent, readPage: read,
    });
    expect((await o.handle({ txHash: TX, signerUrl: PAGE })).status).toBe('signed');
    expect(read).not.toHaveBeenCalled();
  });
});
