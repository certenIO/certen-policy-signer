/**
 * Enrolment votes and the seat registry. Wrapper runbook, change 6 (Phase 6).
 *
 * Two enrolment transactions need Trust Stamp's vote, on DIFFERENT paths:
 *
 *   wrapper creation  UpdateKeyPage on B/1 adding → T.   We sign DIRECTLY on our page, as a new owner of
 *                     B/1 (`chain/update_key_page.go:65-73`). The delegate entry that would give us a path
 *                     is what this transaction creates — the "sign directly" gotcha seen on Kermit.
 *   seat attach       UpdateKeyPage on an org page adding → B.   Through `[B/1]`, the path the person's own
 *                     approval took (Phase 3's rule produces it with no special case).
 *
 * The registry changes only once the transaction EXECUTED — never on our vote alone.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MemoryWrapperRegistry, isRegisteredWrapperPage } from '../src/registry/wrappers.js';
import { BookState, WrapperReader, checkWrapper, checkWrapperChange } from '../src/delegation/wrapper.js';
import { PageState } from '../src/ops/rotate.js';
import { createServer } from '../src/server.js';
import { WrapperChain, submittedVote } from './support/wrapper-chain.js';
import http from 'node:http';
import { AddressInfo } from 'node:net';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const T = 'acc://a-ts.acme/book';           // sorts before every subscriber book below
const TS_PAGE = 'acc://a-ts.acme/book/1';
const B = 'acc://p.acme/id';
const B1 = 'acc://p.acme/id/1';
const ALICE_BOOK = 'acc://p.acme/book';
const ALICE = 'acc://p.acme/book/1';
const ORG = 'acc://o.acme/book/1';
const TEMP = 'cc'.repeat(32);
const ORG_KEY = 'dd'.repeat(32);

const page = (threshold: number, ...entries: Array<{ keyHash?: string; delegate?: string }>): PageState => {
  const e = entries.map((x) => ({ keyHash: x.keyHash ?? null, delegate: x.delegate ?? null }));
  return { version: 1, threshold, keyHashes: e.map((x) => x.keyHash).filter((h): h is string => !!h), entries: e };
};

/** The chain's pages and books, mutable so a test can "execute" a transaction. */
function world() {
  const books: Record<string, BookState> = { [B]: { authorities: [{ url: B, disabled: false }], pageCount: 1 } };
  const pages: Record<string, PageState> = {
    [B1]: page(1, { keyHash: TEMP }),                       // just created with a temporary key
    [ORG]: page(1, { keyHash: ORG_KEY }),
  };
  const reader: WrapperReader = {
    readBook: async (u) => { const b = books[u.toLowerCase()]; if (!b) throw new Error(`no book ${u}`); return structuredClone(b); },
    readPage: async (u) => { const p = pages[u.toLowerCase()]; if (!p) throw new Error(`no page ${u}`); return structuredClone(p); },
  };
  return { books, pages, reader };
}

/** The creation body, as the runbook orders it: adds first, then the threshold, then the temp key out. */
const CREATE_OPS = [
  { type: 'add', entry: { delegate: ALICE_BOOK } },
  { type: 'add', entry: { delegate: T } },
  { type: 'setThreshold', threshold: 2 },
  { type: 'remove', entry: { keyHash: TEMP } },
];

function setup(opts: { status?: 'enrolling' | 'active'; registered?: boolean; decision?: 'approve' | 'deny' } = {}) {
  const w = world();
  const acc = new WrapperChain();
  const registry = new MemoryWrapperRegistry();
  if (opts.registered !== false) void registry.upsert({ wrapperBook: B, wrapperPage: B1, subjectId: 'alice', enrolledAt: 0, seats: [], status: opts.status ?? 'enrolling' });
  const store = new MemoryStore();
  const policy = new MockPolicyClient({ decision: opts.decision ?? 'approve' });
  const o = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), TS_PAGE), policy, store, resolver: new Resolver(acc), logger: silent,
    wrapper: {
      ourBook: T, ourPage: TS_PAGE,
      isEnrolledWrapperPage: (p) => isRegisteredWrapperPage(registry, p),
      wrapperBooks: async () => (await registry.list()).map((e) => e.wrapperBook),
      checkWrapper: (book) => checkWrapper(w.reader, book, T),
      checkWrapperChange: (book, tx) => checkWrapperChange(w.reader, book, T, tx),
      registry, readPage: (u) => w.reader.readPage(u),
    },
  });
  return { ...w, acc, registry, store, policy, o };
}

describe('wrapper creation', () => {
  it('resolves to an EMPTY path: we sign directly on our page, as a new owner of B/1', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    const rows = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    expect(rows.map((r) => [r.status, r.kind])).toEqual([['signed', 'wrapper_create']]);
    const v = submittedVote(d.acc.submissions[0]);
    expect(v.hops).toEqual([]);
    expect(v.signer).toBe(TS_PAGE);
    expect(d.policy.calls[0]).toMatchObject({ attachmentKind: 'wrapper_create', wrapper: { page: B1, path: [] } });
  });

  it('is co-signed only if the RESULT passes the invariant: a creation leaving threshold 1 is refused', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: ALICE_BOOK } }, { type: 'add', entry: { delegate: T } }, { type: 'remove', entry: { keyHash: TEMP } }] }, principal: B1 });
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    expect(row!.status).toBe('rejected');
    expect(row!.lastError).toMatch(/wrapper_invariant: after this change: .*can be met without/);
    expect(d.policy.calls).toHaveLength(0);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('a creation that keeps the temporary key is refused (it could approve without us)', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS.slice(0, 3) }, principal: B1 });
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    expect(row!.status).toBe('rejected');
  });

  it('a wrapper nobody registered as enrolling is not recognised: no work, no vote', async () => {
    const d = setup({ registered: false });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    expect(await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B })).toEqual([]);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('a body that does not add our book is not a creation vote', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: ALICE_BOOK } }] }, principal: B1 });
    expect(await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B })).toEqual([]);
  });

  it('an enrolling wrapper is not a wrapper we vote THROUGH', async () => {
    const d = setup();
    expect(await isRegisteredWrapperPage(d.registry, B1)).toBe(false);
  });
});

describe('seat attach', () => {
  it('resolves to [B/1], classified seat_attach', async () => {
    const d = setup({ status: 'active' });
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: B } }, { type: 'setThreshold', threshold: 2 }] }, principal: ORG });
    d.acc.approvesThrough(TX, ALICE, [B1]);
    const rows = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: ORG });
    expect(rows.map((r) => [r.status, r.kind])).toEqual([['signed', 'seat_attach']]);
    expect(submittedVote(d.acc.submissions[0]).hops).toEqual([B1]);
    expect(d.policy.calls[0]!.attachmentKind).toBe('seat_attach');
  });
});

describe('the registry changes only after execution', () => {
  it('wrapper creation: still enrolling after our vote and while pending; active once executed and valid', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    expect((await d.registry.get(B))?.status).toBe('enrolling');
    await d.o.settleEnrolments();
    expect((await d.registry.get(B))?.status).toBe('enrolling');            // our vote alone changes nothing
    // The transaction executes; the chain now shows the wrapper.
    d.acc.pending.get(TX)!.executed = true;
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    await d.o.settleEnrolments();
    expect((await d.registry.get(B))?.status).toBe('active');
    expect(await isRegisteredWrapperPage(d.registry, B1)).toBe(true);
  });

  it('wrapper creation executed but the chain does not show a valid wrapper: NOT activated', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    d.acc.pending.get(TX)!.executed = true;
    d.pages[B1] = page(1, { delegate: T }, { delegate: ALICE_BOOK });       // not what we co-signed
    await d.o.settleEnrolments();
    expect((await d.registry.get(B))?.status).toBe('enrolling');
  });

  it('seat attach: recorded only once executed AND the org page really holds → B', async () => {
    const d = setup({ status: 'active' });
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: B } }, { type: 'setThreshold', threshold: 2 }] }, principal: ORG });
    d.acc.approvesThrough(TX, ALICE, [B1]);
    await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: ORG });
    await d.o.settleEnrolments();
    expect((await d.registry.get(B))?.seats).toEqual([]);
    d.acc.pending.get(TX)!.executed = true;
    d.pages[ORG] = page(2, { keyHash: ORG_KEY }, { delegate: B });
    await d.o.settleEnrolments();
    expect((await d.registry.get(B))?.seats.map((s) => [s.orgPage, s.attachedTx])).toEqual([[ORG, TX]]);
    // Settled once: a second pass does not add it again.
    await d.o.settleEnrolments();
    expect((await d.registry.get(B))?.seats).toHaveLength(1);
  });

  it('an expired enrolment is settled as failed and records nothing', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    d.acc.pending.get(TX)!.expired = true;
    await d.o.settleEnrolments();
    expect((await d.store.get(row!.workKey ?? row!.txHash))?.settled).toBe('failed');
    expect((await d.registry.get(B))?.status).toBe('enrolling');
  });
});

describe('seat reconcile on every vote', () => {
  function voteSetup(orgEntries: Array<{ keyHash?: string; delegate?: string }>, recorded: boolean) {
    const d = setup({ status: 'active' });
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    d.pages[ORG] = page(2, ...orgEntries);
    if (recorded) void d.registry.addSeat(B, { orgPage: ORG, attachedTx: 'x', attachedAt: 1 });
    d.acc.addPending(TX, { body: { type: 'sendTokens', to: [] }, principal: 'acc://o.acme/tokens' });
    d.acc.approvesThrough(TX, ALICE, [B1, ORG]);
    return d;
  }
  const REF = { txHash: TX, signerUrl: TS_PAGE, principal: 'acc://o.acme/tokens' };

  it('a seat really on chain but not recorded is reconciled, and the vote goes ahead', async () => {
    const d = voteSetup([{ keyHash: ORG_KEY }, { delegate: B }], false);
    expect((await d.o.handleAll(REF)).map((r) => r.status)).toEqual(['signed']);
    expect((await d.registry.get(B))?.seats.map((s) => s.orgPage)).toEqual([ORG]);
  });

  it('a fake seat (the org page does not hold → B) is refused', async () => {
    const d = voteSetup([{ keyHash: ORG_KEY }], false);
    const [row] = await d.o.handleAll(REF);
    expect(row!.status).toBe('rejected');
    expect(row!.lastError).toMatch(/does not hold/);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('a recorded seat the org has since removed is refused, and removed from the registry', async () => {
    const d = voteSetup([{ keyHash: ORG_KEY }], true);
    const [row] = await d.o.handleAll(REF);
    expect(row!.status).toBe('rejected');
    expect((await d.registry.get(B))?.seats).toEqual([]);
  });

  it('an unreadable org page: no vote, retryable', async () => {
    const d = voteSetup([{ keyHash: ORG_KEY }, { delegate: B }], true);
    delete d.pages[ORG];
    const [row] = await d.o.handleAll(REF);
    expect(row!.status).not.toBe('rejected');
    expect(row!.lastError).toMatch(/^wrapper_unreadable/);
    expect(d.acc.submissions).toHaveLength(0);
  });
});

describe('registering an enrolling wrapper', () => {
  async function serve(registry?: MemoryWrapperRegistry) {
    const server = createServer({
      orchestrator: {} as never, store: new MemoryStore(), keyring: {} as never, accumulate: {} as never, pause: { paused: false }, logger: silent,
      adminApiKey: 'k', ...(registry ? { wrapperRegistry: registry, wrapperOurBook: T } : {}),
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    const call = (method: string, body?: unknown, key = 'k') => new Promise<{ status: number; json: any }>((resolve, reject) => {
      const r = http.request({ host: '127.0.0.1', port, method, path: '/v1/admin/wrappers', headers: { 'x-api-key': key, 'content-type': 'application/json' } }, (res) => {
        const c: Buffer[] = []; res.on('data', (x) => c.push(x)); res.on('end', () => { const t = Buffer.concat(c).toString(); resolve({ status: res.statusCode!, json: t ? JSON.parse(t) : undefined }); });
      });
      r.on('error', reject); r.end(body ? JSON.stringify(body) : undefined);
    });
    return { server, call };
  }

  it('registers as ENROLLING (never active), needs the admin key, and validates the books', async () => {
    const reg = new MemoryWrapperRegistry();
    const { server, call } = await serve(reg);
    const body = { wrapper_book: B, subject_id: 'alice', subscriber_book: ALICE_BOOK };
    expect((await call('POST', body, 'wrong')).status).toBe(401);
    expect((await call('POST', { ...body, wrapper_book: B1 })).status).toBe(400);              // a page, not a book
    expect((await call('POST', { ...body, subject_id: undefined })).status).toBe(400);         // no subject
    expect((await call('POST', { ...body, subscriber_book: undefined })).status).toBe(400);    // no subscriber book
    expect((await call('POST', { ...body, subscriber_book: ALICE })).status).toBe(400);        // a page, not a book
    const ok = await call('POST', body);
    expect(ok.status).toBe(201);
    expect(ok.json.wrapper).toMatchObject({ wrapperBook: B, wrapperPage: B1, subscriberBook: ALICE_BOOK, status: 'enrolling' });
    expect((await call('POST', { ...body, subject_id: 'mallory' })).status).toBe(409);         // cannot re-point while enrolling
    expect((await call('POST', { ...body, subscriber_book: 'acc://p2.acme/book' })).status).toBe(409);
    await reg.upsert({ ...(await reg.get(B))!, status: 'active' });
    expect((await call('POST', { ...body, subject_id: 'mallory' })).status).toBe(409);         // cannot reset an active wrapper
    expect((await call('GET')).json.wrappers).toHaveLength(1);
    server.close();
  });

  it('refuses a subscriber book that sorts before Trust Stamp\'s, with a reason, before anything is on chain', async () => {
    const reg = new MemoryWrapperRegistry();
    const { server, call } = await serve(reg);
    // T here is acc://a-ts.acme/book, and acc://a-a.acme/book sorts before it ('a' < 't').
    const early = await call('POST', { wrapper_book: 'acc://a-a.acme/id', subject_id: 'eve', subscriber_book: 'acc://a-a.acme/book' });
    expect(early.status).toBe(422);
    expect(early.json).toMatchObject({ error: 'wrapper_order' });
    expect(early.json.reason).toMatch(/sorts before acc:\/\/a-ts\.acme\/book/);
    expect(await reg.list()).toEqual([]);
    server.close();
  });

  it('is absent outside wrapper mode', async () => {
    const { server, call } = await serve();
    expect((await call('GET')).status).toBe(404);
    server.close();
  });
});

describe('discovery of a wrapper being created', () => {
  it('an enrolling wrapper is watched at its page as well as its book; an active one at its book only', async () => {
    const { Poller } = await import('../src/poller.js');
    const acc = new WrapperChain();
    const registry = new MemoryWrapperRegistry();
    await registry.upsert({ wrapperBook: B, wrapperPage: B1, subjectId: 'alice', enrolledAt: 0, seats: [], status: 'enrolling' });
    await registry.upsert({ wrapperBook: 'acc://q.acme/id', wrapperPage: 'acc://q.acme/id/1', subjectId: 'bob', enrolledAt: 1, seats: [] });
    acc.pendingOn(B1, TX, B1);
    const seen: unknown[] = [];
    const orch = { handleAll: async (r: unknown) => { seen.push(r); return []; } } as never;
    const queried: string[] = [];
    const orig = acc.listPendingForAccount.bind(acc);
    acc.listPendingForAccount = async (u: string) => { queried.push(u); return orig(u); };
    await (new Poller(acc, orch, TS_PAGE, 1000, silent, Date.now, undefined, T, { registry, concurrency: 4 }) as unknown as { tick(): Promise<void> }).tick();
    expect(queried.sort()).toEqual([B, B1, 'acc://q.acme/id'].sort());
    expect(seen).toEqual([{ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B }]);
  });
});

describe('review follow-ups', () => {
  it('a creation-shaped tx on an ACTIVE wrapper\'s page is not a creation vote', async () => {
    const d = setup({ status: 'active' });
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    expect(await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B })).toEqual([]);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('adding a PAGE of our book is not adding our book (the network would wait for T/book/1 forever)', async () => {
    const d = setup();
    const ops = CREATE_OPS.map((o) => (o.type === 'add' && o.entry?.delegate === T ? { type: 'add', entry: { delegate: TS_PAGE } } : o));
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: ops }, principal: B1 });
    expect(await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B })).toEqual([]);
  });

  it('a creation that swaps the temporary key FOR our book with an update op is recognised and checked', async () => {
    const d = setup();
    const ops = [
      { type: 'add', entry: { delegate: ALICE_BOOK } },
      { type: 'update', oldEntry: { keyHash: TEMP }, newEntry: { delegate: T } },
      { type: 'setThreshold', threshold: 2 },
    ];
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: ops }, principal: B1 });
    const rows = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    expect(rows.map((r) => [r.status, r.kind])).toEqual([['signed', 'wrapper_create']]);
  });

  it('a creation run directly with a ref whose wrapperBook does not own the principal is refused', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    const row = await d.o.handle({ txHash: TX, signerUrl: TS_PAGE, principal: B1, delegators: [], kind: 'wrapper_create', wrapperBook: 'acc://mallory.acme/id' });
    expect(row.status).toBe('rejected');
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('settlement: a transaction that FAILED on chain is settled failed, and one never found is given up on', async () => {
    const d = setup();
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    d.acc.pending.get(TX)!.failed = true;
    await d.o.settleEnrolments();
    expect((await d.store.get(row!.txHash))?.settled).toBe('failed');

    const e = setup();
    e.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    await e.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    e.acc.pending.delete(TX);
    for (let i = 0; i < 19; i++) await e.o.settleEnrolments();
    expect((await e.store.get(TX))?.settled).toBeUndefined();
    await e.o.settleEnrolments();
    expect((await e.store.get(TX))?.settled).toBe('failed');
    expect((await e.registry.get(B))?.status).toBe('enrolling');
  });

  it('a one-hop vote that is not a seat attach is refused (a wrapper sits on org pages in this model)', async () => {
    const d = setup({ status: 'active' });
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    d.acc.addPending(TX, { body: { type: 'sendTokens', to: [] }, principal: 'acc://o.acme/tokens' });
    d.acc.approvesThrough(TX, ALICE, [B1]);
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: 'acc://o.acme/tokens' });
    expect(row!.status).toBe('rejected');
    expect(row!.lastError).toMatch(/names no org page/);
  });

  it('a two-hop path to a page that adds the wrapper is a vote (seat-checked), not a seat attach', async () => {
    const d = setup({ status: 'active' });
    d.pages[B1] = page(2, { delegate: T }, { delegate: ALICE_BOOK });
    d.pages[ORG] = page(2, { keyHash: ORG_KEY }, { delegate: B });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: B } }] }, principal: 'acc://o.acme/other/1' });
    d.acc.approvesThrough(TX, ALICE, [B1, ORG]);
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: 'acc://o.acme/other/1' });
    expect(row!.kind).toBe('vote');
    expect(row!.status).toBe('signed');
  });
});

describe('the naming rule', () => {
  it('wrapperOrderProblem: a subscriber book must sort after Trust Stamp\'s, as a lowercase URL', async () => {
    const { wrapperOrderProblem } = await import('../src/delegation/wrapper.js');
    expect(wrapperOrderProblem('acc://0truststamp.acme/book', 'acc://alice.acme/book')).toBeUndefined();
    expect(wrapperOrderProblem('acc://0truststamp.acme/book', 'acc://ZED.acme/book')).toBeUndefined();
    // The runbook's original name does not sort first against ordinary subscriber names…
    expect(wrapperOrderProblem('acc://truststamp.acme/book', 'acc://alice.acme/book')).toMatch(/sorts before acc:\/\/truststamp\.acme\/book/);
    // …and no name beats every possible one: these still sort before the recommended name, and are refused.
    expect(wrapperOrderProblem('acc://0truststamp.acme/book', 'acc://0-x.acme/book')).toMatch(/sorts before/);
    expect(wrapperOrderProblem('acc://0truststamp.acme/book', 'acc://00x.acme/book')).toMatch(/sorts before/);
    expect(wrapperOrderProblem('acc://0truststamp.acme/book', 'ACC://0TRUSTSTAMP.acme/book')).toMatch(/cannot be Trust Stamp's own book/);
  });

  it('the creation vote requires exactly the subscriber book that was registered', async () => {
    const d = setup();
    await d.registry.upsert({ ...(await d.registry.get(B))!, subscriberBook: 'acc://p2.acme/book' });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });   // seats p.acme/book instead
    const [row] = await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B });
    expect(row!.status).toBe('rejected');
    expect(row!.lastError).toMatch(/does not add the registered subscriber book acc:\/\/p2\.acme\/book/);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('…and a creation that seats the registered book is co-signed', async () => {
    const d = setup();
    await d.registry.upsert({ ...(await d.registry.get(B))!, subscriberBook: ALICE_BOOK });
    d.acc.addPending(TX, { body: { type: 'updateKeyPage', operation: CREATE_OPS }, principal: B1 });
    expect((await d.o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: B1, wrapperBook: B })).map((r) => r.status)).toEqual(['signed']);
  });
});
