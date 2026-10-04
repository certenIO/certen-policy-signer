/**
 * The wrapper invariant, checked on every vote. Wrapper runbook, change 5 (Phase 5).
 *
 *   acc://p.acme/id     authorities [acc://p.acme/id]
 *   acc://p.acme/id/1   2-of-2 { → acc://p.acme/book , → acc://a-ts.acme/book }
 *
 * Our vote is only meaningful while no set of signatures WITHOUT Trust Stamp can satisfy the wrapper.
 * Each way that could stop being true is a test below, as is each change that would make it stop.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { BookState, WrapperReader, applyKeyPageOps, checkWrapper, checkWrapperChange, chainWrapperReader, networkOrder, targetsWrapper } from '../src/delegation/wrapper.js';
import { PageState } from '../src/ops/rotate.js';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { extractGovernance } from '../src/decode/facts.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Notifier, NotifyEvent } from '../src/notify.js';
import { WrapperChain } from './support/wrapper-chain.js';
import { MemoryWrapperRegistry } from '../src/registry/wrappers.js';

const silent = pino({ level: 'silent' });
const B = 'acc://p.acme/id';
const B1 = 'acc://p.acme/id/1';
const T = 'acc://a-ts.acme/book';
const ALICE_BOOK = 'acc://p.acme/book';
const KEY = 'aa'.repeat(32);

const page = (threshold: number, ...entries: Array<{ keyHash?: string; delegate?: string }>): PageState => {
  const e = entries.map((x) => ({ keyHash: x.keyHash ?? null, delegate: x.delegate ?? null }));
  return { version: 1, threshold, keyHashes: e.map((x) => x.keyHash).filter((h): h is string => !!h), entries: e };
};
const VALID = () => ({
  book: { authorities: [{ url: B, disabled: false }], pageCount: 1 } as BookState,
  pages: { [B1]: page(2, { delegate: ALICE_BOOK }, { delegate: T }) } as Record<string, PageState>,
});

/** A reader over a state held in memory; a missing page throws, as an unreadable one would. */
function reader(st: ReturnType<typeof VALID>): WrapperReader {
  return {
    readBook: async (u) => { if (u.toLowerCase() !== B) throw new Error('no such book'); return structuredClone(st.book); },
    readPage: async (u) => { const p = st.pages[u.toLowerCase()]; if (!p) throw new Error(`no such page ${u}`); return structuredClone(p); },
  };
}

describe('checkWrapper', () => {
  it('the valid 2-of-2 shape passes', async () => {
    expect(await checkWrapper(reader(VALID()), B, T)).toEqual({ ok: true });
  });

  it("refuses the runbook's own naming, where Trust Stamp's book sorts after the subscriber's", async () => {
    const s2 = VALID();
    s2.pages[B1] = page(2, { delegate: 'acc://alice.acme/book' }, { delegate: 'acc://truststamp.acme/book' });
    const r = await checkWrapper(reader(s2), B, 'acc://truststamp.acme/book');
    expect(!r.ok && r.reason).toMatch(/not the page's first entry .*UpdateKey/);
  });

  it('refuses a T entry that also carries a key hash', async () => {
    const s2 = VALID();
    s2.pages[B1] = page(2, { delegate: ALICE_BOOK }, { keyHash: KEY, delegate: T });
    const r = await checkWrapper(reader(s2), B, T);
    expect(!r.ok && r.reason).toMatch(/also carries key hash/);
  });

  it('matches URLs case-insensitively', async () => {
    const s = VALID();
    s.pages[B1] = page(2, { delegate: ALICE_BOOK }, { delegate: 'ACC://A-TS.acme/Book' });
    expect(await checkWrapper(reader(s), 'acc://P.acme/id', T)).toEqual({ ok: true });
  });

  const broken: Array<[string, (s: ReturnType<typeof VALID>) => void, RegExp]> = [
    ['a second authority', (s) => { s.book.authorities.push({ url: 'acc://bank.acme/book', disabled: false }); }, /authorities must be exactly/],
    ['a different sole authority', (s) => { s.book.authorities = [{ url: 'acc://bank.acme/book', disabled: false }]; }, /authorities must be exactly/],
    ['its own authority disabled', (s) => { s.book.authorities[0]!.disabled = true; }, /disabled/],
    ['a page without T', (s) => { s.pages[B1] = page(2, { delegate: ALICE_BOOK }, { keyHash: KEY }); }, /no entry delegating/],
    ['threshold 1 on two entries', (s) => { s.pages[B1] = page(1, { delegate: ALICE_BOOK }, { delegate: T }); }, /can be met without/],
    ['a third entry without raising the threshold', (s) => { s.pages[B1] = page(2, { delegate: ALICE_BOOK }, { delegate: T }, { keyHash: KEY }); }, /can be met without/],
    ['T removed', (s) => { s.pages[B1] = page(1, { delegate: ALICE_BOOK }); }, /no entry delegating/],
    ['a second page without T', (s) => { s.book.pageCount = 2; s.pages['acc://p.acme/id/2'] = page(1, { keyHash: KEY }); }, /id\/2 has no entry delegating/],
  ];
  for (const [label, mutate, why] of broken) {
    it(`refuses ${label}`, async () => {
      const s = VALID();
      mutate(s);
      const res = await checkWrapper(reader(s), B, T);
      expect(res.ok).toBe(false);
      expect(!res.ok && res.reason).toMatch(why);
      expect(!res.ok && res.unreadable).toBeFalsy();
    });
  }

  it('a second page that also requires T passes', async () => {
    const s = VALID();
    s.book.pageCount = 2;
    s.pages['acc://p.acme/id/2'] = page(2, { keyHash: KEY }, { delegate: T });
    expect(await checkWrapper(reader(s), B, T)).toEqual({ ok: true });
  });

  it('an unreadable page is a refusal, marked unreadable (fail closed, but retryable)', async () => {
    const s = VALID();
    s.book.pageCount = 2;                         // page 2 does not exist in the reader
    const res = await checkWrapper(reader(s), B, T);
    expect(res).toMatchObject({ ok: false, unreadable: true });
  });

  it('the chain reader refuses a record of the wrong type rather than reading it as an empty page', async () => {
    const c = new RawAccumulateClient('http://node.test/v3', silent as never);
    (c as unknown as { query: (u: string) => Promise<unknown> }).query = async (u) => (u === B
      ? { account: { type: 'keyBook', url: B, authorities: [{ url: B }], pageCount: 1 } }
      : { account: { type: 'tokenAccount', url: u } });
    const res = await checkWrapper(chainWrapperReader(c), B, T);
    expect(res).toMatchObject({ ok: false, unreadable: true });
    expect(!res.ok && res.reason).toMatch(/not a keyPage/);
  });

  it('the chain reader reads the live record shape: absent acceptThreshold means 1, delegates kept', async () => {
    const c = new RawAccumulateClient('http://node.test/v3', silent as never);
    (c as unknown as { query: (u: string) => Promise<unknown> }).query = async (u) => (u === B
      ? { account: { type: 'keyBook', url: B, authorities: [{ url: B }], pageCount: 1 } }
      : { account: { type: 'keyPage', url: B1, acceptThreshold: 2, keys: [{ delegate: ALICE_BOOK }, { delegate: T }] } });
    expect(await checkWrapper(chainWrapperReader(c), B, T)).toEqual({ ok: true });
  });
});

/** The governance fact the resolver would produce for an UpdateKeyPage body. */
const ukp = (...operation: unknown[]) => extractGovernance({ type: 'updateKeyPage', operation } as never, B1)!;

describe('applyKeyPageOps (mirrors chain/update_key_page.go)', () => {
  const start = () => page(2, { delegate: ALICE_BOOK }, { delegate: T });

  it('add a key AND raise the threshold to match: still valid', async () => {
    const r = applyKeyPageOps(start(), B1, ukp({ type: 'add', entry: { keyHash: KEY } }, { type: 'setThreshold', threshold: 3 }).operations);
    expect(r.ok && r.page.threshold).toBe(3);
    const s = VALID();
    s.pages[B1] = (r as { page: PageState }).page;
    expect(await checkWrapper(reader(s), B, T)).toEqual({ ok: true });
  });

  it('removal clamps the threshold the way the network does', () => {
    const r = applyKeyPageOps(start(), B1, ukp({ type: 'remove', entry: { delegate: T } }).operations);
    expect(r.ok && r.page.threshold).toBe(1);
    expect(r.ok && r.page.entries).toEqual([{ keyHash: null, delegate: ALICE_BOOK }]);
  });

  it('refuses what the network would refuse: a duplicate, a missing entry, an impossible threshold, the last key of page 1', () => {
    expect(applyKeyPageOps(start(), B1, ukp({ type: 'add', entry: { delegate: T } }).operations).ok).toBe(false);
    expect(applyKeyPageOps(start(), B1, ukp({ type: 'remove', entry: { keyHash: KEY } }).operations).ok).toBe(false);
    expect(applyKeyPageOps(start(), B1, ukp({ type: 'setThreshold', threshold: 3 }).operations).ok).toBe(false);
    expect(applyKeyPageOps(page(1, { delegate: T }), B1, ukp({ type: 'remove', entry: { delegate: T } }).operations).ok).toBe(false);
  });
});

describe('changes to the wrapper itself', () => {
  const change = (st: ReturnType<typeof VALID>, bodyType: string, governance?: ReturnType<typeof ukp>, account = B1) =>
    checkWrapperChange(reader(st), B, T, { bodyType, account, ...(governance ? { governance } : {}) });

  it('UpdateKeyPage adding a key with the threshold raised to match: allowed', async () => {
    expect(await change(VALID(), 'updateKeyPage', ukp({ type: 'add', entry: { keyHash: KEY } }, { type: 'setThreshold', threshold: 3 }))).toEqual({ ok: true });
  });

  it('UpdateKeyPage adding a key WITHOUT raising the threshold: refused', async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'add', entry: { keyHash: KEY } }));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/after this change: .*can be met without/);
  });

  it('UpdateKeyPage removing T: refused', async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'remove', entry: { delegate: T } }));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/no entry delegating/);
  });

  it('UpdateKeyPage replacing T with another book: refused', async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'update', oldEntry: { delegate: T }, newEntry: { delegate: 'acc://evil.acme/book' } }));
    expect(!r.ok && r.reason).toMatch(/no entry delegating/);
  });

  it("UpdateKeyPage giving T's entry a key hash: refused (the key holder could then fill our seat)", async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'update', oldEntry: { delegate: T }, newEntry: { keyHash: KEY, delegate: T } }));
    expect(!r.ok && r.reason).toMatch(/also carries key hash/);
  });

  it('UpdateKeyPage lowering the threshold to 1: refused', async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'setThreshold', threshold: 1 }));
    expect(!r.ok && r.reason).toMatch(/can be met without/);
  });

  it('UpdateKeyPage adding a keyless delegate that sorts BEFORE T: refused (it would take index 0)', async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'add', entry: { delegate: 'acc://0aaa.acme/book' } }, { type: 'setThreshold', threshold: 3 }));
    expect(!r.ok && r.reason).toMatch(/not the page's first entry/);
  });

  it('reject/response thresholds and allowed lists pass through, but not past what the network allows', async () => {
    expect(await change(VALID(), 'updateKeyPage', ukp({ type: 'setRejectThreshold', threshold: 1 }), B1)).toEqual({ ok: true });
    expect(await change(VALID(), 'updateKeyPage', ukp({ type: 'updateAllowed', deny: ['sendTokens'] }), B1)).toEqual({ ok: true });
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'setResponseThreshold', threshold: 2 }));
    expect(!r.ok && r.reason).toMatch(/would fail on chain: setResponseThreshold/);
  });

  it('an UpdateKeyPage whose page cannot be read is unreadable (retryable), not approved', async () => {
    const r = await checkWrapperChange({ readBook: async () => VALID().book, readPage: async () => { throw new Error('timeout'); } }, B, T,
      { bodyType: 'updateKeyPage', account: B1, governance: ukp({ type: 'setRejectThreshold', threshold: 1 }) });
    expect(r).toMatchObject({ ok: false, unreadable: true });
  });

  it('an UpdateKeyPage naming the book itself as principal is refused, not retried forever as unreadable', async () => {
    const r = await change(VALID(), 'updateKeyPage', ukp({ type: 'setThreshold', threshold: 2 }), B);
    expect(r).toMatchObject({ ok: false });
    expect(!r.ok && r.unreadable).toBeFalsy();
  });

  it('an entry whose key hash is present but unreadable makes the operation unrecognised, so it is refused', async () => {
    const g = ukp({ type: 'add', entry: { keyHash: 'not-hex', delegate: 'acc://x.acme/book' } });
    expect(g.operations[0]).toMatchObject({ unrecognized: true });
    expect((await change(VALID(), 'updateKeyPage', g)).ok).toBe(false);
  });

  it('UpdateKeyPage with an operation that could not be read: refused', async () => {
    expect((await change(VALID(), 'updateKeyPage', ukp({ type: 'teleport' }))).ok).toBe(false);
  });

  it('CreateKeyPage on B: refused (a new page starts at threshold 1, without T)', async () => {
    const r = await change(VALID(), 'createKeyPage', undefined, B);
    expect(!r.ok && r.reason).toMatch(/threshold 1/);
  });

  it('UpdateAccountAuth on B: refused', async () => {
    expect((await change(VALID(), 'updateAccountAuth', undefined, B)).ok).toBe(false);
  });

  it("UpdateKey on a page of B, T first: Alice's entry gains a key hash and stays AFTER T, so nothing re-indexes into T's slot", async () => {
    // UpdateKey initiated by Alice's book: her entry keeps its delegate (preserveDelegate) and gets a key
    // hash, then is re-sorted (update_key.go:260-268). Simulate exactly that, in the network's order.
    const before = networkOrder(VALID().pages[B1]!.entries);
    expect(before[0]!.delegate).toBe(T);
    const after = networkOrder(before.map((e) => (e.delegate === ALICE_BOOK ? { keyHash: KEY, delegate: ALICE_BOOK } : e)));
    expect(after.map((e) => e.delegate)).toEqual([T, ALICE_BOOK]);            // T keeps index 0
    const s2 = VALID();
    s2.pages[B1] = page(2, ...after.map((e) => ({ ...(e.keyHash ? { keyHash: e.keyHash } : {}), ...(e.delegate ? { delegate: e.delegate } : {}) })));
    expect(await change(s2, 'updateKey')).toEqual({ ok: true });
  });

  it("THE BYPASS this guards against: with T sorting after Alice, her UpdateKey moves her vote's index into T's place", () => {
    // Runbook naming: acc://truststamp.acme/book sorts AFTER acc://alice.acme/book.
    const TS = 'acc://truststamp.acme/book';
    const AL = 'acc://alice.acme/book';
    const before = networkOrder([{ keyHash: null, delegate: TS }, { keyHash: null, delegate: AL }]);
    expect(before.map((e) => e.delegate)).toEqual([AL, TS]);                  // Alice votes at index 0
    const after = networkOrder([{ keyHash: null, delegate: TS }, { keyHash: KEY, delegate: AL }]);
    expect(after.map((e) => e.delegate)).toEqual([TS, AL]);                   // …now index 0 is T's, and she votes again at 1
  });

  it('any other body on the wrapper: refused', async () => {
    expect((await change(VALID(), 'burnCredits')).ok).toBe(false);
  });

  it('targetsWrapper recognises the book and its pages only', () => {
    expect(targetsWrapper(B, B)).toBe(true);
    expect(targetsWrapper('acc://P.acme/id/1', B)).toBe(true);
    expect(targetsWrapper('acc://p.acme/identity', B)).toBe(false);
    expect(targetsWrapper('acc://o.acme/book/1', B)).toBe(false);
  });
});

describe('the orchestrator checks the wrapper before asking the engine', () => {
  const TX = 'ab'.repeat(32);
  const TS_PAGE = 'acc://a-ts.acme/book/1';
  const ORG = 'acc://o.acme/book/1';

  function setup(st: ReturnType<typeof VALID>, opts: { principal?: string; body?: { type: string; [k: string]: unknown } } = {}) {
    const acc = new WrapperChain();
    const principal = opts.principal ?? 'acc://o.acme/tokens';
    acc.addPending(TX, { body: opts.body ?? { type: 'sendTokens', to: [] }, principal });
    acc.approvesThrough(TX, 'acc://p.acme/book/1', opts.principal === B1 ? [B1] : [B1, ORG]);
    const events: NotifyEvent[] = [];
    const notifier: Notifier = { emit: (e) => { events.push(e.event); } } as Notifier;
    const store = new MemoryStore();
    const policy = new MockPolicyClient({ decision: 'approve' });
    const r = reader(st);
    const reg = new MemoryWrapperRegistry();
    void reg.upsert({ wrapperBook: B, wrapperPage: B1, subjectId: 'alice', enrolledAt: 1, seats: [] });
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), TS_PAGE), policy, store, resolver: new Resolver(acc), logger: silent, notifier,
      wrapper: {
        ourBook: T, ourPage: TS_PAGE, isEnrolledWrapperPage: async (p) => p.toLowerCase() === B1, wrapperBooks: async () => [B],
        checkWrapper: (book) => checkWrapper(r, book, T),
        checkWrapperChange: (book, tx) => checkWrapperChange(r, book, T, tx),
        registry: reg,
        readPage: async () => page(2, { keyHash: KEY }, { delegate: B }),
      },
    });
    return { acc, store, policy, events, o, ref: { txHash: TX, signerUrl: TS_PAGE, principal } };
  }

  it('no wrapper check wired: refused, never assumed fine', async () => {
    const acc = new WrapperChain();
    acc.addPending(TX, { body: { type: 'sendTokens', to: [] }, principal: 'acc://o.acme/tokens' });
    acc.approvesThrough(TX, 'acc://p.acme/book/1', [B1, ORG]);
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), TS_PAGE), policy: new MockPolicyClient({ decision: 'approve' }),
      store: new MemoryStore(), resolver: new Resolver(acc), logger: silent,
      wrapper: { ourBook: T, ourPage: TS_PAGE, isEnrolledWrapperPage: async () => true, wrapperBooks: async () => [B] },
    });
    const [row] = await o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: 'acc://o.acme/tokens' });
    expect(row!.status).toBe('rejected');
    expect(acc.submissions).toHaveLength(0);
  });

  it('a valid wrapper: asked and signed', async () => {
    const d = setup(VALID());
    expect((await d.o.handleAll(d.ref)).map((r) => r.status)).toEqual(['signed']);
  });

  it('a broken wrapper: not asked, not signed, rejected with a receipt and a denial notice', async () => {
    const s = VALID();
    s.pages[B1] = page(1, { delegate: ALICE_BOOK }, { delegate: T });
    const d = setup(s);
    const [row] = await d.o.handleAll(d.ref);
    expect(row!.status).toBe('rejected');
    expect(row!.lastError).toMatch(/^wrapper_invariant: /);
    expect(d.policy.calls).toHaveLength(0);
    expect(d.acc.submissions).toHaveLength(0);
    expect((await d.store.getReceipt(row!.workKey!))?.policyEvidence).toMatchObject({ blockedBy: 'wrapper_invariant', wrapper: B });
    await new Promise((r) => setTimeout(r, 0));
    expect(d.events).toContain('decision.denied');
  });

  it('an unreadable wrapper: not signed, and left retryable rather than rejected', async () => {
    const s = VALID();
    s.book.pageCount = 2;
    const d = setup(s);
    const [row] = await d.o.handleAll(d.ref);
    expect(row!.status).not.toBe('rejected');
    expect(row!.lastError).toMatch(/^wrapper_unreadable: /);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('a change on the wrapper itself that would break it: refused before the engine is asked', async () => {
    const d = setup(VALID(), { principal: B1, body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { keyHash: KEY } }] } });
    const [row] = await d.o.handleAll(d.ref);
    expect(row!.status).toBe('rejected');
    expect(row!.lastError).toMatch(/after this change/);
    expect(d.policy.calls).toHaveLength(0);
  });

  it('a change on the wrapper itself that keeps it valid: asked and signed through [B/1]', async () => {
    const d = setup(VALID(), { principal: B1, body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { keyHash: KEY } }, { type: 'setThreshold', threshold: 3 }] } });
    expect((await d.o.handleAll(d.ref)).map((r) => r.status)).toEqual(['signed']);
  });
});
