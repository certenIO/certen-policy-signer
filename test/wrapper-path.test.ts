/**
 * The signing path per transaction, and idempotency per path. Wrapper runbook, change 2 (Phase 3).
 *
 * ── THE MODEL ──────────────────────────────────────────────────────────────────────────────────────
 *
 *   acc://p.acme/id/1        2-of-2 { → Alice's own book , → Trust Stamp's book }       (Alice's wrapper)
 *   acc://o.acme/book/1      N-of-M { … , → p.acme/id , → q.acme/id }                  (the org page)
 *
 * Alice signs with her own key through `[P/id/1, O/book/1]`. Her page meets its threshold and the network
 * sends her BOOK's authority signature to `P/id/1`, checks it is a delegate there, and records it on the
 * wrapper's partition with the remaining path `[P/id/1, O/book/1]`. Trust Stamp must sign through that
 * same path, because a page counts votes per path (`SignerWillVote`, `entry.PathHash()`).
 *
 * ── WHY THE PATH IS READ AT THE WRAPPER, NOT OFF HER KEY SIGNATURE ─────────────────────────────────
 *
 * Her key signature is recorded with whatever delegators it CLAIMS, before any hop checks them, and only
 * on her own partition. Read at the principal it is invisible across BVNs, and where it is visible anyone
 * could claim Alice's wrapper with their own key. Both are tested below.
 *
 * ── THE HIDDEN SECOND BUG ──────────────────────────────────────────────────────────────────────────
 *
 * The store was keyed by tx hash, so when Alice AND Bob sit on the page that approves one transaction the
 * second Trust Stamp vote was skipped as "idempotent". The Alice-and-Bob tests show the work key fixed it.
 */
import { describe, it, expect, afterAll } from 'vitest';
import pino from 'pino';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveWrapperPaths, workKey } from '../src/delegation/path.js';
import { AuthorityVote } from '../src/accumulate/client.js';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { FileStore, MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { loadConfig } from '../src/config.js';
import { WrapperChain, submittedVote } from './support/wrapper-chain.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const TS_BOOK = 'acc://ts.acme/book';
const TS_PAGE = 'acc://ts.acme/book/1';
const ALICE = 'acc://p.acme/book/1';     // Alice's own page
const BOB = 'acc://q.acme/book/1';
const W_ALICE = 'acc://p.acme/id/1';     // Alice's wrapper page
const W_BOB = 'acc://q.acme/id/1';
const ORG = 'acc://o.acme/book/1';
const PRINCIPAL = 'acc://o.acme/tokens';

const vote = (origin: string, path: string[], over: Partial<AuthorityVote> = {}): AuthorityVote => ({
  origin, authority: origin.replace(/\/\d+$/, ''), delegators: path, vote: 'accept', historical: false, ...over,
});
const enrolled = (...pages: string[]) => async (p: string) => pages.map((x) => x.toLowerCase()).includes(p.toLowerCase());
const opts = (...pages: string[]) => ({ ourBook: TS_BOOK, ourPage: TS_PAGE, isEnrolledWrapperPage: enrolled(...pages) });

describe('resolveWrapperPaths', () => {
  it('one person approving through one wrapper gives one path, [W, O]', async () => {
    expect(await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG])], opts(W_ALICE)))
      .toEqual([{ wrapperPage: W_ALICE, path: [W_ALICE, ORG] }]);
  });

  it('custody below the person: the vote recorded at W already starts at W, so the path is [W, O]', async () => {
    // Key on a custodian page → custody book A → W → O. A's page met its threshold and sent A's book on to W.
    expect(await resolveWrapperPaths([vote('acc://a.acme/book/1', [W_ALICE, ORG])], opts(W_ALICE)))
      .toEqual([{ wrapperPage: W_ALICE, path: [W_ALICE, ORG] }]);
  });

  it('Alice and Bob through two wrappers give two paths', async () => {
    const paths = await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG]), vote(BOB, [W_BOB, ORG])], opts(W_ALICE, W_BOB));
    expect(paths.map((p) => p.path)).toEqual([[W_ALICE, ORG], [W_BOB, ORG]]);
  });

  it('our own prior vote on a path suppresses that path only', async () => {
    const paths = await resolveWrapperPaths(
      [vote(ALICE, [W_ALICE, ORG]), vote(BOB, [W_BOB, ORG]), vote(TS_PAGE, [W_ALICE, ORG])],
      opts(W_ALICE, W_BOB),
    );
    expect(paths.map((p) => p.path)).toEqual([[W_BOB, ORG]]);
  });

  it('a vote of ours on a DIFFERENT path does not suppress this one', async () => {
    const paths = await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG]), vote(TS_PAGE, [W_ALICE, 'acc://o.acme/board/1'])], opts(W_ALICE));
    expect(paths.map((p) => p.path)).toEqual([[W_ALICE, ORG]]);
  });

  it('a historical vote of ours does not suppress (it no longer counts, so we must vote again)', async () => {
    const paths = await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG]), vote(TS_PAGE, [W_ALICE, ORG], { historical: true })], opts(W_ALICE));
    expect(paths.map((p) => p.path)).toEqual([[W_ALICE, ORG]]);
  });

  it('a person who rejected or abstained through the wrapper gives nothing to co-sign', async () => {
    expect(await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG], { vote: 'reject' })], opts(W_ALICE))).toEqual([]);
    expect(await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG], { vote: 'abstain' })], opts(W_ALICE))).toEqual([]);
  });

  it('a historical approval gives nothing to co-sign', async () => {
    expect(await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG], { historical: true })], opts(W_ALICE))).toEqual([]);
  });

  it('a vote recorded on a page that is not an enrolled wrapper gives no path', async () => {
    expect(await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG])], opts(W_BOB))).toEqual([]);
  });

  it('a vote with no remaining path (direct, at the principal) gives no path', async () => {
    expect(await resolveWrapperPaths([vote(ALICE, [])], opts(W_ALICE))).toEqual([]);
  });

  it('our own votes never start a path', async () => {
    expect(await resolveWrapperPaths([vote(TS_PAGE, [W_ALICE, ORG])], opts(W_ALICE))).toEqual([]);
  });

  it('two people on the same path give it once', async () => {
    const paths = await resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG]), vote('acc://p2.acme/book/1', [W_ALICE, ORG])], opts(W_ALICE));
    expect(paths).toHaveLength(1);
  });

  it('compares URLs case-insensitively, as Accumulate does', async () => {
    // Positive: an enrolled page written in another case still starts a path…
    expect(await resolveWrapperPaths([vote(ALICE, ['ACC://P.acme/ID/1', ORG])], opts(W_ALICE))).toHaveLength(1);
    // …and our own vote in another case still suppresses it.
    expect(await resolveWrapperPaths(
      [vote(ALICE, ['ACC://P.acme/ID/1', ORG]), vote('acc://TS.acme/book/1', [W_ALICE, 'ACC://o.acme/BOOK/1'], { authority: 'ACC://ts.ACME/book' })],
      opts(W_ALICE),
    )).toEqual([]);
  });

  it('an enrolment lookup that throws fails the whole resolution (nothing partial is signed)', async () => {
    const boom = { ourBook: TS_BOOK, ourPage: TS_PAGE, isEnrolledWrapperPage: async () => { throw new Error('registry down'); } };
    await expect(resolveWrapperPaths([vote(ALICE, [W_ALICE, ORG])], boom)).rejects.toThrow('registry down');
  });
});

describe('reading authority signatures off a record', () => {
  /** A client whose only real behaviour is the record it is handed, in the v3 shape. */
  function clientReturning(record: unknown) {
    const c = new RawAccumulateClient('http://node.test/v3', silent as never);
    const scopes: string[] = [];
    (c as unknown as { query: (s: string) => Promise<unknown> }).query = async (s) => { scopes.push(s); return record; };
    return { c, scopes };
  }
  const authSig = (extra: Record<string, unknown>) => ({ type: 'authority', origin: ALICE, authority: 'acc://p.acme/book', delegator: [W_ALICE, ORG], ...extra });

  it('reads origin, authority, path and vote, keeps the historical flag, and asks at the given account', async () => {
    const { c, scopes } = clientReturning({
      status: 'pending',
      signatures: { records: [{ account: { url: W_ALICE }, signatures: { records: [
        { message: { type: 'signature', signature: authSig({}) } },
        { message: { type: 'signature', signature: authSig({ origin: BOB, authority: 'acc://q.acme/book' }) }, historical: true },
        { message: { type: 'signature', signature: { type: 'ed25519', publicKey: 'aa', signer: ALICE } } },
      ] } }] },
    });
    const out = await c.getAuthoritySignatures(TX, 'acc://p.acme/id');
    expect(scopes).toEqual([`acc://${TX}@p.acme/id`]);
    expect(out.unavailable).toBeUndefined();
    expect(out.votes).toEqual([
      { origin: ALICE, authority: 'acc://p.acme/book', delegators: [W_ALICE, ORG], vote: 'accept', historical: false },
      { origin: BOB, authority: 'acc://q.acme/book', delegators: [W_ALICE, ORG], vote: 'accept', historical: true },
    ]);
  });

  it('drops a suggestion, an unreadable vote and a malformed path rather than guessing', async () => {
    const { c } = clientReturning({ status: 'pending', signatures: { records: [{ signatures: { records: [
      { message: { signature: authSig({ vote: 'suggest' }) } },
      { message: { signature: authSig({ vote: 'maybe' }) } },
      { message: { signature: authSig({ delegator: [W_ALICE, 7] }) } },
      { message: { signature: authSig({ vote: 'reject' }) } },
    ] } }] } });
    expect((await c.getAuthoritySignatures(TX, 'acc://p.acme/id')).votes.map((v) => v.vote)).toEqual(['reject']);
  });

  it('reports a failed read as unavailable, never as "nobody voted"', async () => {
    const c = new RawAccumulateClient('http://node.test/v3', silent as never);
    (c as unknown as { query: () => Promise<unknown> }).query = async () => { throw new Error('ECONNREFUSED'); };
    const out = await c.getAuthoritySignatures(TX, 'acc://p.acme/id');
    expect(out.unavailable).toMatch(/ECONNREFUSED/);
    expect(out.votes).toEqual([]);
  });
});

describe('workKey', () => {
  it('is the bare tx hash with no path or an empty one, so existing stores keep working', () => {
    expect(workKey(TX)).toBe(TX);
    expect(workKey(TX, [])).toBe(TX);
  });

  it('differs per path, and is stable and case-insensitive for one path', () => {
    const a = workKey(TX, [W_ALICE, ORG]);
    const b = workKey(TX, [W_BOB, ORG]);
    expect(a).toMatch(new RegExp(`^${TX}:[0-9a-f]{16}$`));
    expect(a).not.toBe(b);
    expect(workKey(TX, [W_ALICE.toUpperCase(), ORG])).toBe(a);
  });
});

/** A wrapper-mode orchestrator over the mock chain. */
function wrapperSetup(enrolledPages: string[], decision: ConstructorParameters<typeof MockPolicyClient>[0] = { decision: 'approve' }) {
  const acc = new WrapperChain();
  acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '5' }] }, principal: PRINCIPAL });
  const store = new MemoryStore();
  const policy = new MockPolicyClient(decision);
  const signer = new LocalSigner(new Uint8Array(32).fill(9));
  const o = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(signer, TS_PAGE), policy, store, resolver: new Resolver(acc), logger: silent,
    wrapper: {
      ourBook: TS_BOOK, ourPage: TS_PAGE, isEnrolledWrapperPage: enrolled(...enrolledPages),
      wrapperBooks: async () => enrolledPages.map((p) => p.replace(/\/\d+$/, '')),
      checkWrapper: async () => ({ ok: true }),   // the invariant has its own suite (wrapper-invariant.test.ts)
    },
  });
  return { acc, store, policy, o };
}
const REF = { txHash: TX, signerUrl: TS_PAGE, principal: PRINCIPAL };

describe('wrapper mode in the orchestrator', () => {
  it('Alice and Bob on one tx: two work keys, two votes, each through its own path', async () => {
    const d = wrapperSetup([W_ALICE, W_BOB]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.approvesThrough(TX, BOB, [W_BOB, ORG]);

    const rows = await d.o.handleAll(REF);

    expect(rows.map((r) => r.status)).toEqual(['signed', 'signed']);
    expect(new Set(rows.map((r) => r.workKey)).size).toBe(2);
    expect(d.acc.submissions).toHaveLength(2);
    const votes = d.acc.submissions.map(submittedVote);
    expect(votes.map((v) => v.hops)).toEqual([[W_ALICE, ORG], [W_BOB, ORG]]);
    expect(votes.every((v) => v.signer === TS_PAGE)).toBe(true);
    // Each is its own question to the engine, naming its wrapper…
    expect(d.policy.calls.map((c) => c.wrapper)).toEqual([
      { page: W_ALICE, path: [W_ALICE, ORG] },
      { page: W_BOB, path: [W_BOB, ORG] },
    ]);
    // …stored under its own key, so neither overwrites the other.
    expect((await d.store.getPolicyRequest(rows[0]!.workKey!))?.wrapper?.page).toBe(W_ALICE);
    expect((await d.store.getPolicyRequest(rows[1]!.workKey!))?.wrapper?.page).toBe(W_BOB);
    expect(await d.store.getPolicyRequest(TX)).toBeUndefined();
    // Two receipts, not one overwritten by the other.
    expect((await d.store.getReceipt(rows[0]!.workKey!))?.signedBy?.delegators).toEqual([W_ALICE, ORG]);
    expect((await d.store.getReceipt(rows[1]!.workKey!))?.signedBy?.delegators).toEqual([W_BOB, ORG]);
  });

  it('the store alone keeps a second cycle from voting again, even before our vote is visible on chain', async () => {
    const d = wrapperSetup([W_ALICE, W_BOB]);
    d.acc.recordOurVotes = false;
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.approvesThrough(TX, BOB, [W_BOB, ORG]);
    await d.o.handleAll(REF);
    await d.o.handleAll(REF);
    expect(d.acc.submissions).toHaveLength(2);
  });

  it('our vote on chain alone suppresses the path, even with an empty store (a restart without state)', async () => {
    const d = wrapperSetup([W_ALICE]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.approvesThrough(TX, TS_PAGE, [W_ALICE, ORG]);
    expect(await d.o.handleAll(REF)).toEqual([]);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('Bob approving after our vote for Alice gets his own vote next cycle', async () => {
    const d = wrapperSetup([W_ALICE, W_BOB]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    await d.o.handleAll(REF);
    d.acc.approvesThrough(TX, BOB, [W_BOB, ORG]);
    await d.o.handleAll(REF);
    expect(d.acc.submissions.map(submittedVote).map((v) => v.hops)).toEqual([[W_ALICE, ORG], [W_BOB, ORG]]);
  });

  it('reads the votes at the wrapper books and the transaction at its principal, never at our page', async () => {
    const d = wrapperSetup([W_ALICE]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    await d.o.handleAll(REF);
    expect(d.acc.voteReads).toEqual(['acc://p.acme/id']);
    expect(d.acc.reads.length).toBeGreaterThan(0);
    expect(d.acc.reads.every((r) => r.at === PRINCIPAL)).toBe(true);
  });

  it('a wrapperBook hint narrows the read to that book; the path still comes from what is recorded there', async () => {
    const d = wrapperSetup([W_ALICE, W_BOB]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.approvesThrough(TX, BOB, [W_BOB, ORG]);
    await d.o.handleAll({ ...REF, wrapperBook: 'acc://q.acme/id' });
    expect(d.acc.voteReads).toEqual(['acc://q.acme/id']);
    expect(d.acc.submissions.map(submittedVote).map((v) => v.hops)).toEqual([[W_BOB, ORG]]);
  });

  it('a wrong hint finds nothing and signs nothing', async () => {
    const d = wrapperSetup([W_ALICE]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    expect(await d.o.handleAll({ ...REF, wrapperBook: 'acc://mallory.acme/id' })).toEqual([]);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('a key signature that merely CLAIMS Alice\'s wrapper triggers nothing (it was never checked at W)', async () => {
    const d = wrapperSetup([W_ALICE]);
    d.acc.keySigns(TX, 'acc://mallory.acme/book/1', [W_ALICE, ORG]);
    expect(await d.o.handleAll(REF)).toEqual([]);
    expect(d.policy.calls).toHaveLength(0);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('Alice rejecting through her wrapper: the engine is not asked and nothing is signed', async () => {
    const d = wrapperSetup([W_ALICE]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG], { vote: 'reject' });
    expect(await d.o.handleAll(REF)).toEqual([]);
    expect(d.policy.calls).toHaveLength(0);
  });

  it('a person through no enrolled wrapper: no work, no vote, no row', async () => {
    const d = wrapperSetup([W_BOB]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    expect(await d.o.handleAll(REF)).toEqual([]);
    expect(d.acc.submissions).toHaveLength(0);
    expect(d.policy.calls).toHaveLength(0);
    expect(await d.store.listRecent(10)).toEqual([]);
  });

  it('an unreadable wrapper book: nothing signed for it and no row, while a readable one proceeds', async () => {
    const d = wrapperSetup([W_ALICE, W_BOB]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.approvesThrough(TX, BOB, [W_BOB, ORG]);
    d.acc.unreadable.add('acc://p.acme/id');
    const rows = await d.o.handleAll(REF);
    expect(rows).toHaveLength(1);
    expect(d.acc.submissions.map(submittedVote).map((v) => v.hops)).toEqual([[W_BOB, ORG]]);
    expect((await d.store.listRecent(10)).map((r) => r.request.delegators)).toEqual([[W_BOB, ORG]]);
  });

  it('every wrapper book unreadable: nothing signed, nothing recorded', async () => {
    const d = wrapperSetup([W_ALICE]);
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.unreadable.add('acc://p.acme/id');
    expect(await d.o.handleAll(REF)).toEqual([]);
    expect(d.acc.submissions).toHaveLength(0);
    expect(await d.store.listRecent(10)).toEqual([]);
  });

  it('once the tx is delivered, our open rows on it are closed rather than left non-terminal forever', async () => {
    const d = wrapperSetup([W_ALICE], { decision: 'pending' });
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    const [row] = await d.o.handleAll(REF);
    expect(row!.status).toBe('awaiting_policy');
    d.acc.pending.get(TX)!.executed = true;
    expect(await d.o.handleAll(REF)).toEqual([]);
    expect((await d.store.get(row!.workKey!))?.status).toBe('signed');
    expect(await d.store.listNonTerminal()).toEqual([]);
  });

  it('a deny on one path does not stop the other', async () => {
    const d = wrapperSetup([W_ALICE, W_BOB], (r) => ({ decision: r.wrapper?.page === W_ALICE ? 'deny' : 'approve' }));
    d.acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    d.acc.approvesThrough(TX, BOB, [W_BOB, ORG]);
    const rows = await d.o.handleAll(REF);
    expect(rows.map((r) => r.status)).toEqual(['rejected', 'signed']);
    expect(d.acc.submissions.map(submittedVote).map((v) => v.hops)).toEqual([[W_BOB, ORG]]);
  });

  it('refuses a bare or empty-path reference in wrapper mode rather than signing directly on our page', async () => {
    const d = wrapperSetup([W_ALICE]);
    await expect(d.o.handle({ txHash: TX, signerUrl: TS_PAGE })).rejects.toThrow(/handleAll/);
    await expect(d.o.handle({ txHash: TX, signerUrl: TS_PAGE, delegators: [] })).rejects.toThrow(/handleAll/);
    expect(d.acc.submissions).toHaveLength(0);
  });

  it('outside wrapper mode handleAll is exactly handle (one row, keyed by the hash)', async () => {
    const acc = new WrapperChain();
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '5' }] }, principal: PRINCIPAL });
    const store = new MemoryStore();
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9))), policy: new MockPolicyClient({ decision: 'approve' }),
      store, resolver: new Resolver(acc), logger: silent, options: { delegators: [W_ALICE] },
    });
    const rows = await o.handleAll({ txHash: TX, signerUrl: TS_PAGE });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.workKey).toBeUndefined();
    expect((await store.get(TX))?.status).toBe('signed');
    expect(await store.getPolicyRequest(TX)).toBeDefined();
    // The boot-time delegate path still applies, unchanged.
    expect(submittedVote(acc.submissions[0]).hops).toEqual([W_ALICE]);
  });
});

describe('the store across the upgrade', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'certen-workkey-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it('a FileStore file written before work keys still loads, keyed by tx hash', async () => {
    const path = join(tmp, 'legacy.json');
    // The exact shape the previous release wrote: no workKey anywhere.
    writeFileSync(path, JSON.stringify({
      requests: [{ txHash: TX, signerUrl: TS_PAGE, status: 'signed', attempts: 1, createdAt: 1, updatedAt: 1 }],
      receipts: [{ txHash: TX, decision: 'approve', vote: 'approve' }],
      policyRequests: [{ requestId: 'r1', txHash: TX, account: PRINCIPAL, actionSummary: 'x', expiresAt: 'z' }],
    }));
    const s = new FileStore(path);
    expect((await s.get(TX))?.status).toBe('signed');
    expect((await s.getReceipt(TX))?.vote).toBe('approve');
    expect((await s.getPolicyRequest(TX))?.requestId).toBe('r1');
    // And path-keyed rows and requests live beside them without colliding, and survive a restart.
    const k = workKey(TX, [W_ALICE, ORG]);
    await s.create({ workKey: k, txHash: TX, signerUrl: TS_PAGE, status: 'discovered', attempts: 0, createdAt: 2, updatedAt: 2 });
    await s.update(k, { status: 'signed' });
    await s.savePolicyRequest({ requestId: 'r2', txHash: TX, account: PRINCIPAL, actionSummary: 'x', expiresAt: 'z' }, k);
    const reloaded = new FileStore(path);
    expect((await reloaded.get(TX))?.status).toBe('signed');
    expect((await reloaded.get(k))?.txHash).toBe(TX);
    expect((await reloaded.getPolicyRequest(TX))?.requestId).toBe('r1');
    expect((await reloaded.getPolicyRequest(k))?.requestId).toBe('r2');
    expect((await reloaded.listRecent(10)).map((r) => r.request.workKey ?? r.request.txHash).sort()).toEqual([TX, k].sort());
  });

  it('an update cannot move a row to another key', async () => {
    const s = new MemoryStore();
    const k = workKey(TX, [W_ALICE, ORG]);
    await s.create({ workKey: k, txHash: TX, signerUrl: TS_PAGE, status: 'discovered', attempts: 0, createdAt: 1, updatedAt: 1 });
    const next = await s.update(k, { workKey: 'other', txHash: 'cd'.repeat(32), status: 'signed' } as never);
    expect(next.workKey).toBe(k);
    expect(next.txHash).toBe(TX);
  });
});

describe('config for wrapper mode', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'certen-wrapper-cfg-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));
  let n = 0;
  const write = (wallet: string, extra: string[] = []) => {
    const p = join(tmp, `c-${n++}.yaml`);
    writeFileSync(p, [
      `wallet: { org_id: "o", accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"], signer_url: "${TS_PAGE}", ${wallet} }`,
      `signer: { provider: "local", local: { seed_hex: "${'a'.repeat(64)}" } }`,
      'policy: { url: "http://127.0.0.1:9099/decision" }',
      ...extra,
    ].join('\n'));
    return p;
  };

  it('accepts attachment_model: wrapper', () => {
    expect(loadConfig(write('attachment_model: "wrapper"')).wallet.attachment_model).toBe('wrapper');
  });
  it('refuses delegator_url together with wrapper', () => {
    expect(() => loadConfig(write(`attachment_model: "wrapper", delegator_url: "${W_ALICE}"`))).toThrow(/delegator_url/);
  });
  it('refuses wrapper with the gateway', () => {
    expect(() => loadConfig(write('attachment_model: "wrapper"', ['gateway: { enabled: true, url: "http://127.0.0.1:8090", api_key: "ck_live_x", identity: "acc://ts.acme" }'])))
      .toThrow(/gateway/);
  });
  it('leaves delegate mode as it was', () => {
    const cfg = loadConfig(write(`attachment_model: "delegate", delegator_url: "${W_ALICE}"`));
    expect(cfg.wallet.attachment_model).toBe('delegate');
    expect(cfg.wallet.delegator_url).toBe(W_ALICE);
  });
});
