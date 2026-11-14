/**
 * Security review 2026-10-02, finding 1: a delegate seat on a human-only page counts only when the delegate book has
 * itself voted as Accumulate counts it (one of its pages reached its own threshold), recursively. One signature on a
 * 2-of-3 delegate page used to count the whole seat and end the request `signed` while the chain had not executed.
 * All books, pages and keys are FICTIONAL.
 */
import { describe, expect, it } from 'vitest';
import { advanceAwaitingHuman, countedSignatures, MAX_DELEGATION_DEPTH } from '../src/officer/landed.js';
import { MemoryStore, humanRecordId } from '../src/store/store.js';
import type { PageState } from '../src/ops/rotate.js';
import type { ChainSignature, TxSignatures } from '../src/accumulate/client.js';

const HUMAN = 'acc://fictional-firm-tcl1.acme/book/1';
const DELEGATE_BOOK = 'acc://fictional-partners-tcl1.acme/book';
const DELEGATE_P1 = `${DELEGATE_BOOK}/1`;
const INNER_BOOK = 'acc://fictional-inner-tcl1.acme/book';
const INNER_P1 = `${INNER_BOOK}/1`;
const TX = '6b'.repeat(32);
const D = ['d1', 'd2', 'd3'].map((x) => x.repeat(32));
const I = ['e1', 'e2'].map((x) => x.repeat(32));

const page = (threshold: number, keys: string[], delegates: string[] = [], rejectThreshold = 0): PageState => ({
  version: 1, threshold, rejectThreshold, keyHashes: keys,
  entries: [...keys.map((keyHash) => ({ keyHash, delegate: null })), ...delegates.map((delegate) => ({ keyHash: null, delegate }))],
});
/** The human page: one seat, the delegate book; accept threshold 1. */
const HUMAN_PAGE = page(1, [], [DELEGATE_BOOK]);
const pages: Record<string, PageState> = {
  [HUMAN]: HUMAN_PAGE,
  [DELEGATE_P1]: page(2, D),              // the delegate book votes only with two of three
  [INNER_P1]: page(2, I),
};
const readPage = async (p: string): Promise<PageState> => {
  const st = pages[p];
  if (!st) throw new Error(`FICTIONAL: no page ${p}`);
  return st;
};
const viaDelegate = (keyHash: string, vote: 'approve' | 'reject' = 'approve'): ChainSignature =>
  ({ type: 'ed25519', publicKeyHash: keyHash, delegators: [HUMAN], hops: [HUMAN], signer: DELEGATE_P1, vote });
const set = (...signatures: ChainSignature[]): TxSignatures => ({ status: 'pending', delivered: false, signatures });

describe('a delegate seat counts only when the delegate book reached its own threshold', () => {
  it('one signature on a 2-of-3 delegate page does not count the seat; the second does', async () => {
    expect(await countedSignatures(set(viaDelegate(D[0]!)), HUMAN, HUMAN_PAGE, readPage)).toEqual([]);
    const two = await countedSignatures(set(viaDelegate(D[0]!), viaDelegate(D[1]!)), HUMAN, HUMAN_PAGE, readPage);
    expect(two).toEqual([{ seat: `delegate:${DELEGATE_BOOK}`, publicKeyHash: D[0], type: 'ed25519', delegators: [HUMAN], vote: 'approve' }]);
  });

  it('the same key twice is one seat of the delegate page; a key not on it, or a mixed vote, does not make up the threshold', async () => {
    expect(await countedSignatures(set(viaDelegate(D[0]!), viaDelegate(D[0]!)), HUMAN, HUMAN_PAGE, readPage)).toEqual([]);
    expect(await countedSignatures(set(viaDelegate(D[0]!), viaDelegate('ff'.repeat(32))), HUMAN, HUMAN_PAGE, readPage)).toEqual([]);
    expect(await countedSignatures(set(viaDelegate(D[0]!), viaDelegate(D[1]!, 'reject')), HUMAN, HUMAN_PAGE, readPage)).toEqual([]);
  });

  it('a delegate page that cannot be read does not count, and says why (fail closed)', async () => {
    const unread: string[] = [];
    const none = async (): Promise<PageState> => { throw new Error('FICTIONAL node down'); };
    expect(await countedSignatures(set(viaDelegate(D[0]!), viaDelegate(D[1]!)), HUMAN, HUMAN_PAGE, none, unread)).toEqual([]);
    expect(unread.join(' ')).toContain('FICTIONAL node down');
    expect(await countedSignatures(set(viaDelegate(D[0]!), viaDelegate(D[1]!)), HUMAN, HUMAN_PAGE, undefined)).toEqual([]);
  });

  it('a delegate of a delegate is counted the same way, recursively', async () => {
    const twoLevel: PageState = page(2, [D[0]!], [INNER_BOOK]);
    const read = async (p: string) => (p === DELEGATE_P1 ? twoLevel : readPage(p));
    // Signed on the inner page, delegated through the delegate page, then through the human page.
    const inner = (keyHash: string): ChainSignature => ({ type: 'ed25519', publicKeyHash: keyHash, delegators: [HUMAN, DELEGATE_P1], hops: [DELEGATE_P1, HUMAN], signer: INNER_P1, vote: 'approve' });
    const direct: ChainSignature = viaDelegate(D[0]!);
    // D0 directly on the delegate page + only ONE inner signature: the inner book has not voted, so 1 of 2.
    expect(await countedSignatures(set(direct, inner(I[0]!)), HUMAN, HUMAN_PAGE, read)).toEqual([]);
    // The inner book reaches 2 of 2: it is the delegate page's second seat, so the delegate book has voted.
    expect((await countedSignatures(set(direct, inner(I[0]!), inner(I[1]!)), HUMAN, HUMAN_PAGE, read)).map((x) => x.seat)).toEqual([`delegate:${DELEGATE_BOOK}`]);
  });

  it(`a delegation deeper than ${MAX_DELEGATION_DEPTH} never counts`, async () => {
    const chain = Array.from({ length: MAX_DELEGATION_DEPTH + 2 }, (_, i) => `acc://fictional-d${i}-tcl1.acme/book`);
    const deep: Record<string, PageState> = { [HUMAN]: page(1, [], [chain[0]!]) };
    chain.forEach((b, i) => { deep[`${b}/1`] = i + 1 < chain.length ? page(1, [], [chain[i + 1]!]) : page(1, ['aa'.repeat(32)]); });
    const delegators = [HUMAN, ...chain.slice(0, -1).map((b) => `${b}/1`)];
    const s: ChainSignature = { type: 'ed25519', publicKeyHash: 'aa'.repeat(32), delegators, hops: [...delegators].reverse(), signer: `${chain.at(-1)}/1`, vote: 'approve' };
    const unread: string[] = [];
    expect(await countedSignatures(set(s), HUMAN, deep[HUMAN]!, async (p) => deep[p]!, unread)).toEqual([]);
    expect(unread.join(' ')).toContain('deeper than');
  });

  it('advanceAwaitingHuman keeps the request awaiting_human on one delegate signature and ends it on the threshold', async () => {
    const store = new MemoryStore();
    const key = humanRecordId(TX, HUMAN);
    await store.create({ txHash: TX, recordId: key, signerUrl: HUMAN, account: 'acc://fictional-payer-tcl1.acme/tokens', status: 'awaiting_human', attempts: 0, createdAt: 1, updatedAt: 1 } as never);
    const onChain: ChainSignature[] = [viaDelegate(D[0]!)];
    const deps = { store, readPage, getTxSignatures: async () => set(...onChain) };
    expect(await advanceAwaitingHuman(deps, TX, HUMAN)).toMatchObject({ status: 'awaiting_human' });
    expect((await store.getReceipt(key))?.vote).toBeUndefined();
    onChain.push(viaDelegate(D[2]!));
    expect(await advanceAwaitingHuman(deps, TX, HUMAN)).toMatchObject({ status: 'signed' });
    expect(await store.getReceipt(key)).toMatchObject({ vote: 'approve', signedBy: { page: HUMAN } });
  });
});
