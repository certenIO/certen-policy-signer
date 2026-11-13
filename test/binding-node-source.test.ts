/**
 * The node source reads Accumulate API v3 the way the DAX-3A live run saw it on Kermit:
 *   - a data entry record has NO timestamp; `value.received` is the index of the minor block that executed it, and the chain time of the
 *     entry is the time of THAT block (a `block` query scoped to the account);
 *   - the entries of a data account are the WriteData transactions of its MAIN chain: the `data` chain query resolves an entry to a
 *     transaction through the entry hash, so identical entries (accept, revoke, accept) collapse to the later transaction;
 *   - chain time has one-second resolution, so two entries can carry the same time.
 * FICTIONAL accounts, a fake node that answers in the recorded shapes (test/support/fake-node.ts).
 */
import { describe, expect, it } from 'vitest';
import { createNodeSource, type Meter } from '../src/binding/node-source.js';
import { FakeNode } from './support/fake-node.js';

const A = 'acc://fic-agent.acme/certen-acceptances';
const BOOK = 'acc://fic-agent.acme/book';
const accept = [new Uint8Array([1, 2, 3]), new Uint8Array([0xab])];
const revoke = [new Uint8Array([9, 9]), new Uint8Array([0xcd])];
const meter = (): Meter => ({ n: 0 });
const chainCalls = (n: FakeNode, scope = A, kind = 'chain') => n.calls.filter((c) => c === `${scope} ${kind}`).length;

function world() {
  const node = new FakeNode();
  node.dataAccount(A, [BOOK]);
  const src = createNodeSource(node.query);
  const total = async () => (await src.chainLength(A, meter()))!;
  return { node, src, total };
}

describe('the entries are the main-chain WriteData transactions, each with the time of the block that executed it', () => {
  it('accept, revoke, accept again (identical bytes): three entries, three transactions, three block times, in chain order', async () => {
    const { node, src, total } = world();
    const e1 = node.write(A, accept, 1_800_000_000);
    const e2 = node.write(A, revoke, 1_800_000_100);
    const e3 = node.write(A, accept, 1_800_000_200);
    const got = await src.entries(A, await total(), meter());
    expect(got).not.toBeNull();
    expect(got!.map((e) => e.txId)).toEqual([e1.txId, e2.txId, e3.txId]);
    expect(got!.map((e) => e.time)).toEqual([1_800_000_000, 1_800_000_100, 1_800_000_200]);
    expect(got![0]!.elements.map((b) => Buffer.from(b).toString('hex'))).toEqual(['010203', 'ab']);
    // the first acceptance is NOT dated by the later, byte-identical one (what the data chain would do)
    expect(got![0]!.time).not.toBe(got![2]!.time);
    expect(chainCalls(node, A, 'data')).toBe(0);
  });

  it('a record that is not a WriteData (the creation, an authority change) is not an entry, and the entries keep chain order around it', async () => {
    const { node, src, total } = world();
    const e1 = node.write(A, accept, 1_800_000_000);
    node.updateAuth(A, [BOOK, 'acc://other.acme/book']);
    const e2 = node.write(A, revoke, 1_800_000_050);
    const got = await src.entries(A, await total(), meter());
    expect(got!.map((e) => e.txId)).toEqual([e1.txId, e2.txId]);
  });

  it('an account with no entry yet has no entries (an empty list is a true answer, not a failure)', async () => {
    const { src, total } = world();
    expect(await src.entries(A, await total(), meter())).toEqual([]);
  });

  it('the time of a block is its time to the second: two entries of one second carry the same time (the library tie rule applies)', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_300);
    node.write(A, revoke, 1_800_000_300); // another block, the same second
    const got = await src.entries(A, await total(), meter());
    expect(got!.map((e) => e.time)).toEqual([1_800_000_300, 1_800_000_300]);
    expect(chainCalls(node, A, 'block')).toBe(2);
  });

  it('two entries of one block are dated by one block query', async () => {
    const { node, src, total } = world();
    const e1 = node.write(A, accept, 1_800_000_400);
    node.write(A, revoke, undefined, { block: e1.block });
    const got = await src.entries(A, await total(), meter());
    expect(got!.map((e) => e.time)).toEqual([1_800_000_400, 1_800_000_400]);
    expect(chainCalls(node, A, 'block')).toBe(1);
  });

  it('a block time already read is not asked again (it is chain history), a new entry costs one block query', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    node.write(A, revoke, 1_800_000_100);
    await src.entries(A, await total(), meter());
    expect(chainCalls(node, A, 'block')).toBe(2);
    node.write(A, accept, 1_800_000_200);
    const got = await src.entries(A, await total(), meter());
    expect(got!.map((e) => e.time)).toEqual([1_800_000_000, 1_800_000_100, 1_800_000_200]);
    expect(chainCalls(node, A, 'block')).toBe(3);
  });

  it('a block time that was not answered is never remembered: the node answers it next time', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    node.blockOverride = () => ({ recordType: 'minorBlock', index: 1, time: 'not a time', source: 'acc://bvn-BVN3.acme' });
    expect((await src.entries(A, await total(), meter()))![0]!.time).toBeUndefined();
    node.blockOverride = undefined;
    expect((await src.entries(A, await total(), meter()))![0]!.time).toBe(1_800_000_000);
  });
});

describe('an entry gets a time only from the block that executed it, and never a guessed one', () => {
  const timeOf = async (override: (scope: string, minor: number, honest: unknown) => unknown): Promise<number | undefined | 'unreadable'> => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    node.blockOverride = override;
    const got = await src.entries(A, await total(), meter());
    return got === null ? 'unreadable' : got[0]!.time;
  };

  it('a block record for another block, another record type, a missing time or an inexact time gives the entry no time', async () => {
    expect(await timeOf((_s, minor, h) => ({ ...(h as object), index: minor + 1 }))).toBeUndefined();
    expect(await timeOf((_s, _m, h) => ({ ...(h as object), recordType: 'account' }))).toBeUndefined();
    expect(await timeOf((_s, _m, h) => ({ ...(h as object), time: undefined }))).toBeUndefined();
    expect(await timeOf((_s, _m, h) => ({ ...(h as object), time: 1_800_000_000 }))).toBeUndefined();
    expect(await timeOf((_s, _m, h) => ({ ...(h as object), time: '2026-11-12T20:47:34+01:00' }))).toBeUndefined();
    expect(await timeOf((_s, _m, h) => ({ ...(h as object), time: '2026-13-40T25:61:61Z' }))).toBeUndefined();
    expect(await timeOf(() => 'a string')).toBeUndefined();
  });

  it('the fraction of a second is floored, the instant is exact UTC', async () => {
    expect(await timeOf((_s, _m, h) => ({ ...(h as object), time: '2026-11-12T20:47:34.987654321Z' }))).toBe(Date.parse('2026-11-12T20:47:34Z') / 1000);
  });

  it('a record without `received` (no executing block to ask) gives the entry no time; the entry is still an entry', async () => {
    const { node, src, total } = world();
    node.write(A, accept, null);
    const got = await src.entries(A, await total(), meter());
    expect(got).toHaveLength(1);
    expect(got![0]!.time).toBeUndefined();
    expect(chainCalls(node, A, 'block')).toBe(0);
  });

  it('a record that says `lastBlockTime` (a field of the ACCOUNT answer, not of an entry) is not a time', async () => {
    const { node, src, total } = world();
    node.write(A, accept, null);
    const orig = node.query;
    const wrapped = createNodeSource(async (scope, q) => {
      const r = await orig(scope, q);
      if (['chain', 'data'].includes((q as { queryType?: string } | undefined)?.queryType ?? '')) for (const rec of r.records) rec.value.lastBlockTime = '2026-11-12T22:21:35Z';
      return r;
    });
    const m = meter();
    const t = (await wrapped.chainLength(A, m))!;
    expect((await wrapped.entries(A, t, m))![0]!.time).toBeUndefined();
    void src; void total;
  });

  it('a block query that fails (a node outage) makes the account unreadable: a missing time is not the same fact as a failed read', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    node.blockOverride = () => { throw new Error('connect ECONNREFUSED'); };
    expect(await src.entries(A, await total(), meter())).toBeNull();
    node.blockOverride = undefined;
    expect(await src.entries(A, await total(), meter())).not.toBeNull(); // and the failure was not remembered
  });
});

describe('a main-chain record that cannot be read exactly makes the whole account unreadable', () => {
  it('a WriteData that was not delivered, a record without a body, a non-hex element, a missing id', async () => {
    const mk = (mut: (n: FakeNode) => void) => async () => {
      const { node, src, total } = world();
      node.write(A, accept, 1_800_000_000);
      mut(node);
      return src.entries(A, await total(), meter());
    };
    expect(await mk((n) => { n.accounts.get(A)!.chain[1]!.status = 'failed'; })()).toBeNull();
    expect(await mk((n) => { n.accounts.get(A)!.chain[1]!.noBody = true; })()).toBeNull();
    expect(await mk((n) => { n.accounts.get(A)!.chain[1]!.entry!.elements = ['zz']; })()).toBeNull();
    expect(await mk((n) => { n.accounts.get(A)!.chain[1]!.entry!.txId = 'not-a-txid'; })()).toBeNull();
    expect(await mk(() => undefined)()).not.toBeNull();
  });

  it('a short read, a node outage and a missing account are unreadable, never an empty list', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    const t = await total();
    node.historyShortRead = true;
    expect(await src.entries(A, t, meter())).toBeNull();
    node.historyShortRead = false;
    node.down.add(A);
    expect(await src.entries(A, t, meter())).toBeNull();
    node.down.delete(A);
    node.accounts.delete(A);
    expect(await src.entries(A, t, meter())).toBeNull();
  });
});

describe('a key book is read as a roster: keys AND delegate seats, every seat exactly, or the book is unreadable', () => {
  const BK = 'acc://fic-risk.acme/risk';
  const pagesOf = async (seats: Array<Record<string, unknown>>) => {
    const node = new FakeNode();
    node.book(BK, [{ keyHashes: [], threshold: 1, seats }]);
    return createNodeSource(node.query).keyBookPages(BK, meter());
  };

  it('a key seat, a delegate seat and a seat that is both: each is kept, hashes lower-cased', async () => {
    expect(await pagesOf([{ publicKeyHash: 'AB'.repeat(32) }, { delegate: 'acc://x.acme/book' }, { publicKeyHash: 'cd'.repeat(32), delegate: 'acc://y.acme/book' }])).toEqual([
      { url: `${BK}/1`, keyHashes: ['ab'.repeat(32), 'cd'.repeat(32)], delegates: ['acc://x.acme/book', 'acc://y.acme/book'], threshold: 1 },
    ]);
  });

  it('a seat that cannot be read exactly makes the book unreadable, never a shorter roster', async () => {
    expect(await pagesOf([{}])).toBeNull(); // neither a key nor a delegate
    expect(await pagesOf([{ publicKeyHash: 'abcd' }])).toBeNull(); // not 64 hex
    expect(await pagesOf([{ publicKeyHash: 'zz'.repeat(32) }])).toBeNull();
    expect(await pagesOf([{ publicKeyHash: 7 }])).toBeNull();
    expect(await pagesOf([{ delegate: 5 }])).toBeNull();
    expect(await pagesOf([{ publicKeyHash: 'ab'.repeat(32) }, {}])).toBeNull(); // one bad seat among good ones
  });
});

describe('the main chain is read once per evaluation, for the history AND for the entries', () => {
  it('one read serves both: the pages are not asked twice; a later evaluation (another meter) reads again', async () => {
    const { node, src, total } = world();
    for (let i = 0; i < 230; i++) node.write(A, [new Uint8Array([i & 255, i >> 8])], undefined, i === 0 ? {} : { block: node.lastBlock(A) });
    const t = await total(); // 231 records: 3 pages
    expect(t).toBe(231);
    const before = chainCalls(node);
    const m = meter();
    const h = await src.history(A, t, m);
    const e = await src.entries(A, t, m);
    expect(h!.types).toHaveLength(231);
    expect(h!.types[0]).toBe('createDataAccount');
    expect(h!.incomplete).toBe(false);
    expect(e).toHaveLength(230);
    expect(chainCalls(node) - before).toBe(3); // three pages, once
    expect(m.n).toBe(3 + 1); // + the one block (all 230 entries ran in it)
    await src.entries(A, t, meter());
    expect(chainCalls(node) - before).toBe(6); // a new evaluation reads the chain again: nothing outlives the evaluation but the immutable block times
  });

  it('a read that failed is not served as a success to the second reader of the same evaluation', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    const t = await total();
    node.historyShortRead = true;
    const m = meter();
    expect(await src.history(A, t, m)).toBeNull();
    expect(await src.entries(A, t, m)).toBeNull();
  });

  it('a chain that does not add up to the length asked (it grew or shrank) is not an answer', async () => {
    const { node, src, total } = world();
    node.write(A, accept, 1_800_000_000);
    const t = await total();
    node.write(A, revoke, 1_800_000_100); // the chain grew by one after the probe
    expect(await src.history(A, t, meter())).toBeNull();
    expect(await src.entries(A, t, meter())).toBeNull();
    expect(await src.history(A, t + 5, meter())).toBeNull();
  });
});
