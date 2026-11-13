/**
 * A FAKE Accumulate API v3 node for the reader tests, in the shapes the DAX-3A live run read from Kermit (answers recorded in
 * test/fixtures/live-dax3a-answers-trimmed.json): accounts with an authority set and an own MAIN chain whose records are the delivered
 * transactions (createDataAccount, writeData, updateAccountAuth, ...), each carrying `value.received`, the index of the MINOR BLOCK that
 * executed it; and minor blocks that carry the chain time. A data entry record has NO timestamp.
 *
 * It answers what src/binding/node-source.ts asks and records every query as `scope queryType`. It ALSO answers the `data` chain query the
 * way the real node does (two entries with identical bytes come back as the LATER transaction, so the first one would be dated by the
 * second one's block): a reader that fell back to the data chain would fail the tests that write identical entries. FICTIONAL accounts only.
 */
import type { ChainQuery } from '../../src/binding/node-source.js';

export interface FakeEntry { txId: string; elements: string[]; time?: number; block?: number }
export interface FakeRecord {
  type: string;
  /** the WriteData that this record is */
  entry?: FakeEntry;
  /** the executing minor block index; undefined = the record carries no `received` */
  block?: number;
  /** the delivery status the node reports; a real main chain holds `delivered` */
  status?: string;
  /** a record the node serves with the body missing (an unreadable record) */
  noBody?: boolean;
}
export interface FakeAccount {
  type: string;
  authorities: string[];
  /** the account's own main chain, from the creation */
  chain: FakeRecord[];
  entries: FakeEntry[];
  /** a key book: its page count; a key page: its key hashes and threshold */
  pageCount?: number;
  keys?: string[];
  /** the seats of a key page exactly as the node serves them (a key, a delegate book, both, or something odd); overrides `keys` */
  seats?: Array<Record<string, unknown>>;
  acceptThreshold?: number;
}

const FIRST_BLOCK = 16_000_000;
const AUTO_TIME_BASE = 1_799_000_000;

/** RFC 3339 UTC, whole seconds, as a minor block record states its time */
export const isoSeconds = (s: number): string => new Date(s * 1000).toISOString().replace('.000Z', 'Z');

export class FakeNode {
  readonly accounts = new Map<string, FakeAccount>();
  /** every query, as `scope kind` */
  calls: string[] = [];
  /** every query in full, in the order it arrived */
  log: Array<{ scope: string; query: any }> = [];
  /** accounts whose queries fail like a node outage (no JSON-RPC answer: a node-side error) */
  down = new Set<string>();
  /** the main chain cannot be read back (pages answer empty) while its length probe still works */
  historyShortRead = false;
  /** a delay on every answer, ms (to make concurrent reads overlap) */
  delayMs = 0;
  active = 0;
  maxActive = 0;
  /** the time of each minor block, Unix seconds (a block exists once an entry was executed in it) */
  readonly blockTimes = new Map<number, number>();
  /** replaces the answer to a block query (to serve a block that is not the block asked for, a time that is not a time, ...); undefined = the honest answer */
  blockOverride?: (scope: string, minor: number, honest: unknown) => unknown;
  private seq = 0;
  private nextBlock = FIRST_BLOCK;

  dataAccount(url: string, authorities: string[]): FakeAccount {
    const a: FakeAccount = { type: 'dataAccount', authorities, chain: [{ type: 'createDataAccount', block: this.newBlock(AUTO_TIME_BASE) }], entries: [] };
    this.accounts.set(url, a);
    return a;
  }

  identity(url: string, authorities: string[]): FakeAccount {
    const a: FakeAccount = { type: 'identity', authorities, chain: [{ type: 'createIdentity', block: this.newBlock(AUTO_TIME_BASE) }], entries: [] };
    this.accounts.set(url, a);
    return a;
  }

  /** a key book with pages (the quorum roster read; never an online verdict). `delegates` are delegate seats (book urls); `seats` replaces both with raw seats */
  book(url: string, pages: Array<{ keyHashes: string[]; threshold: number; delegates?: string[]; seats?: Array<Record<string, unknown>> }>): void {
    this.accounts.set(url, { type: 'keyBook', authorities: [], chain: [{ type: 'createKeyBook' }], entries: [], pageCount: pages.length });
    pages.forEach((p, i) => this.accounts.set(`${url}/${i + 1}`, { type: 'keyPage', authorities: [], chain: [{ type: 'createKeyPage' }], entries: [], keys: p.keyHashes, acceptThreshold: p.threshold, seats: p.seats ?? [...p.keyHashes.map((publicKeyHash) => ({ publicKeyHash })), ...(p.delegates ?? []).map((delegate) => ({ delegate }))] }));
  }

  private newBlock(time: number | undefined): number {
    const index = this.nextBlock++;
    this.blockTimes.set(index, time ?? AUTO_TIME_BASE + 7 * (index - FIRST_BLOCK));
    return index;
  }

  /**
   * A WriteData to a data account: one main-chain transaction, executed in a minor block.
   * `time` is the block's chain time in Unix seconds (omitted: a distinct, increasing time); `null` = the record carries no `received`
   * (nothing to ask the node a time for). `opts.block` puts the entry in a block that already exists (two entries, one block).
   */
  write(url: string, elements: Uint8Array[], time?: number | null, opts: { block?: number; status?: string } = {}): FakeEntry {
    const a = this.accounts.get(url);
    if (a === undefined) throw new Error('no account ' + url);
    const block = time === null ? undefined : opts.block ?? this.newBlock(time);
    const e: FakeEntry = {
      txId: `acc://${(++this.seq).toString(16).padStart(64, '0')}@${url.replace('acc://', '')}`,
      elements: elements.map((b) => Buffer.from(b).toString('hex')),
      ...(block === undefined ? {} : { block }),
      ...(time === null || time === undefined ? {} : { time }),
    };
    a.entries.push(e);
    a.chain.push({ type: 'writeData', entry: e, ...(block === undefined ? {} : { block }), ...(opts.status === undefined ? {} : { status: opts.status }) });
    return e;
  }

  /** the executing block of the newest entry of an account (to write a second entry into the same block) */
  lastBlock(url: string): number | undefined {
    return this.accounts.get(url)?.entries.at(-1)?.block;
  }

  /** an authority change: a main-chain transaction of the account */
  updateAuth(url: string, authorities: string[]): void {
    const a = this.accounts.get(url)!;
    a.authorities = authorities;
    a.chain.push({ type: 'updateAccountAuth', block: this.newBlock(undefined) });
  }

  private chainRecord(scope: string, r: FakeRecord, index: number): unknown {
    const id = r.entry?.txId ?? `acc://${(0xc0de00 + index).toString(16).padStart(64, '0')}@${scope.replace('acc://', '')}`;
    const body = r.noBody === true ? undefined : r.entry !== undefined ? { type: 'writeData', entry: { type: 'doubleHash', data: r.entry.elements } } : { type: r.type };
    return {
      recordType: 'chainEntry', name: 'main', type: 'transaction', index, entry: id.replace(/^acc:\/\//, '').split('@')[0],
      value: {
        recordType: 'message', id, message: { type: 'transaction', transaction: { header: { principal: scope }, ...(body === undefined ? {} : { body }) } },
        status: r.status ?? 'delivered', statusNo: 201, ...(r.block === undefined ? {} : { received: r.block }),
      },
    };
  }

  readonly query: ChainQuery = async (scope, q) => {
    this.calls.push(scope + (q ? ' ' + (q as { queryType?: string }).queryType : ''));
    this.log.push({ scope, query: q });
    this.active++;
    this.maxActive = Math.max(this.maxActive, this.active);
    try {
      if (this.delayMs > 0) await new Promise((r) => setTimeout(r, this.delayMs));
      if (this.down.has(scope)) throw new Error('connect ECONNREFUSED');
      const a = this.accounts.get(scope);
      if (a === undefined) throw Object.assign(new Error('record not found'), { rpc: { message: 'not found' } });
      const qq = q as { queryType?: string; name?: string; minor?: number; range?: { start: number; count: number } } | undefined;
      if (qq?.queryType === 'chain') {
        const r = qq.range!;
        const recs = this.historyShortRead && r.count > 1 ? [] : a.chain.slice(r.start, r.start + r.count).map((rec, i) => this.chainRecord(scope, rec, r.start + i));
        return { recordType: 'range', start: r.start, total: a.chain.length, records: recs };
      }
      if (qq?.queryType === 'block') {
        const time = this.blockTimes.get(qq.minor as number);
        if (time === undefined) throw Object.assign(new Error('record not found'), { rpc: { message: 'not found' } });
        const honest = { recordType: 'minorBlock', index: qq.minor, time: isoSeconds(time), source: 'acc://bvn-BVN3.acme' };
        return this.blockOverride === undefined ? honest : this.blockOverride(scope, qq.minor as number, honest);
      }
      if (qq?.queryType === 'data') {
        // the real data chain: an entry is resolved to a transaction through its entry hash, so identical entries are the LATER transaction
        const key = (e: FakeEntry) => e.elements.join('|');
        const later = new Map<string, FakeEntry>();
        for (const e of a.entries) later.set(key(e), e);
        const r = qq.range!;
        return {
          recordType: 'range', start: r.start, total: a.entries.length,
          records: a.entries.slice(r.start, r.start + r.count).map((e, i) => {
            const t = later.get(key(e))!;
            return { recordType: 'chainEntry', name: 'data', index: r.start + i, value: { id: t.txId, ...(t.block === undefined ? {} : { received: t.block }), message: { type: 'transaction', transaction: { body: { type: 'writeData', entry: { data: t.elements } } } } } };
          }),
        };
      }
      return { recordType: 'account', account: { type: a.type, authorities: a.authorities.map((url) => ({ url })), ...(a.pageCount === undefined ? {} : { pageCount: a.pageCount }), ...(a.keys === undefined ? {} : { keys: a.seats ?? a.keys.map((publicKeyHash) => ({ publicKeyHash })), acceptThreshold: a.acceptThreshold }) } };
    } finally {
      this.active--;
    }
  };
}

/**
 * A replay of REAL recorded Kermit answers (test/fixtures/live-dax3a-answers-trimmed.json). It answers a query only when an answer for the
 * same scope, queryType, chain name and minor index was recorded, serves the recorded `result` (the client unwraps JSON-RPC), cuts a recorded
 * chain page to the range asked, and throws like a node for everything else (the call is recorded either way).
 * `synthetic` holds answers the recording does NOT contain (keyed `scope queryType [chain name]`); a test that uses one says so.
 */
export function replayNode(doc: { answers: Array<{ method: string; params: { scope: string; query: { queryType: string; name?: string; minor?: number; range?: { start: number; count: number } } }; response: { result: any } }> }, synthetic: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const query: ChainQuery = async (scope, q) => {
    const qq = (q ?? { queryType: 'default' }) as { queryType: string; name?: string; minor?: number; range?: { start: number; count: number } };
    calls.push(`${scope} ${qq.queryType}${qq.minor === undefined ? '' : ' ' + qq.minor}`);
    const hit = doc.answers.find((a) => a.method === 'query' && a.params.scope === scope && a.params.query.queryType === qq.queryType && a.params.query.name === qq.name && a.params.query.minor === qq.minor);
    const fake = synthetic[`${scope} ${qq.queryType}${qq.name === undefined ? '' : ' ' + qq.name}`];
    if (hit === undefined && fake !== undefined) return JSON.parse(JSON.stringify(fake));
    if (hit === undefined) throw Object.assign(new Error('record not found'), { rpc: { message: 'no recorded answer' } });
    const res = JSON.parse(JSON.stringify(hit.response.result));
    if (qq.queryType === 'chain' && qq.range !== undefined) res.records = res.records.slice(qq.range.start, qq.range.start + qq.range.count);
    return res;
  };
  return { query, calls };
}
