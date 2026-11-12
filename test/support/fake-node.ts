/**
 * A FAKE Accumulate API v3 node for the reader tests: accounts with an authority set, an own main chain (transaction types from the
 * creation) and data entries with a chain time, answering the queries src/binding/node-source.ts asks, and recording every one.
 * FICTIONAL accounts only. It answers what the DAX-3A live driver read; it is not Kermit.
 */
import type { ChainQuery } from '../../src/binding/node-source.js';

export interface FakeEntry { txId: string; elements: string[]; time?: number }
export interface FakeAccount {
  type: string;
  authorities: string[];
  /** transaction types of the account's own main chain, from the creation */
  chain: string[];
  entries: FakeEntry[];
  /** a key book: its page count; a key page: its key hashes and threshold */
  pageCount?: number;
  keys?: string[];
  acceptThreshold?: number;
}

export class FakeNode {
  readonly accounts = new Map<string, FakeAccount>();
  /** every query, as `scope kind` */
  calls: string[] = [];
  /** accounts whose queries fail like a node outage (no JSON-RPC answer: a node-side error) */
  down = new Set<string>();
  /** the main chain cannot be read back (pages answer empty) while its length probe still works */
  historyShortRead = false;
  /** a delay on every answer, ms (to make concurrent reads overlap) */
  delayMs = 0;
  active = 0;
  maxActive = 0;
  private seq = 0;

  dataAccount(url: string, authorities: string[]): FakeAccount {
    const a: FakeAccount = { type: 'dataAccount', authorities, chain: ['createDataAccount'], entries: [] };
    this.accounts.set(url, a);
    return a;
  }

  identity(url: string, authorities: string[]): FakeAccount {
    const a: FakeAccount = { type: 'identity', authorities, chain: ['createIdentity'], entries: [] };
    this.accounts.set(url, a);
    return a;
  }

  /** a key book with pages (advisory reads only) */
  book(url: string, pages: Array<{ keyHashes: string[]; threshold: number }>): void {
    this.accounts.set(url, { type: 'keyBook', authorities: [], chain: ['createKeyBook'], entries: [], pageCount: pages.length });
    pages.forEach((p, i) => this.accounts.set(`${url}/${i + 1}`, { type: 'keyPage', authorities: [], chain: ['createKeyPage'], entries: [], keys: p.keyHashes, acceptThreshold: p.threshold }));
  }

  /** a WriteData to a data account: one data entry and one main-chain transaction */
  write(url: string, elements: Uint8Array[], time?: number): FakeEntry {
    const a = this.accounts.get(url);
    if (a === undefined) throw new Error('no account ' + url);
    const e: FakeEntry = { txId: `acc://${(++this.seq).toString(16).padStart(64, '0')}@${url.replace('acc://', '')}`, elements: elements.map((b) => Buffer.from(b).toString('hex')), ...(time === undefined ? {} : { time }) };
    a.entries.push(e);
    a.chain.push('writeData');
    return e;
  }

  /** an authority change: a main-chain transaction of the account */
  updateAuth(url: string, authorities: string[]): void {
    const a = this.accounts.get(url)!;
    a.authorities = authorities;
    a.chain.push('updateAccountAuth');
  }

  readonly query: ChainQuery = async (scope, q) => {
    this.calls.push(scope + (q ? ' ' + (q as { queryType?: string }).queryType : ''));
    this.active++;
    this.maxActive = Math.max(this.maxActive, this.active);
    try {
      if (this.delayMs > 0) await new Promise((r) => setTimeout(r, this.delayMs));
      if (this.down.has(scope)) throw new Error('connect ECONNREFUSED');
      const a = this.accounts.get(scope);
      if (a === undefined) throw Object.assign(new Error('record not found'), { rpc: { message: 'not found' } });
      const qq = q as { queryType?: string; name?: string; range?: { start: number; count: number } } | undefined;
      if (qq?.queryType === 'chain') {
        const r = qq.range!;
        const recs = this.historyShortRead && r.count > 1 ? [] : a.chain.slice(r.start, r.start + r.count);
        return { total: a.chain.length, records: recs.map((type) => ({ value: { message: { transaction: { body: { type } } } } })) };
      }
      if (qq?.queryType === 'data') {
        const r = qq.range!;
        return {
          total: a.entries.length,
          records: a.entries.slice(r.start, r.start + r.count).map((e) => ({
            value: { id: e.txId, ...(e.time === undefined ? {} : { lastBlockTime: e.time }), message: { transaction: { body: { entry: { data: e.elements } } } } },
          })),
        };
      }
      return { account: { type: a.type, authorities: a.authorities.map((url) => ({ url })), ...(a.pageCount === undefined ? {} : { pageCount: a.pageCount }), ...(a.keys === undefined ? {} : { keys: a.keys.map((publicKeyHash) => ({ publicKeyHash })), acceptThreshold: a.acceptThreshold }) } };
    } finally {
      this.active--;
    }
  };

}
