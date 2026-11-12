/**
 * The raw facts of Accumulate API v3 that the core reader needs (READER-MODEL-V2): the main-chain LENGTH of an account (one cheap
 * query), its authority set NOW, its own main chain FROM CREATION as transaction types, its data entries with chain time, and
 * (advisory only) the pages of a key book. Every method counts the node queries it makes in `Meter` so a caller can state its
 * load; none reads a key page unless it is the advisory `keyBookPages`; none makes a txid-miss query.
 *
 * The response shapes are those the DAX-3A live driver read from Kermit (transaction-controls scenarios/spikes/DAX3A.ts):
 *   account record     { account: { type, authorities: [{url, disabled}], pageCount, keys: [{publicKeyHash}], acceptThreshold } }
 *   main chain query   { queryType: "chain", name: "main", range: { start, count, expand: true } }
 *                      -> { total, records: [{ value: { message: { transaction: { body: { type } } } } }] }
 *   data query         { queryType: "data", range: { start, count, expand: true } }
 *                      -> { total, records: [{ value: { id, message: { transaction: { body: { entry: { data: [hex] } } } } } }] }
 * NOT proven against Kermit by the signer's own tests (no chain contact in DAX-4S; the live smoke is the proof). The one fact the
 * model leaves OPEN until DAX-3-A15 is settled live is WHICH FIELD of an entry record carries its chain time: `entryTimeOf` is the
 * single place that reads it. When it finds none the entry has no `time`, and the core refuses a registry or acceptance entry
 * without one (`entry_time_missing`): a Grant seat refuses, it never guesses a time.
 *
 * Fail closed: any surprise (a missing member, a non-hex element, a query error, a count that does not add up) answers null, which
 * the core turns into a named refusal. Nothing here is an allow.
 */
import type { AccountHistory, DataEntry, KeyPageInfo } from '../core/reader.js';

export type ChainQuery = (scope: string, query?: unknown) => Promise<any>;
/** counts the node queries made on behalf of one caller */
export interface Meter { n: number }

export interface NodeSource {
  /** the length of the account's main chain (null when unreadable): the cheap change detector */
  chainLength(account: string, m: Meter): Promise<number | null>;
  authorities(account: string, m: Meter): Promise<string[] | null>;
  /** the main chain from its creation; `total` is the length already read by chainLength (saves the probe) */
  history(account: string, total: number, m: Meter): Promise<AccountHistory | null>;
  entries(account: string, m: Meter): Promise<DataEntry[] | null>;
  keyBookPages(book: string, m: Meter): Promise<KeyPageInfo[] | null>;
}

const PAGE = 100;
const MAX_RECORDS = 100_000;

function hexBytes(h: unknown): Uint8Array | null {
  if (typeof h !== 'string') return null;
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  return new Uint8Array(Buffer.from(s, 'hex'));
}

/**
 * The chain time of a data-entry record, Unix seconds, or undefined. UNSETTLED until DAX-3-A15 shows the live record: this reads
 * `value.lastBlockTime` (RFC 3339 text or seconds) and nothing else, and reads NOTHING that the producer of the entry controls.
 */
export function entryTimeOf(rec: any): number | undefined {
  const t = rec?.value?.lastBlockTime;
  if (typeof t === 'number' && Number.isSafeInteger(t) && t >= 0) return t;
  if (typeof t === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(t)) {
    const ms = Date.parse(t);
    if (Number.isFinite(ms) && ms >= 0) return Math.floor(ms / 1000);
  }
  return undefined;
}

export function createNodeSource(query: ChainQuery): NodeSource {
  const ask = async (m: Meter, scope: string, q?: unknown): Promise<any | null> => {
    m.n++;
    try {
      const r = await query(scope, q);
      return r === undefined || r === null ? null : r;
    } catch {
      return null;
    }
  };
  const chainRange = (start: number, count: number) => ({ queryType: 'chain', name: 'main', range: { start, count, expand: true } });
  return {
    async chainLength(account, m) {
      const r = await ask(m, account, chainRange(0, 1));
      const total = Number(r?.total);
      return r !== null && Number.isSafeInteger(total) && total >= 0 ? total : null;
    },

    async authorities(account, m) {
      const r = await ask(m, account);
      const list = r?.account?.authorities;
      if (!r?.account || (list !== undefined && !Array.isArray(list))) return null;
      return (list ?? []).filter((a: any) => a?.disabled !== true).map((a: any) => String(a?.url ?? '')).filter((u: string) => u.length > 0);
    },

    async history(account, total, m) {
      if (!Number.isSafeInteger(total) || total < 0 || total > MAX_RECORDS) return null;
      const types: string[] = [];
      let start = 0;
      while (start < total) {
        const r = await ask(m, account, chainRange(start, PAGE));
        const recs = r?.records;
        if (!Array.isArray(recs) || recs.length === 0) return null; // the chain could not be read back: never an answer
        for (const rec of recs) {
          const t = rec?.value?.message?.transaction?.body?.type;
          if (typeof t !== 'string' || t.length === 0) return null;
          types.push(t);
        }
        start += recs.length;
      }
      // read from index 0: complete. A chain longer than what was read, or a count that moved, is not an answer.
      return types.length === total ? { types, incomplete: false } : null;
    },

    async entries(account, m) {
      const out: DataEntry[] = [];
      let start = 0;
      for (;;) {
        const r = await ask(m, account, { queryType: 'data', range: { start, count: PAGE, expand: true } });
        const recs = r?.records;
        if (!Array.isArray(recs)) return null;
        for (const rec of recs) {
          const data = rec?.value?.message?.transaction?.body?.entry?.data;
          if (!Array.isArray(data)) return null;
          const elements: Uint8Array[] = [];
          for (const h of data) {
            const b = hexBytes(h);
            if (b === null) return null;
            elements.push(b);
          }
          const time = entryTimeOf(rec);
          out.push({ txId: String(rec?.value?.id ?? ''), ...(time === undefined ? {} : { time }), elements });
        }
        start += recs.length;
        const total = Number(r.total);
        if (recs.length === 0 || (Number.isSafeInteger(total) && start >= total) || recs.length < PAGE) {
          // when the node states a total it must agree with what was read: a short read is not the whole account
          if (Number.isSafeInteger(total) && total !== out.length) return null;
          return out;
        }
        if (out.length > MAX_RECORDS) return null;
      }
    },

    async keyBookPages(book, m) {
      const b = await ask(m, book);
      if (!b?.account || b.account.type !== 'keyBook') return null;
      const count = Number(b.account.pageCount);
      if (!Number.isSafeInteger(count) || count < 1 || count > 1000) return null;
      const pages: KeyPageInfo[] = [];
      for (let i = 1; i <= count; i++) {
        const url = `${book}/${i}`;
        const p = await ask(m, url);
        const keys = p?.account?.keys;
        const threshold = Number(p?.account?.acceptThreshold);
        if (!p?.account || !Array.isArray(keys) || !Number.isSafeInteger(threshold) || threshold < 1) return null;
        const keyHashes: string[] = [];
        for (const k of keys) if (typeof k?.publicKeyHash === 'string' && k.publicKeyHash.length > 0) keyHashes.push(k.publicKeyHash.toLowerCase());
        pages.push({ url, keyHashes, threshold });
      }
      return pages;
    },
  };
}
