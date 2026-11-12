/**
 * The core's pluggable `AccumulateReader` over the signer's own Accumulate query (`RawAccumulateClient.query`, API v3).
 *
 * The response shapes are the ones the DAX-3A live spike read from Kermit (transaction-controls scenarios/spikes/DAX3A.ts,
 * kermitReader): an account record has `account.authorities[{url, disabled}]`; a key book has `account.type == "keyBook"` and
 * `account.pageCount`; a key page has `account.keys[{publicKeyHash}]` and `account.acceptThreshold`; a data account answers
 * `{queryType: "data", range: {start, count, expand: true}}` with `records[]`, each `value.id` and
 * `value.message.transaction.body.entry.data` (hex elements). This file adds paging (the spike read the first 100 entries).
 *
 * Fail closed: ANY surprise (a missing member, a record without entry data, a non-hex element, a query error, a count that does
 * not add up) answers `null`, and the core turns `null` into `authority_unreadable`, `lineage_unreadable` or
 * `registry_unreadable`, which deny. Nothing here is an allow. NOT proven against Kermit by the signer's own tests (no chain
 * contact in DAX-4S); the live smoke (DAX-4-A6) is the proof.
 */
import type { AccumulateReader, DataEntry, KeyPageInfo } from '../core/reader.js';

export type ChainQuery = (scope: string, query?: unknown) => Promise<any>;

const PAGE = 100;
const MAX_ENTRIES = 100_000;

function hexBytes(h: unknown): Uint8Array | null {
  if (typeof h !== 'string') return null;
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  return new Uint8Array(Buffer.from(s, 'hex'));
}

export function createChainReader(query: ChainQuery): AccumulateReader {
  const safe = async (scope: string, q?: unknown): Promise<any | null> => {
    try {
      const r = await query(scope, q);
      return r === undefined || r === null ? null : r;
    } catch {
      return null;
    }
  };
  return {
    async authorities(account: string): Promise<string[] | null> {
      const r = await safe(account);
      const list = r?.account?.authorities;
      if (!r?.account || (list !== undefined && !Array.isArray(list))) return null;
      return (list ?? []).filter((a: any) => a?.disabled !== true).map((a: any) => String(a?.url ?? '')).filter((u: string) => u.length > 0);
    },

    async keyBookPages(book: string): Promise<KeyPageInfo[] | null> {
      const b = await safe(book);
      if (!b?.account || b.account.type !== 'keyBook') return null;
      const count = Number(b.account.pageCount);
      if (!Number.isSafeInteger(count) || count < 1 || count > 1000) return null;
      const pages: KeyPageInfo[] = [];
      for (let i = 1; i <= count; i++) {
        const url = `${book}/${i}`;
        const p = await safe(url);
        const keys = p?.account?.keys;
        const threshold = Number(p?.account?.acceptThreshold);
        if (!p?.account || !Array.isArray(keys) || !Number.isSafeInteger(threshold) || threshold < 1) return null;
        const keyHashes: string[] = [];
        for (const k of keys) {
          // a delegated entry carries no key hash: it is not a key of this page for any envelope
          if (typeof k?.publicKeyHash === 'string' && k.publicKeyHash.length > 0) keyHashes.push(k.publicKeyHash.toLowerCase());
        }
        pages.push({ url, keyHashes, threshold });
      }
      return pages;
    },

    async dataEntries(account: string): Promise<DataEntry[] | null> {
      const out: DataEntry[] = [];
      let start = 0;
      for (;;) {
        const r = await safe(account, { queryType: 'data', range: { start, count: PAGE, expand: true } });
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
          out.push({ txId: String(rec?.value?.id ?? ''), elements });
        }
        start += recs.length;
        const total = Number(r.total);
        if (recs.length === 0 || (Number.isSafeInteger(total) && start >= total) || recs.length < PAGE) {
          // when the node states a total it must agree with what was read: a short read is not the whole account
          if (Number.isSafeInteger(total) && total !== out.length) return null;
          return out;
        }
        if (out.length > MAX_ENTRIES) return null;
      }
    },
  };
}
