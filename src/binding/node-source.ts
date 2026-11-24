/**
 * The raw facts of Accumulate API v3 that the core reader needs (READER-MODEL-V2): the main-chain LENGTH of an account (one cheap
 * query), its authority set NOW, its own main chain FROM CREATION as transaction types, its data entries with chain time, and
 * the pages of a key book (the roster of the Console's quorum; NEVER read by an online Grant or registration verdict). Every method counts the node queries it makes in `Meter` so a caller can state its
 * load; none reads a key page unless it is `keyBookPages`; none makes a txid-miss query.
 *
 * The response shapes are those the DAX-3A live run read from Kermit (recorded answers: test/fixtures/live-dax3a-answers-trimmed.json,
 * replayed by test/binding-real-shapes.test.ts):
 *   account record     { recordType:"account", account: { type, authorities: [{url}], pageCount, keys: [{publicKeyHash}], acceptThreshold } }
 *   main chain query   { queryType: "chain", name: "main", range: { start, count, expand: true } }
 *                      -> { recordType:"range", total, records: [{ index, value: { id, status:"delivered", received: <minor block index>,
 *                           message: { type:"transaction", transaction: { body: { type, entry?: { data: [hex] } } } } } }] }
 *   block query        { queryType: "block", minor: <index> }  (scope: the account; the network resolves the partition)
 *                      -> { recordType:"minorBlock", index, time:"2026-11-12T20:47:34Z", source }
 *
 * Two live findings shape the entries (DAX-3A R5-1, R5-2), both decided in the core (block-time.ts, main-chain-entry.ts):
 *   - a data entry record has NO timestamp. `value.received` is the index of the minor block that executed it, and the chain time of
 *     the entry is that block's `time`, one-second resolution (two entries of one second compare equal; the library tie rule applies).
 *     `lastBlockTime` is a field of an ACCOUNT answer, never of an entry: nothing reads it as an entry time.
 *   - the entries of a data account are the WriteData transactions of its MAIN chain. The `data` chain query resolves an entry to a
 *     transaction through the entry hash, so byte-identical entries (accept, revoke, accept) collapse to the later transaction: this
 *     source never asks the data chain.
 * An entry has no `time` only when the node truly gave none (no executing block on the record, or a block record that is not the block
 * asked for / has no exact UTC time): the core then refuses a registry or acceptance entry by name (`entry_time_missing`). A block
 * QUERY that fails is a different fact: the whole account is unreadable, never an entry that merely lacks a time.
 *
 * Read cost: the main chain is read ONCE per evaluation for the history and the entries together (one query per 100 records), plus
 * one block query per distinct executing block. A block time is chain history that never changes, so it is remembered for the life of
 * the process (bounded; only an answered, exact time is remembered), and a new entry costs one block query.
 *
 * Fail closed: any surprise (a missing member, a non-hex element, a WriteData that was not delivered, a query error, a count that
 * does not add up) answers null, which the core turns into a named refusal. Nothing here is an allow.
 */
import type { AccountHistory, DataEntry, KeyPageInfo } from '../core/reader.js';
import { entryBlockIndex, minorBlockTime } from '../core/block-time.js';
import { mainChainEntryOf } from '../core/main-chain-entry.js';

export type ChainQuery = (scope: string, query?: unknown) => Promise<any>;
/** counts the node queries made on behalf of one caller (one evaluation) */
export interface Meter { n: number }

export interface NodeSource {
  /** the length of the account's main chain (null when unreadable): the cheap change detector */
  chainLength(account: string, m: Meter): Promise<number | null>;
  authorities(account: string, m: Meter): Promise<string[] | null>;
  /** the main chain from its creation; `total` is the length already read by chainLength (saves the probe) */
  history(account: string, total: number, m: Meter): Promise<AccountHistory | null>;
  /** the WriteData entries of the main chain, in chain order, each with the time of its executing block; `total` is the length already read by chainLength */
  entries(account: string, total: number, m: Meter): Promise<DataEntry[] | null>;
  keyBookPages(book: string, m: Meter): Promise<RosterPage[] | null>;
}

/**
 * A key page as the quorum roster needs it: the key hashes (64 lower-case hex) AND the delegate books of its seats (a seat may be a key, a
 * delegation to another key BOOK, or both: a delegate entry stands as its book url), and the accept threshold.
 */
/**
 * DAX-F167a: `rejectThreshold` is the page's STORED reject threshold, 0 when the page sets none (Accumulate then rejects at the accept threshold:
 * SignerWillVote, internal/core/execute/v2/block/transaction.go). The quorum needs it to know when a page's refusals deny (core DE-84).
 */
/** DAX-F167c: one key entry of a page in chain order: its key hash, its delegate book, or both (null where it holds none) */
export interface RosterEntry { keyHash: string | null; delegate: string | null }
/**
 * rejectThreshold and responseThreshold: as stored (0 = the page sets none); entries: the page's key entries in chain order (Accumulate counts a page per
 * entry: SignerWillVote over the page's signature set, one entry per key entry and delegation path), so an entry that holds a key AND a delegate is one
 */
export interface RosterPage extends KeyPageInfo { delegates: string[]; rejectThreshold: number; responseThreshold: number; entries: RosterEntry[] }

const PAGE = 100;
const MAX_RECORDS = 100_000;
/** how many block times are remembered (oldest dropped first) */
const MAX_BLOCK_TIMES = 20_000;

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

  // The main chain of one account at one length, read once per evaluation (the Meter is the evaluation): the history and the entries
  // are two views of the same records. A failed read is shared inside the evaluation (a failing node is not asked twice) and forgotten with it.
  const reads = new WeakMap<Meter, Map<string, Promise<any[] | null>>>();
  const mainChain = (account: string, total: number, m: Meter): Promise<any[] | null> => {
    let per = reads.get(m);
    if (per === undefined) reads.set(m, (per = new Map()));
    const key = `${account}#${total}`;
    let p = per.get(key);
    if (p === undefined) {
      p = (async (): Promise<any[] | null> => {
        if (!Number.isSafeInteger(total) || total < 0 || total > MAX_RECORDS) return null;
        const records: any[] = [];
        let start = 0;
        while (start < total) {
          const r = await ask(m, account, chainRange(start, PAGE));
          const recs = r?.records;
          if (!Array.isArray(recs) || recs.length === 0) return null; // the chain could not be read back: never an answer
          records.push(...recs);
          start += recs.length;
        }
        // read from index 0: complete. A chain longer than what was asked for, or a count that moved, is not an answer.
        return records.length === total ? records : null;
      })();
      per.set(key, p);
    }
    return p;
  };

  // The time of a minor block (chain history: immutable), by account and block index. Only an answered, exact time is remembered.
  const blockTimes = new Map<string, number>();
  const rememberBlockTime = (key: string, t: number): void => {
    if (blockTimes.size >= MAX_BLOCK_TIMES) blockTimes.delete(blockTimes.keys().next().value as string);
    blockTimes.set(key, t);
  };
  /** 'failed' = the node could not be asked; undefined = the node answered and gave no exact time of that block */
  const blockTime = async (account: string, minor: number, m: Meter): Promise<number | undefined | 'failed'> => {
    const key = `${account}#${minor}`;
    const have = blockTimes.get(key);
    if (have !== undefined) return have;
    const r = await ask(m, account, { queryType: 'block', minor });
    if (r === null) return 'failed';
    const t = minorBlockTime(r, minor);
    if (t !== undefined) rememberBlockTime(key, t);
    return t;
  };

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
      const records = await mainChain(account, total, m);
      if (records === null) return null;
      const types: string[] = [];
      for (const rec of records) {
        const t = rec?.value?.message?.transaction?.body?.type;
        if (typeof t !== 'string' || t.length === 0) return null;
        types.push(t);
      }
      return { types, incomplete: false };
    },

    async entries(account, total, m) {
      const records = await mainChain(account, total, m);
      if (records === null) return null;
      const found: Array<{ txId: string; elements: Uint8Array[]; minor: number | undefined }> = [];
      for (const rec of records) {
        const e = mainChainEntryOf(rec);
        if (e.kind === 'other') continue;
        if (e.kind === 'malformed') return null;
        // a WriteData that is on the chain but was not delivered is not an entry, and is not skipped either: the account cannot be read exactly
        if (rec?.value?.status !== 'delivered') return null;
        found.push({ txId: e.txId, elements: e.elements, minor: entryBlockIndex(rec) });
      }
      // one block query per distinct executing block (the read cache bounds how many run at once)
      const distinct = [...new Set(found.map((f) => f.minor).filter((x): x is number => x !== undefined))];
      const times = new Map<number, number | undefined | 'failed'>();
      await Promise.all(distinct.map(async (minor) => { times.set(minor, await blockTime(account, minor, m)); }));
      const out: DataEntry[] = [];
      for (const f of found) {
        const t = f.minor === undefined ? undefined : times.get(f.minor);
        if (t === 'failed') return null;
        out.push({ txId: f.txId, ...(t === undefined ? {} : { time: t }), elements: f.elements });
      }
      return out;
    },

    async keyBookPages(book, m) {
      const b = await ask(m, book);
      if (!b?.account || b.account.type !== 'keyBook') return null;
      const count = Number(b.account.pageCount);
      if (!Number.isSafeInteger(count) || count < 1 || count > 1000) return null;
      const pages: RosterPage[] = [];
      for (let i = 1; i <= count; i++) {
        const url = `${book}/${i}`;
        const p = await ask(m, url);
        const keys = p?.account?.keys;
        const threshold = Number(p?.account?.acceptThreshold);
        if (!p?.account || !Array.isArray(keys) || !Number.isSafeInteger(threshold) || threshold < 1) return null;
        // DAX-F167a: the reject threshold as stored; the node omits it when the page sets none (0). A value that is not a whole number, or one above
        // the page's entries (Accumulate caps it there), makes the book unreadable: never a guessed threshold.
        const rawReject = p.account.rejectThreshold;
        const rejectThreshold = rawReject === undefined || rawReject === null ? 0 : Number(rawReject);
        if (!Number.isSafeInteger(rejectThreshold) || rejectThreshold < 0 || rejectThreshold > keys.length) return null;
        // DAX-F167c: the response threshold as stored, read exactly as the reject threshold (absent = 0, the page sets none; Accumulate caps it at the
        // entries): SignerWillVote decides nothing on a page before its votes reach it
        const rawResponse = p.account.responseThreshold;
        const responseThreshold = rawResponse === undefined || rawResponse === null ? 0 : Number(rawResponse);
        if (!Number.isSafeInteger(responseThreshold) || responseThreshold < 0 || responseThreshold > keys.length) return null;
        // every seat is read exactly: a seat with a key hash that is not 64 hex, a delegate that is not text, or neither a key nor a delegate
        // makes the book unreadable. A roster that silently lost a seat would be SHORTER than the chain's, and shorter is never safe to answer.
        const keyHashes: string[] = [];
        const delegates: string[] = [];
        const entries: RosterEntry[] = [];
        for (const k of keys) {
          const h = k?.publicKeyHash;
          const d = k?.delegate;
          const hasKey = h !== undefined && h !== null && h !== '';
          const hasDelegate = d !== undefined && d !== null && d !== '';
          if (!hasKey && !hasDelegate) return null;
          if (hasKey) {
            if (typeof h !== 'string' || !/^[0-9a-fA-F]{64}$/.test(h)) return null;
            keyHashes.push(h.toLowerCase());
          }
          if (hasDelegate) {
            if (typeof d !== 'string') return null;
            delegates.push(d);
          }
          entries.push({ keyHash: hasKey ? keyHashes[keyHashes.length - 1]! : null, delegate: hasDelegate ? delegates[delegates.length - 1]! : null });
        }
        // DAX-F167c: a key hash or a delegate twice on one page is not a page the chain builds (UpdateKeyPage refuses a duplicate entry) and only one of
        // the two could ever be voted on (EntryByKeyHash / EntryByDelegate find one): the book is unreadable, never a guessed count
        if (new Set(keyHashes).size !== keyHashes.length || new Set(delegates).size !== delegates.length) return null;
        pages.push({ url, keyHashes, delegates, threshold, rejectThreshold, responseThreshold, entries });
      }
      return pages;
    },
  };
}
