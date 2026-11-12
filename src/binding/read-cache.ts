/**
 * Read amplification control for the reader (READER-MODEL-V2, last section): the online model reads three accounts per decision
 * evaluation and the signer evaluates a pending item every poll, so the node would otherwise see 10 to 30 queries per item per
 * poll. The rules, each enforced here and each tested (test/binding-read-cache.test.ts):
 *   1. cache successful reads only, keyed by account AND its main-chain length: one cheap chain-length query per account per
 *      evaluation says whether anything changed; the entries, the authority set and the history are re-read only when it did;
 *   2. a hard TTL (at most 30 seconds) on every cached fact even when the length is unchanged, so a revocation or a supersede is
 *      visible within that bound (the bound is part of the facts-age record the decision journal carries);
 *   3. a failure, an unreadable answer and an incomplete history are never cached and never served from the cache;
 *   4. bounded concurrency on the node and exponential back-off after a node-side error (a failing node is not asked again until
 *      the back-off has passed: a read inside it fails closed at once, no retry storm);
 *   5. one in-flight read per account fact (concurrent evaluations coalesce);
 *   6. counters per evaluation (queries, hits, misses, invalidations, coalesced, the age of the oldest fact used) and totals;
 *   7. no txid-miss query: nothing here asks for a transaction by id.
 * The key-book pages (advisory, never a gate) have no cheap change detector, so they are cached by the TTL alone.
 */
import type { AccountHistory, AccumulateReader, DataEntry, KeyPageInfo } from '../core/reader.js';
import { isDefinitiveNotFound } from '../accumulate/raw-client.js';
import { createNodeSource, type ChainQuery, type Meter, type NodeSource } from './node-source.js';

export const MAX_TTL_MS = 30_000;

export interface MetricsSink { inc(name: string, by?: number): void }

export interface ReadCacheOptions {
  /** hard TTL of every cached fact, at most 30 000 ms (default 30 000) */
  ttlMs?: number;
  /** most node queries in flight at once (default 4) */
  maxConcurrent?: number;
  /** back-off after a node-side error: base and ceiling in ms (default 500 and 30 000) */
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  now?: () => number;
  metrics?: MetricsSink;
}

export interface EvaluationStats {
  /** node queries made on behalf of this evaluation (a read coalesced onto another's in-flight read counts on that one) */
  queries: number;
  cacheHits: number;
  cacheMisses: number;
  /** cached facts dropped because the chain moved or the TTL passed */
  invalidations: number;
  coalesced: number;
  /** a result that was NOT cached because it was incomplete */
  notCached: number;
  /** the age of the oldest cached fact this evaluation served, ms (0 when everything was read fresh) */
  maxFactAgeMs: number;
  ttlMs: number;
}

export interface CountedReader extends AccumulateReader {
  stats(): EvaluationStats;
}

interface Fact<T> { v: T; at: number }
interface Entry {
  total: number;
  authorities?: Fact<string[]>;
  history?: Fact<AccountHistory>;
  entries?: Fact<DataEntry[]>;
}
type FactKey = 'authorities' | 'history' | 'entries';

/** a node-side error (no answer, a 5xx, 429), not a definitive answer of the node (a JSON-RPC error, a not-found) */
function nodeSide(e: unknown): boolean {
  const x = e as { response?: { status?: number }; rpc?: unknown; message?: string };
  const status = x?.response?.status;
  if (typeof status === 'number') return status >= 500 || status === 429;
  if (x?.rpc !== undefined) return false;
  return !isDefinitiveNotFound(String(x?.message ?? ''));
}

export interface ReadCacheTotals { nodeQueries: number; cacheHits: number; cacheMisses: number; invalidations: number; coalesced: number; backoffRefusals: number }

export class ReadCache {
  private readonly source: NodeSource;
  private readonly entries = new Map<string, Entry>();
  private readonly books = new Map<string, Fact<KeyPageInfo[]>>();
  private readonly inflight = new Map<string, Promise<unknown>>();
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly totalsData: ReadCacheTotals = { nodeQueries: 0, cacheHits: 0, cacheMisses: 0, invalidations: 0, coalesced: 0, backoffRefusals: 0 };
  private active = 0;
  private readonly waiters: Array<() => void> = [];
  private failures = 0;
  private blockedUntil = 0;
  private readonly maxConcurrent: number;
  private readonly backoffBase: number;
  private readonly backoffMax: number;

  constructor(query: ChainQuery, private readonly opts: ReadCacheOptions = {}) {
    const ttl = opts.ttlMs ?? MAX_TTL_MS;
    if (!Number.isFinite(ttl) || ttl < 1 || ttl > MAX_TTL_MS) throw new Error(`read cache: ttlMs must be 1 to ${MAX_TTL_MS} (a revocation must be visible within 30 seconds), got ${ttl}`);
    this.ttlMs = ttl;
    this.now = opts.now ?? Date.now;
    this.maxConcurrent = opts.maxConcurrent ?? 4;
    if (!Number.isSafeInteger(this.maxConcurrent) || this.maxConcurrent < 1) throw new Error('read cache: maxConcurrent must be a positive integer');
    this.backoffBase = opts.backoffBaseMs ?? 500;
    this.backoffMax = opts.backoffMaxMs ?? 30_000;
    this.source = createNodeSource((scope, q) => this.guarded(query, scope, q));
  }

  totals(): ReadCacheTotals {
    return { ...this.totalsData };
  }

  /** the node query: bounded concurrency, and a node-side error blocks the node for an exponentially growing time */
  private async guarded(query: ChainQuery, scope: string, q?: unknown): Promise<any> {
    if (this.now() < this.blockedUntil) {
      this.totalsData.backoffRefusals++;
      this.opts.metrics?.inc('reader_backoff_refusals_total');
      throw new Error('node back-off: not asked again until the back-off has passed');
    }
    if (this.active >= this.maxConcurrent) await new Promise<void>((res) => this.waiters.push(res));
    else this.active++;
    try {
      const r = await query(scope, q);
      this.failures = 0;
      return r;
    } catch (e) {
      if (nodeSide(e)) {
        this.failures++;
        this.blockedUntil = this.now() + Math.min(this.backoffMax, this.backoffBase * 2 ** (this.failures - 1));
      }
      throw e;
    } finally {
      const next = this.waiters.shift();
      if (next) next();
      else this.active--;
    }
  }

  private coalesce<T>(key: string, load: () => Promise<T>, st: EvaluationStats): Promise<T> {
    const running = this.inflight.get(key) as Promise<T> | undefined;
    if (running !== undefined) {
      st.coalesced++;
      this.totalsData.coalesced++;
      this.opts.metrics?.inc('reader_coalesced_total');
      return running;
    }
    const p = load().finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  /** One decision evaluation (or one relay request): its own counters, the shared cache. */
  evaluation(): CountedReader {
    const st: EvaluationStats = { queries: 0, cacheHits: 0, cacheMisses: 0, invalidations: 0, coalesced: 0, notCached: 0, maxFactAgeMs: 0, ttlMs: this.ttlMs };
    const m: Meter = { n: 0 };
    let reported = 0;
    const flush = (): void => {
      const d = m.n - reported;
      reported = m.n;
      st.queries = m.n;
      if (d > 0) {
        this.totalsData.nodeQueries += d;
        this.opts.metrics?.inc('reader_node_queries_total', d);
      }
    };
    const hit = (age: number): void => {
      st.cacheHits++;
      st.maxFactAgeMs = Math.max(st.maxFactAgeMs, age);
      this.totalsData.cacheHits++;
      this.opts.metrics?.inc('reader_cache_hits_total');
    };
    const miss = (): void => {
      st.cacheMisses++;
      this.totalsData.cacheMisses++;
      this.opts.metrics?.inc('reader_cache_misses_total');
    };
    const drop = (n: number): void => {
      if (n === 0) return;
      st.invalidations += n;
      this.totalsData.invalidations += n;
      this.opts.metrics?.inc('reader_cache_invalidations_total', n);
    };

    // One chain-length query per account per evaluation: it decides whether the cached facts still stand.
    const validated = new Map<string, Promise<Entry | null>>();
    const validate = (account: string): Promise<Entry | null> => {
      const have = validated.get(account);
      if (have !== undefined) return have;
      const p = (async (): Promise<Entry | null> => {
        let e = this.entries.get(account);
        if (e !== undefined) {
          const t = this.now();
          let dropped = 0;
          for (const k of ['authorities', 'history', 'entries'] as const) {
            const f = e[k];
            if (f !== undefined && t - f.at >= this.ttlMs) {
              delete e[k];
              dropped++;
            }
          }
          drop(dropped);
        }
        const total = await this.coalesce(`count:${account}`, () => this.source.chainLength(account, m), st);
        flush();
        if (total === null) {
          // never serve what cannot be checked, never cache the failure
          if (this.entries.delete(account)) drop(1);
          return null;
        }
        if (e !== undefined && e.total !== total) {
          drop(['authorities', 'history', 'entries'].filter((k) => e![k as FactKey] !== undefined).length);
          this.entries.delete(account);
          e = undefined;
        }
        if (e === undefined) {
          e = { total };
          this.entries.set(account, e);
        }
        return e;
      })();
      validated.set(account, p);
      return p;
    };

    const fact = async <T>(account: string, key: FactKey, load: (e: Entry) => Promise<T | null>, cacheable: (v: T) => boolean): Promise<T | null> => {
      const e = await validate(account);
      if (e === null) return null;
      const have = e[key] as Fact<T> | undefined;
      if (have !== undefined) {
        hit(this.now() - have.at);
        return have.v;
      }
      miss();
      const v = await this.coalesce(`${key}:${account}:${e.total}`, () => load(e), st);
      flush();
      if (v === null) return null;
      if (cacheable(v)) (e as unknown as Record<string, Fact<T>>)[key] = { v, at: this.now() };
      else {
        st.notCached++;
      }
      return v;
    };

    return {
      authorities: (account) => fact<string[]>(account, 'authorities', () => this.source.authorities(account, m), () => true),
      accountHistory: (account) => fact<AccountHistory>(account, 'history', (e) => this.source.history(account, e.total, m), (h) => !h.incomplete),
      dataEntries: (account) => fact<DataEntry[]>(account, 'entries', () => this.source.entries(account, m), () => true),
      keyBookPages: async (book) => {
        const cached = this.books.get(book);
        const t = this.now();
        if (cached !== undefined && t - cached.at < this.ttlMs) {
          hit(t - cached.at);
          return cached.v;
        }
        miss();
        const v = await this.coalesce(`book:${book}`, () => this.source.keyBookPages(book, m), st);
        flush();
        if (v === null) {
          this.books.delete(book);
          return null;
        }
        this.books.set(book, { v, at: this.now() });
        return v;
      },
      stats: () => ({ ...st }),
    };
  }
}
