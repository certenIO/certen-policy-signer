/**
 * Persistence: SigningRequest + Receipt, keyed by WORK KEY. Interface + in-memory and file-backed impls.
 *
 * The work key is the transaction hash, except for a vote on one delegation path in wrapper mode, where
 * it is `txHash:<16 hex>` (src/delegation/path.ts `workKey`). Every existing mode uses the bare hash, so
 * for them nothing here changed. A record written before work keys existed has no `workKey` and is
 * keyed by its `txHash`, which is exactly the key it was stored under.
 */
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { PolicyRequest, Receipt, RequestStatus, SigningRequest } from '../types.js';

export const TERMINAL: RequestStatus[] = ['signed', 'rejected', 'expired'];

/** The key a record lives under: its `workKey`, or its `txHash` when it predates work keys. */
export function keyOf(r: { workKey?: string; txHash: string }): string {
  return r.workKey ?? r.txHash;
}

export interface Store {
  /** `key` is a work key: the tx hash, or `txHash:<16 hex>` for one delegation path. */
  get(key: string): Promise<SigningRequest | undefined>;
  create(req: SigningRequest): Promise<void>;
  update(key: string, patch: Partial<SigningRequest>): Promise<SigningRequest>;
  /**
   * APPENDS a receipt: nothing replaces or removes one (DAX-4S, DE-48). The store stamps `seq`, store-wide and contiguous from 1,
   * and `recordedAt`; a drop or a reorder shows as a gap, and the Console chains the receipts through its decision log.
   */
  saveReceipt(r: Receipt): Promise<void>;
  /** The LATEST receipt of a unit of work (what every reader has always had). */
  getReceipt(key: string): Promise<Receipt | undefined>;
  /** Every receipt of a unit of work, oldest first. */
  getReceipts(key: string): Promise<Receipt[]>;
  /**
   * The latest PolicyRequest built for a unit of work (Phase 6.4 `/relay/pending/:hash`). `key` defaults
   * to the request's tx hash; a wrapper path's request lives under its work key, so the tx-hash route
   * never returns one wrapper's question as another's.
   */
  savePolicyRequest(r: PolicyRequest, key?: string): Promise<void>;
  getPolicyRequest(key: string): Promise<PolicyRequest | undefined>;
  listNonTerminal(): Promise<SigningRequest[]>;
  /**
   * Most-recently-updated requests, with their receipts — the operator's audit view.
   *
   * Returns receipts alongside requests deliberately: the request says what happened, the receipt says
   * WHY (the policy engine's reason and evidence). Separating them would make the common question —
   * "why did we sign that?" — an N+1 walk.
   *
   * `statuses`, when given, filters BEFORE the limit is applied — so asking for the 50 most recent
   * `awaiting_policy` rows returns 50 of them, not whatever share of the 50 most recent rows happens to be
   * waiting. That distinction is the whole point of the filter: a queue UI on a busy signer would otherwise
   * show an empty work list because the recent window is full of settled transactions.
   */
  listRecent(limit?: number, statuses?: RequestStatus[]): Promise<Array<{ request: SigningRequest; receipt?: Receipt }>>;
  /** Best-effort single-flight lock, per work key. Returns false if already locked. */
  tryLock(key: string): boolean;
  unlock(key: string): void;
}

export class MemoryStore implements Store {
  protected reqs = new Map<string, SigningRequest>();
  /** Every receipt, in the order appended: `seq` is the index plus one. Never edited, never shortened. */
  protected receiptLog: Receipt[] = [];
  protected receipts = new Map<string, Receipt>();
  protected policyRequests = new Map<string, PolicyRequest>();
  private locks = new Set<string>();

  async get(key: string) { return this.reqs.get(key); }
  async create(req: SigningRequest) {
    const key = keyOf(req);
    if (this.reqs.has(key)) throw new Error(`duplicate signing_request ${key}`);
    this.reqs.set(key, { ...req });
    await this.persist();
  }
  async update(key: string, patch: Partial<SigningRequest>) {
    const cur = this.reqs.get(key);
    if (!cur) throw new Error(`no signing_request ${key}`);
    // The key is the row's identity: a patch must not move it under another key.
    const next = { ...cur, ...patch, txHash: cur.txHash, workKey: cur.workKey, updatedAt: Date.now() };
    if (next.workKey === undefined) delete next.workKey;
    this.reqs.set(key, next);
    await this.persist();
    return next;
  }
  async saveReceipt(r: Receipt) {
    const rec: Receipt = { ...r, seq: this.receiptLog.length + 1, recordedAt: Date.now() };
    this.receiptLog.push(rec);
    this.receipts.set(keyOf(rec), rec);
    try {
      await this.persist();
    } catch (e) {
      // An append that could not be made durable is not an append: roll the in-memory log back so a retry takes the same seq.
      this.receiptLog.pop();
      const prior = [...this.receiptLog].reverse().find((x) => keyOf(x) === keyOf(rec));
      if (prior) this.receipts.set(keyOf(rec), prior); else this.receipts.delete(keyOf(rec));
      throw e;
    }
  }
  async getReceipt(key: string) { return this.receipts.get(key); }
  async getReceipts(key: string) { return this.receiptLog.filter((x) => keyOf(x) === key); }
  async savePolicyRequest(r: PolicyRequest, key = r.txHash) { this.policyRequests.set(key, structuredClone(r)); await this.persist(); }
  async getPolicyRequest(key: string) { return this.policyRequests.get(key); }
  async listNonTerminal() {
    return [...this.reqs.values()].filter((r) => !TERMINAL.includes(r.status));
  }
  async listRecent(limit = 50, statuses?: RequestStatus[]) {
    const wanted = statuses?.length ? new Set(statuses) : undefined;
    return [...this.reqs.values()]
      .filter((r) => !wanted || wanted.has(r.status))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, Math.max(0, limit))
      .map((request) => ({ request, receipt: this.receipts.get(keyOf(request)) }));
  }
  tryLock(key: string) {
    if (this.locks.has(key)) return false;
    this.locks.add(key);
    return true;
  }
  unlock(key: string) { this.locks.delete(key); }

  /** No-op for the in-memory store; FileStore overrides it. */
  protected async persist(): Promise<void> {}
}

/**
 * FileStore — the same state, durable across restarts.
 *
 * Without this the wallet forgets, on every restart, which transactions it has already voted on and every
 * receipt it issued. The receipts ARE the audit trail ("we signed X because the policy engine said Y"), so
 * losing them is not a cache miss, it is losing the evidence. It also means a restart re-runs policy on
 * transactions already decided.
 *
 * The whole state is a few KB (one row per pending tx), so each mutation rewrites the file atomically:
 * write a temp file, fsync it, rename over the target. A crash mid-write therefore leaves either the old
 * file or the new one, never a half-written one. Writes are serialized through a promise chain so two
 * concurrent mutations cannot interleave and lose an update.
 */
export class FileStore extends MemoryStore {
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly path: string) {
    super();
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) this.load();
  }

  private load() {
    try {
      const raw = JSON.parse(readFileSync(this.path, 'utf8')) as {
        requests?: SigningRequest[]; receipts?: Receipt[]; policyRequests?: PolicyRequest[];
        policyRequestsByKey?: Array<[string, PolicyRequest]>;
      };
      // A file written before work keys has no `workKey` on any record; `keyOf` files those under their
      // txHash, which is where they always were, so an upgrade neither re-votes nor loses a receipt.
      for (const r of raw.requests ?? []) this.reqs.set(keyOf(r), r);
      this.loadReceipts(raw.receipts ?? []);
      for (const r of raw.policyRequests ?? []) this.policyRequests.set(r.txHash, r);
      for (const [k, r] of raw.policyRequestsByKey ?? []) this.policyRequests.set(k, r);
    } catch (e) {
      // A corrupt state file must not silently become an empty one: that would re-vote everything.
      throw new Error(`store: ${this.path} exists but is unreadable (${(e as Error).message}) — refusing to start with an empty history`);
    }
  }

  /**
   * Receipts are an append-only log. A file written before this change holds one receipt per key and no `seq`: its receipts are
   * numbered in file order. A file that has `seq` must have it on every receipt, contiguous from 1: a gap, a duplicate or a mix
   * means a receipt was dropped or edited out, and the process refuses to start rather than carry on with a shortened trail.
   */
  private loadReceipts(rows: Receipt[]): void {
    const withSeq = rows.filter((r) => typeof r.seq === 'number').length;
    if (withSeq !== 0 && withSeq !== rows.length) throw new Error('receipts with and without a sequence number: a receipt trail that may have been edited');
    const ordered = withSeq === 0 ? rows.map((r, i) => ({ ...r, seq: i + 1 })) : [...rows].sort((a, b) => a.seq! - b.seq!);
    ordered.forEach((r, i) => {
      if (r.seq !== i + 1) throw new Error(`receipt sequence is not contiguous (expected ${i + 1}, found ${r.seq}): a receipt was dropped or duplicated`);
      this.receiptLog.push(r);
      this.receipts.set(keyOf(r), r);
    });
  }

  protected async persist(): Promise<void> {
    const snapshot = JSON.stringify({
      requests: [...this.reqs.values()],
      receipts: this.receiptLog,
      // Hash-keyed requests in the original field, so a file stays readable by the previous release;
      // path-keyed ones beside it, with their key, because the request itself does not carry it.
      policyRequests: [...this.policyRequests.entries()].filter(([k, r]) => k === r.txHash).map(([, r]) => r),
      policyRequestsByKey: [...this.policyRequests.entries()].filter(([k, r]) => k !== r.txHash),
    });
    this.queue = this.queue.then(() => this.writeAtomic(snapshot)).catch(() => this.writeAtomic(snapshot));
    return this.queue;
  }

  private async writeAtomic(data: string): Promise<void> {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, data, 'utf8');
    const fd = openSync(tmp, 'r+');
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, this.path);
  }
}
