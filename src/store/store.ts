/** Persistence: SigningRequest + Receipt, keyed by txHash. Interface + in-memory and file-backed impls. */
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { Receipt, RequestStatus, SigningRequest } from '../types.js';

export const TERMINAL: RequestStatus[] = ['signed', 'rejected', 'expired'];

export interface Store {
  get(txHash: string): Promise<SigningRequest | undefined>;
  create(req: SigningRequest): Promise<void>;
  update(txHash: string, patch: Partial<SigningRequest>): Promise<SigningRequest>;
  saveReceipt(r: Receipt): Promise<void>;
  getReceipt(txHash: string): Promise<Receipt | undefined>;
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
  /** Best-effort single-flight lock. Returns false if already locked. */
  tryLock(txHash: string): boolean;
  unlock(txHash: string): void;
}

export class MemoryStore implements Store {
  protected reqs = new Map<string, SigningRequest>();
  protected receipts = new Map<string, Receipt>();
  private locks = new Set<string>();

  async get(txHash: string) { return this.reqs.get(txHash); }
  async create(req: SigningRequest) {
    if (this.reqs.has(req.txHash)) throw new Error(`duplicate signing_request ${req.txHash}`);
    this.reqs.set(req.txHash, { ...req });
    await this.persist();
  }
  async update(txHash: string, patch: Partial<SigningRequest>) {
    const cur = this.reqs.get(txHash);
    if (!cur) throw new Error(`no signing_request ${txHash}`);
    const next = { ...cur, ...patch, updatedAt: Date.now() };
    this.reqs.set(txHash, next);
    await this.persist();
    return next;
  }
  async saveReceipt(r: Receipt) { this.receipts.set(r.txHash, { ...r }); await this.persist(); }
  async getReceipt(txHash: string) { return this.receipts.get(txHash); }
  async listNonTerminal() {
    return [...this.reqs.values()].filter((r) => !TERMINAL.includes(r.status));
  }
  async listRecent(limit = 50, statuses?: RequestStatus[]) {
    const wanted = statuses?.length ? new Set(statuses) : undefined;
    return [...this.reqs.values()]
      .filter((r) => !wanted || wanted.has(r.status))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, Math.max(0, limit))
      .map((request) => ({ request, receipt: this.receipts.get(request.txHash) }));
  }
  tryLock(txHash: string) {
    if (this.locks.has(txHash)) return false;
    this.locks.add(txHash);
    return true;
  }
  unlock(txHash: string) { this.locks.delete(txHash); }

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
        requests?: SigningRequest[]; receipts?: Receipt[];
      };
      for (const r of raw.requests ?? []) this.reqs.set(r.txHash, r);
      for (const r of raw.receipts ?? []) this.receipts.set(r.txHash, r);
    } catch (e) {
      // A corrupt state file must not silently become an empty one: that would re-vote everything.
      throw new Error(`store: ${this.path} exists but is unreadable (${(e as Error).message}) — refusing to start with an empty history`);
    }
  }

  protected async persist(): Promise<void> {
    const snapshot = JSON.stringify({
      requests: [...this.reqs.values()],
      receipts: [...this.receipts.values()],
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
