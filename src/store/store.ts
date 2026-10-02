/** Persistence: SigningRequest + Receipt, keyed by txHash. Interface + in-memory and file-backed impls. */
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { PolicyRequest, Receipt, RequestStatus, SigningRequest } from '../types.js';

export const TERMINAL: RequestStatus[] = ['signed', 'rejected', 'expired'];

export interface Store {
  /**
   * A request by its RECORD KEY: the tx hash for a keyed seat (the key every existing record has), or
   * `humanRecordId(txHash, page)` for a human-only seat (review #1). A transaction several pages must act on
   * therefore has one record per acting page, and no page's record can pre-empt another's.
   */
  get(key: string): Promise<SigningRequest | undefined>;
  /** Every record for one transaction, whichever page it belongs to. */
  listForTx(txHash: string): Promise<SigningRequest[]>;
  create(req: SigningRequest): Promise<void>;
  update(txHash: string, patch: Partial<SigningRequest>): Promise<SigningRequest>;
  /** Keyed by `r.recordId ?? r.txHash`, as the request it belongs to. */
  saveReceipt(r: Receipt): Promise<void>;
  getReceipt(txHash: string): Promise<Receipt | undefined>;
  /** The latest PolicyRequest built for a transaction (Phase 6.4 `/relay/pending/:hash`). */
  /** `key` defaults to the tx hash; a human-only seat stores its request under its record key. */
  savePolicyRequest(r: PolicyRequest, key?: string): Promise<void>;
  /** By key; a bare tx hash falls back to any page's record for that transaction (officer intake, relay). */
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
  /**
   * G-39: officer-intake state that must outlive a restart -- open prepares and governance proposals --
   * keyed by kind and id. Records are plain JSON (binary fields hex-encoded by the caller) and hold no
   * secret: a prepare is a public key, hashes and a display; a proposal is typed operations and a display.
   */
  saveIntakeRecord(kind: IntakeRecordKind, id: string, record: Record<string, unknown>): Promise<void>;
  deleteIntakeRecord(kind: IntakeRecordKind, id: string): Promise<void>;
  listIntakeRecords(kind: IntakeRecordKind): Promise<Array<Record<string, unknown>>>;
  /** Best-effort single-flight lock. Returns false if already locked. */
  tryLock(txHash: string): boolean;
  unlock(txHash: string): void;
}

export type IntakeRecordKind = 'prepare' | 'proposal';

/**
 * The record key of a HUMAN-ONLY seat's request for a transaction (review #1): `<txHash>@<page>`, page
 * lower-cased without a trailing slash. Distinct from the bare tx hash a keyed seat's record uses, so a
 * human-only page and a keyed page that both act on one transaction each keep, and decide, their own record.
 */
export function humanRecordId(txHash: string, page: string): string {
  return `${txHash.toLowerCase()}@${page.toLowerCase().replace(/\/+$/, '')}`;
}

export class MemoryStore implements Store {
  protected reqs = new Map<string, SigningRequest>();
  protected receipts = new Map<string, Receipt>();
  protected policyRequests = new Map<string, PolicyRequest>();
  protected intake = { prepare: new Map<string, Record<string, unknown>>(), proposal: new Map<string, Record<string, unknown>>() };
  private locks = new Set<string>();

  async get(key: string) { return this.reqs.get(key); }
  async listForTx(txHash: string) { return [...this.reqs.values()].filter((r) => r.txHash === txHash); }
  async create(req: SigningRequest) {
    const key = req.recordId ?? req.txHash;
    if (this.reqs.has(key)) throw new Error(`duplicate signing_request ${key}`);
    this.reqs.set(key, { ...req });
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
  async saveReceipt(r: Receipt) { this.receipts.set(r.recordId ?? r.txHash, { ...r }); await this.persist(); }
  async getReceipt(key: string) { return this.receipts.get(key); }
  async savePolicyRequest(r: PolicyRequest, key?: string) { this.policyRequests.set(key ?? r.txHash, structuredClone(r)); await this.persist(); }
  async getPolicyRequest(key: string) {
    const exact = this.policyRequests.get(key);
    if (exact || key.includes('@')) return exact;
    for (const [k, v] of this.policyRequests) if (k.startsWith(`${key}@`)) return v;
    return undefined;
  }
  async saveIntakeRecord(kind: IntakeRecordKind, id: string, record: Record<string, unknown>) {
    this.intake[kind].set(id, structuredClone(record)); await this.persist();
  }
  async deleteIntakeRecord(kind: IntakeRecordKind, id: string) {
    if (this.intake[kind].delete(id)) await this.persist();
  }
  async listIntakeRecords(kind: IntakeRecordKind) { return [...this.intake[kind].values()].map((r) => structuredClone(r)); }
  async listNonTerminal() {
    return [...this.reqs.values()].filter((r) => !TERMINAL.includes(r.status));
  }
  async listRecent(limit = 50, statuses?: RequestStatus[]) {
    const wanted = statuses?.length ? new Set(statuses) : undefined;
    return [...this.reqs.values()]
      .filter((r) => !wanted || wanted.has(r.status))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, Math.max(0, limit))
      .map((request) => ({ request, receipt: this.receipts.get(request.recordId ?? request.txHash) }));
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
        requests?: SigningRequest[]; receipts?: Receipt[]; policyRequests?: PolicyRequest[]; policyRequestKeys?: string[];
        intake?: { prepares?: Array<Record<string, unknown>>; proposals?: Array<Record<string, unknown>> };
      };
      for (const r of raw.requests ?? []) this.reqs.set(r.recordId ?? r.txHash, r);
      for (const r of raw.receipts ?? []) this.receipts.set(r.recordId ?? r.txHash, r);
      // A file written before per-page keys has no policyRequestKeys: every request was keyed by its tx hash.
      (raw.policyRequests ?? []).forEach((r, i) => this.policyRequests.set(raw.policyRequestKeys?.[i] ?? r.txHash, r));
      for (const r of raw.intake?.prepares ?? []) this.intake.prepare.set(String(r.prepareId), r);
      for (const r of raw.intake?.proposals ?? []) this.intake.proposal.set(String(r.id), r);
    } catch (e) {
      // A corrupt state file must not silently become an empty one: that would re-vote everything.
      throw new Error(`store: ${this.path} exists but is unreadable (${(e as Error).message}) — refusing to start with an empty history`);
    }
  }

  protected async persist(): Promise<void> {
    const snapshot = JSON.stringify({
      requests: [...this.reqs.values()],
      receipts: [...this.receipts.values()],
      policyRequests: [...this.policyRequests.values()],
      policyRequestKeys: [...this.policyRequests.keys()],
      intake: { prepares: [...this.intake.prepare.values()], proposals: [...this.intake.proposal.values()] },
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
