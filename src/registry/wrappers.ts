/**
 * The enrolment registry: which wrapper books this signer serves. Wrapper runbook, change 1.
 *
 * The one source of "which wrappers we serve", read on every poll cycle, so a wrapper enrolled while the
 * process runs is polled on the next cycle with no restart. Discovery reads each listed wrapper book's
 * pending list, because that is where a delegated transaction waits: a delegate receives no signature
 * request (`block/sig_user.go:476-515`), and the vote routes to the wrapper's book
 * (`block/sig_common.go:188-196`, `:262-268`), never to ours.
 *
 * Being listed here is NECESSARY for a vote, never SUFFICIENT: the wrapper's on-chain shape is checked
 * before every vote (`checkWrapper`), and the path always comes from the chain. A stale or forged entry
 * can at worst cost a read.
 *
 * Backed the way the store is: memory for tests, a JSON file for deployments, rewritten atomically.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface Seat {
  /** The org page the wrapper sits on as a delegate, e.g. `acc://acme.acme/treasury/1`. */
  orgPage: string;
  /** The transaction that attached it, once it executed. */
  attachedTx: string;
  attachedAt: number;
}

export interface WrapperEntry {
  /** `acc://alice.acme/id` */
  wrapperBook: string;
  /** `acc://alice.acme/id/1` */
  wrapperPage: string;
  /** The live-check subject this wrapper is enrolled to. Opaque here. */
  subjectId: string;
  /**
   * The subscriber's own book: the wrapper's other delegate, beside Trust Stamp's. Recorded at
   * registration so the creation vote can require that exact book (a creation that seats anyone else is
   * refused). Absent on entries registered before it was recorded.
   */
  subscriberBook?: string;
  enrolledAt: number;
  seats: Seat[];
  /**
   * `enrolling`: Trust Stamp's enrolment service registered the wrapper before its creation transaction,
   * so discovery watches it and the creation vote can be recognised — but it is NOT yet a wrapper we vote
   * through. It becomes `active` only once the creation transaction has EXECUTED on chain and the result
   * passes the wrapper check (wrapper runbook, change 6). Absent means `active` (entries written before
   * enrolment states existed).
   */
  status?: 'enrolling' | 'active';
}

export const isActive = (e: WrapperEntry) => e.status !== 'enrolling';

export interface WrapperRegistry {
  list(): Promise<WrapperEntry[]>;
  get(wrapperBook: string): Promise<WrapperEntry | undefined>;
  upsert(e: WrapperEntry): Promise<void>;
  addSeat(wrapperBook: string, s: Seat): Promise<void>;
  removeSeat(wrapperBook: string, orgPage: string): Promise<void>;
}

/** Accumulate URLs are case-insensitive, and a trailing slash names the same account. */
const norm = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase();

export class MemoryWrapperRegistry implements WrapperRegistry {
  protected entries = new Map<string, WrapperEntry>();

  async list() { return [...this.entries.values()].map((e) => structuredClone(e)); }
  async get(wrapperBook: string) {
    const e = this.entries.get(norm(wrapperBook));
    return e && structuredClone(e);
  }
  async upsert(e: WrapperEntry) {
    // An upsert keeps the seats already recorded unless the caller states them: re-enrolling a subject
    // must not silently forget where their wrapper sits.
    const cur = this.entries.get(norm(e.wrapperBook));
    this.entries.set(norm(e.wrapperBook), structuredClone({ ...e, seats: e.seats.length ? e.seats : cur?.seats ?? [] }));
    await this.persist();
  }
  async addSeat(wrapperBook: string, s: Seat) {
    const e = this.entries.get(norm(wrapperBook));
    if (!e) throw new Error(`registry: ${wrapperBook} is not an enrolled wrapper`);
    if (!e.seats.some((x) => norm(x.orgPage) === norm(s.orgPage))) e.seats.push({ ...s });
    await this.persist();
  }
  async removeSeat(wrapperBook: string, orgPage: string) {
    const e = this.entries.get(norm(wrapperBook));
    if (!e) return;
    e.seats = e.seats.filter((x) => norm(x.orgPage) !== norm(orgPage));
    await this.persist();
  }

  /** No-op in memory; the file registry overrides it. */
  protected async persist(): Promise<void> {}
}

/** The same registry, durable: a JSON file rewritten atomically (temp file, fsync, rename). */
export class FileWrapperRegistry extends MemoryWrapperRegistry {
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly path: string) {
    super();
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      try {
        const raw = JSON.parse(readFileSync(path, 'utf8')) as { wrappers?: WrapperEntry[] };
        for (const e of raw.wrappers ?? []) this.entries.set(norm(e.wrapperBook), { ...e, seats: e.seats ?? [] });
      } catch (e) {
        // An unreadable registry must not become an empty one: the signer would serve nobody, silently.
        throw new Error(`registry: ${path} exists but is unreadable (${(e as Error).message}) — refusing to start with no wrappers`);
      }
    }
  }

  protected async persist(): Promise<void> {
    const snapshot = JSON.stringify({ wrappers: [...this.entries.values()] }, null, 2);
    this.queue = this.queue.then(() => this.writeAtomic(snapshot)).catch(() => this.writeAtomic(snapshot));
    return this.queue;
  }

  private writeAtomic(data: string): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, data, 'utf8');
    const fd = openSync(tmp, 'r+');
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, this.path);
  }
}

/**
 * Is this page an ACTIVE enrolled wrapper page in the registry? (The on-chain check is `checkWrapper`.)
 * A wrapper still enrolling is not one we vote through: its creation has not executed yet.
 */
export async function isRegisteredWrapperPage(reg: WrapperRegistry, page: string): Promise<boolean> {
  return (await reg.list()).some((e) => isActive(e) && norm(e.wrapperPage) === norm(page));
}

/** The registry entry (any status) whose wrapper book is, or contains, this account. */
export async function wrapperOwning(reg: WrapperRegistry, account: string): Promise<WrapperEntry | undefined> {
  const a = norm(account);
  return (await reg.list()).find((e) => a === norm(e.wrapperBook) || a.startsWith(`${norm(e.wrapperBook)}/`));
}
