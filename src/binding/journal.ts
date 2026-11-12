/**
 * The signer's decision journal: ONE append-only, hash-chained log per process (the core's decision log, DECISION.md section 9)
 * holding what must survive a restart and must not be quietly editable: the nonces consumed (`decision.consumed`), the pauses
 * set and cleared (`pause.set`, `pause.clear`) and the nonces voided (`recheck.result`).
 *
 * Durability. An append is one JSON line, written and fsync-ed BEFORE `append` returns; the caller signs only after that. A
 * failed write breaks the journal (every later append refuses: `journal_broken`) so that no entry is ever skipped or written
 * after a gap (DE-47: an append that cannot be made fails the decision). A crash inside an append leaves a torn last line
 * (no newline): the decision it belonged to never returned, was never signed, and the fragment is cut off at the next start.
 *
 * Tamper evidence. At start every line is parsed and `verifyLog` runs against the PIN, `{seq, hash}` of the head, rewritten
 * atomically after every append. An edited payload, a deleted middle entry, a reorder, an insert, a truncated tail (shorter
 * than the pin) and an edit re-chained to the end (a different hash at the pin's seq) each refuse to start, by the core's
 * name. A missing pin next to a non-empty journal refuses too. LIMIT (DE-45): a pin stored next to the journal does not stop a
 * writer who can rewrite the journal AND the pin; `pinPath` may name a medium the journal's writer cannot edit.
 * One writer per state directory.
 */
import { appendFileSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, truncateSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { appendEntry, verifyLog, type LogEntry, type LogHead } from '../core/log.js';

export class JournalError extends Error {
  constructor(readonly reason: string, readonly detail?: string) {
    super(detail === undefined ? reason : `${reason} ${detail}`);
  }
}

export interface JournalOptions {
  /** the journal file; absent = in memory (lost on restart: the caller says so) */
  path?: string;
  /** the pin file; defaults to `<path>.pin.json` */
  pinPath?: string;
  /** the id of the log (genesis of the chain); one per signer, so a journal cannot be replaced by another signer's */
  logId: string;
  /** called when a torn last line was cut off at start */
  onTornTail?: (bytes: number) => void;
}

const isHead = (v: unknown): v is LogHead => typeof v === 'object' && v !== null && typeof (v as LogHead).seq === 'number' && typeof (v as LogHead).hash === 'string';

function writeAtomic(path: string, data: string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, data, 'utf8');
  const fd = openSync(tmp, 'r+');
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
}

export class DecisionJournal {
  private log: LogEntry[] = [];
  private head: LogHead | null = null;
  private chain: Promise<unknown> = Promise.resolve();
  private broken: string | undefined;
  readonly path: string | undefined;
  readonly pinPath: string | undefined;
  readonly logId: string;
  /** true when the log was read and verified against a pin at start (false: in memory, or an empty fresh journal) */
  verifiedAtStart = false;

  constructor(opts: JournalOptions) {
    this.logId = opts.logId;
    this.path = opts.path;
    this.pinPath = opts.path === undefined ? undefined : opts.pinPath ?? `${opts.path}.pin.json`;
    if (this.path !== undefined) this.load(opts);
  }

  private load(opts: JournalOptions): void {
    const path = this.path!;
    mkdirSync(dirname(path), { recursive: true });
    if (this.pinPath !== undefined) mkdirSync(dirname(this.pinPath), { recursive: true });
    let text = existsSync(path) ? readFileSync(path, 'utf8') : '';
    if (text.length > 0 && !text.endsWith('\n')) {
      const cut = text.lastIndexOf('\n') + 1;
      const torn = Buffer.byteLength(text.slice(cut), 'utf8');
      truncateSync(path, Buffer.byteLength(text.slice(0, cut), 'utf8'));
      text = text.slice(0, cut);
      opts.onTornTail?.(torn);
    }
    const entries: unknown[] = [];
    const lines = text.length === 0 ? [] : text.slice(0, -1).split('\n');
    lines.forEach((line, i) => {
      try {
        entries.push(JSON.parse(line));
      } catch {
        throw new JournalError('journal_line_unparseable', `line ${i + 1}`);
      }
    });
    let pin: unknown;
    if (this.pinPath !== undefined && existsSync(this.pinPath)) {
      try {
        pin = JSON.parse(readFileSync(this.pinPath, 'utf8'));
      } catch {
        throw new JournalError('journal_pin_unreadable');
      }
    } else if (entries.length > 0) {
      throw new JournalError('journal_pin_missing', 'a journal with entries and no pin: the pin is rewritten after every append, so it was deleted');
    }
    const v = verifyLog({ logId: this.logId, entries, ...(pin !== undefined ? { expectedHead: pin } : {}) });
    if (!v.ok) throw new JournalError(v.reason, v.seq === undefined ? v.detail : `seq ${v.seq}${v.detail ? ' ' + v.detail : ''}`);
    this.log = entries as LogEntry[];
    this.head = v.head;
    this.verifiedAtStart = true;
    // the pin may lag the journal by one append (a crash between the line and the pin): bring it up to the verified head
    if (this.head !== null && (!isHead(pin) || (pin as LogHead).seq !== this.head.seq)) writeAtomic(this.pinPath!, JSON.stringify(this.head));
  }

  /** every entry, oldest first (a copy: the journal is append-only) */
  entries(): LogEntry[] {
    return [...this.log];
  }

  currentHead(): LogHead | null {
    return this.head === null ? null : { ...this.head };
  }

  /**
   * Appends one entry and returns it after it is durable (written, fsync-ed, pin rewritten). Appends are serialized. A
   * refusal or a write failure throws and appends nothing; the caller fails the decision it belongs to.
   */
  append(kind: string, at: number, payload: Record<string, unknown>): Promise<LogEntry> {
    const run = this.chain.then(() => this.appendNow(kind, at, payload));
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** runs `fn` after every append queued so far and before any later one: the nonce check and its append are one step */
  exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** `append` for a caller that already holds the exclusive step */
  appendNow(kind: string, at: number, payload: Record<string, unknown>): LogEntry {
    if (this.broken !== undefined) throw new JournalError('journal_broken', this.broken);
    const made = appendEntry({ logId: this.logId, head: this.head, kind, at, payload });
    if (!made.ok) throw new JournalError(made.reason, made.detail);
    const entry = made.entry;
    if (this.path !== undefined) {
      try {
        const fd = openSync(this.path, 'a');
        try {
          appendFileSync(fd, JSON.stringify(entry) + '\n', 'utf8');
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
      } catch (e) {
        this.broken = (e as Error).message;
        throw new JournalError('journal_write_failed', (e as Error).message);
      }
    }
    this.log.push(entry);
    this.head = { seq: entry.seq, hash: entry.hash };
    if (this.pinPath !== undefined) {
      try {
        writeAtomic(this.pinPath, JSON.stringify(this.head));
      } catch (e) {
        // the entry IS durable; a stale pin still verifies (the journal has only grown past it). Refuse further appends so
        // the operator sees it, and fail this one: the caller must not sign on an entry it cannot pin.
        this.broken = (e as Error).message;
        throw new JournalError('journal_pin_write_failed', (e as Error).message);
      }
    }
    return entry;
  }
}
