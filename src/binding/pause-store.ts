/**
 * The persisted pause (DECISION.md section 6; DE-24 to DE-28): the state machine is the core's (`applyPause`, `applyResume`,
 * `checkSigning`), this file is what makes it durable and enforced.
 *
 * Two durable artifacts, written in this order: the journal entry (`pause.set` / `pause.clear`, fsync-ed, chained and pinned) and
 * then `pause-state.json` (the core's canonical text, written atomically). The state file is what every signature READS; the
 * journal is what shows it was not edited.
 *
 * At start the state file is checked against the verified journal through the core's `checkPersistedPause` (DE-78). A state that
 * differs is refused (`pause_state_log_mismatch`), because a dropped record must never read as "not paused", with ONE exception
 * that is not an attack: a crash between the two writes leaves the file behind the journal by the entries of one change (the
 * file equals the replay of a prefix of the pause entries). That is rewritten from the journal, which only re-asserts what the
 * verified journal says, and it is said in the log.
 *
 * Before EVERY signature `check` re-reads the file and runs the core's `checkSigningFromText`: a pause set meanwhile, by this
 * process or by another tool, applies; an unreadable file signs nothing; a seat pause is reported before a subject pause.
 */
import { existsSync, closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  applyPause, applyResume, checkSigningFromText, emptyPauseState, parsePauseState, checkPersistedPause, serializePauseState,
  type PauseOptions, type PauseScope, type PauseState, type SigningVerdict,
} from '../core/pause.js';
import { DecisionJournal, JournalError } from './journal.js';

/** What the orchestrator asks before every signature. `PauseStore` implements it by re-reading the persisted state. */
export interface PauseGate {
  check(req: { seat: string; subject: string | null; vote: 'approve' | 'reject' }): SigningVerdict;
}

export interface PauseOp { scope: PauseScope; id: string; by: string; reason: string }
/** pausing what is paused is not a refusal (DE-78, pz-17): the answer is `status: 'already_paused'`, the first record stays, nothing is journalled */
export type PauseOutcome = { ok: true; state: PauseState; status?: 'already_paused' } | { ok: false; reason: string; detail?: string };

export class PauseStateError extends Error {
  constructor(readonly reason: string, readonly detail?: string) {
    super(detail === undefined ? reason : `${reason} ${detail}`);
  }
}

export interface PauseStoreOptions {
  journal: DecisionJournal;
  /** `pause-state.json`; absent = in memory (lost on restart: the caller says so) */
  statePath?: string;
  /** the configured seat ids: what a pause or resume without a scope acts on */
  seats: string[];
  nowSeconds: () => number;
  pause?: PauseOptions;
  onHeal?: (detail: string) => void;
}

function writeAtomic(path: string, data: string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, data, 'utf8');
  const fd = openSync(tmp, 'r+');
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
}

/** the state the pause entries of the journal add up to (the same fold as the core's checkPersistedPause) */
function replay(entries: Array<{ kind: string; at: number; payload: Record<string, unknown> }>): PauseState {
  let state = emptyPauseState();
  for (const e of entries) {
    if (e.kind !== 'pause.set' && e.kind !== 'pause.clear') continue;
    const p = e.payload;
    const op = { scope: p['scope'], id: p['id'], by: p['by'], reason: p['reason'], at: e.at };
    const r = e.kind === 'pause.set' ? applyPause(state, op, { minReasonLength: 1 }) : applyResume(state, op, { minReasonLength: 1 });
    if (!r.ok) throw new PauseStateError('pause_journal_unreplayable', `${e.kind} ${r.reason}`);
    state = r.state;
  }
  return state;
}

export class PauseStore {
  private state: PauseState = emptyPauseState();
  private readonly journal: DecisionJournal;
  private readonly statePath: string | undefined;
  private readonly seatIds: string[];
  private readonly now: () => number;
  private readonly opts: PauseOptions | undefined;

  constructor(o: PauseStoreOptions) {
    this.journal = o.journal;
    this.statePath = o.statePath;
    this.seatIds = [...o.seats];
    this.now = o.nowSeconds;
    this.opts = o.pause;
    if (this.statePath !== undefined) mkdirSync(dirname(this.statePath), { recursive: true });
    this.start(o.onHeal);
  }

  /** read at start: reconcile the persisted state with the verified journal, heal the one crash window, refuse the rest */
  private start(onHeal?: (detail: string) => void): void {
    const entries = this.journal.entries();
    const pauseEntries = entries.filter((e) => e.kind === 'pause.set' || e.kind === 'pause.clear');
    const expected = replay(pauseEntries);
    if (this.statePath === undefined) {
      this.state = expected;
      return;
    }
    // A crash between the journal append(s) and the state write leaves the file behind the journal by the entries of ONE
    // change (one entry, or one per seat for a pause of every seat). The state must then equal the replay of a prefix of the
    // pause entries; it is rewritten from the journal, which only ever re-asserts what the verified journal says.
    const heal = (current: PauseState, why: string): boolean => {
      const have = serializePauseState(current);
      for (let k = 1; k <= Math.min(pauseEntries.length, this.seatIds.length + 1); k++) {
        if (serializePauseState(replay(pauseEntries.slice(0, pauseEntries.length - k))) === have) {
          this.write(expected);
          this.state = expected;
          onHeal?.(why + ' (' + k + ' pause entr' + (k === 1 ? 'y' : 'ies') + ' behind the journal, a crash between the two writes); rewritten from the journal');
          return true;
        }
      }
      return false;
    };
    if (!existsSync(this.statePath)) {
      if (pauseEntries.length === 0) {
        this.write(expected);
        this.state = expected;
        return;
      }
      if (heal(emptyPauseState(), 'state file missing')) return;
      throw new PauseStateError('pause_state_log_mismatch', 'the state file is missing and the journal holds pause entries it cannot account for');
    }
    const parsed = parsePauseState(readFileSync(this.statePath, 'utf8'));
    if (!parsed.ok) throw new PauseStateError('pause_state_unreadable', parsed.reason);
    const r = checkPersistedPause({ state: parsed.state, log: pauseEntries.map((e) => ({ kind: e.kind, at: e.at, payload: e.payload })) });
    if (r.ok) {
      this.state = parsed.state;
      return;
    }
    if (r.reason === 'pause_state_log_mismatch' && heal(parsed.state, 'state file behind the journal')) return;
    throw new PauseStateError(r.reason, r.detail);
  }

  private write(state: PauseState): void {
    if (this.statePath !== undefined) writeAtomic(this.statePath, serializePauseState(state));
  }

  /** the persisted state (re-read from the file when there is one) */
  snapshot(): PauseState {
    if (this.statePath === undefined) return this.state;
    const p = parsePauseState(readFileSync(this.statePath, 'utf8'));
    if (!p.ok) throw new PauseStateError('pause_state_unreadable', p.reason);
    return p.state;
  }

  /** true when any pause is set; an unreadable state counts as paused (it signs nothing) */
  anyPaused(): boolean {
    try {
      return this.snapshot().pauses.length > 0;
    } catch {
      return true;
    }
  }

  seats(): string[] {
    return [...this.seatIds];
  }

  /**
   * May this seat sign this vote about this subject? Read from the persisted state on EVERY call. `subject` is an ADI or null.
   * A paused seat or subject signs nothing, a reject vote included; an unreadable state signs nothing.
   */
  check(req: { seat: string; subject: string | null; vote: 'approve' | 'reject' }): SigningVerdict {
    if (this.statePath === undefined) return checkSigningFromText(serializePauseState(this.state), req);
    try {
      return checkSigningFromText(readFileSync(this.statePath, 'utf8'), req);
    } catch (e) {
      return { ok: false, reason: 'pause_state_unreadable', detail: (e as Error).message };
    }
  }

  /** Sets a pause (one scope and id). The journal entry is durable before the state file is written. */
  set(op: PauseOp): Promise<PauseOutcome> {
    return this.journal.exclusive(async () => this.change('set', [op]));
  }

  /** Resumes one scope and id. Another scope or id stays paused. */
  resume(op: PauseOp): Promise<PauseOutcome> {
    return this.journal.exclusive(async () => this.change('resume', [op]));
  }

  /** Pauses every configured seat that is not yet paused (the old "stop everything"), with a named seat and a reason. */
  setAllSeats(by: string, reason: string): Promise<PauseOutcome> {
    return this.journal.exclusive(async () => {
      const cur = this.snapshot();
      const todo = this.seatIds.filter((id) => !cur.pauses.some((p) => p.scope === 'seat' && p.id === id));
      if (todo.length === 0) return { ok: true, state: cur, status: 'already_paused' } as PauseOutcome;
      return this.change('set', todo.map((id) => ({ scope: 'seat' as const, id, by, reason })));
    });
  }

  /** Resumes every configured seat that is paused; a pause on a subject is NOT lifted. Refused when no seat is paused. */
  resumeAllSeats(by: string, reason: string): Promise<PauseOutcome> {
    return this.journal.exclusive(async () => {
      const cur = this.snapshot();
      const todo = this.seatIds.filter((id) => cur.pauses.some((p) => p.scope === 'seat' && p.id === id));
      if (todo.length === 0) return { ok: false, reason: 'not_paused', detail: 'no configured seat is paused' } as PauseOutcome;
      return this.change('resume', todo.map((id) => ({ scope: 'seat' as const, id, by, reason })));
    });
  }

  /** every op is validated against the state first (nothing is journalled when any refuses), then journalled, then the file is written */
  private change(kind: 'set' | 'resume', ops: PauseOp[]): PauseOutcome {
    let state = this.snapshot();
    const at = this.now();
    const events: Array<{ kind: 'pause.set' | 'pause.clear'; payload: Record<string, unknown> }> = [];
    for (const op of ops) {
      const r = kind === 'set' ? applyPause(state, { ...op, at }, this.opts) : applyResume(state, { ...op, at }, this.opts);
      if (!r.ok) return r;
      state = r.state;
      if ('event' in r) events.push({ kind: r.event.kind, payload: { ...r.event.payload } });
    }
    if (events.length === 0) return { ok: true, state, status: 'already_paused' };
    try {
      for (const e of events) this.journal.appendNow(e.kind, at, e.payload);
    } catch (e) {
      if (e instanceof JournalError) return { ok: false, reason: e.reason, ...(e.detail !== undefined ? { detail: e.detail } : {}) };
      throw e;
    }
    this.write(state);
    this.state = state;
    return { ok: true, state };
  }
}


/** What the admin routes and /healthz use: the gate plus reading and changing the persisted pause. `PauseStore` implements it. */
export interface PauseControl extends PauseGate {
  snapshot(): PauseState;
  anyPaused(): boolean;
  seats(): string[];
  set(op: PauseOp): Promise<PauseOutcome>;
  resume(op: PauseOp): Promise<PauseOutcome>;
  setAllSeats(by: string, reason: string): Promise<PauseOutcome>;
  resumeAllSeats(by: string, reason: string): Promise<PauseOutcome>;
}

/**
 * A pause store with no files: used where nothing is persisted (a signer without `store.path`, which already says its history is
 * lost on restart, and tests). Same semantics, same core state machine; it simply does not survive a restart.
 */
export function memoryPauseStore(seats: string[] = [], nowSeconds: () => number = () => Math.floor(Date.now() / 1000)): PauseStore {
  return new PauseStore({ journal: new DecisionJournal({ logId: 'certen-signer-memory' }), seats, nowSeconds });
}
