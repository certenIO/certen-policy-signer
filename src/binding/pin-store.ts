/**
 * The persisted policy pin of every bound seat (DECISION.md section 4, DE-93, DE-94, DE-104). The state machine is the core's
 * (`applyPinOp`, `pinPhase`); this file makes it durable and enforced.
 *
 * What the signer "loads" is the rule-set hash its operator configured for the seat (`binding.policy_hash`): the signer does not compute
 * the decision service's rule-set hash, it is told it, and it pins exactly that hash by an explicit step. So the two phases are:
 *   1. boot: the seat loads its configured hash. With no pin it is `pin_pending`; with a pin equal to it, `pinned`; with a pin that differs
 *      (the rule set changed) `pin_stale`.
 *   2. the pin step (`POST /v1/admin/pin`): a named seat identity (`seat:` plus a name), a reason of at least ten characters, the hash the seat
 *      has LOADED. The step never pins an arbitrary hash (`pin_hash_not_loaded`).
 * A seat that is not `pinned` decides nothing: `gate` answers `policy_pin_missing` (no pin) or `policy_hash_mismatch` with the detail
 * `pin_stale`, and the binding check answers it BEFORE anything of the decision is read (a deny that would become a reject vote included).
 *
 * Durability: the pin IS the `policy.pinned` entry of the decision journal (hash-chained, fsync-ed, pinned head, verified at start), the
 * latest such entry of a seat. The entry is durable before the step answers; a restart replays the entries, so the pin survives it. Every
 * entry names the previous pin, and a journal whose entries do not chain (an entry whose `previous` is not the pin before it) refuses the
 * start. An entry of a seat that is no longer configured is kept (the journal is append-only) and ignored.
 */
import { applyPinOp, emptyPinState, pinPhase, type PinPhase, type PinState } from '../core/policy-pin.js';
import { isHash, isSeatId } from '../core/decision-identity.js';
import { DecisionJournal, JournalError } from './journal.js';

export class PinStateError extends Error {
  constructor(readonly reason: string, readonly detail?: string) {
    super(detail === undefined ? reason : `${reason} ${detail}`);
  }
}

export interface PinSeat {
  seat: string;
  /** the rule-set hash this seat loaded at boot (its configured `binding.policy_hash`) */
  loadedHash: string;
}

export type PinGateResult = { ok: true; pin: string } | { ok: false; reason: 'policy_pin_missing' | 'policy_not_loaded' | 'policy_hash_mismatch'; detail?: string };
/** what the binding check asks before it reads anything of a decision */
export interface PinGate {
  gate(seat: string): PinGateResult;
}

export interface PinView { seat: string; loaded: string | null; pin: string | null; phase: PinPhase }
export interface PinOp { seat: unknown; hash: unknown; by: unknown; reason: unknown }
export type PinOutcome = { ok: true; phase: PinPhase; previous?: string | null; idempotent?: boolean } | { ok: false; reason: string; detail?: string };

/** What the admin routes use: the gate plus reading and changing the pin. `PinStore` implements it. */
export interface PinControl extends PinGate {
  snapshot(): PinView[];
  pin(op: PinOp): Promise<PinOutcome>;
}

export interface PinStoreOptions {
  journal: DecisionJournal;
  seats: PinSeat[];
  nowSeconds: () => number;
}

export class PinStore implements PinControl {
  private readonly states = new Map<string, PinState>();
  private readonly journal: DecisionJournal;
  private readonly now: () => number;

  constructor(o: PinStoreOptions) {
    this.journal = o.journal;
    this.now = o.nowSeconds;
    // the pins the verified journal holds: the latest `policy.pinned` entry of each seat, each entry chained to the one before it
    const pins = new Map<string, string>();
    for (const e of o.journal.entries()) {
      if (e.kind !== 'policy.pinned') continue;
      const seat = e.payload['seat'];
      const hash = e.payload['policyHash'];
      const previous = e.payload['previous'] ?? null;
      if (!isSeatId(seat) || !isHash(hash)) throw new PinStateError('pin_journal_unreadable', `seq ${e.seq}`);
      if ((pins.get(seat) ?? null) !== previous) throw new PinStateError('pin_journal_not_chained', `seq ${e.seq} names previous ${String(previous)} for ${seat}`);
      pins.set(seat, hash);
    }
    for (const s of o.seats) {
      if (!isSeatId(s.seat)) throw new PinStateError('pin_seat_invalid', s.seat);
      if (this.states.has(s.seat)) throw new PinStateError('pin_seat_duplicate', s.seat);
      // phase 1, the boot: the seat loads its hash (the core machine refuses a hash that is not 32 bytes)
      const booted = applyPinOp({ ...emptyPinState(s.seat), pin: pins.get(s.seat) ?? null }, { op: 'boot', loadedHash: s.loadedHash });
      if (!booted.result.ok) throw new PinStateError(booted.result.reason, s.seat);
      this.states.set(s.seat, booted.state);
    }
  }

  /** the verdict for a seat: only a seat whose pin equals the hash it loaded decides. A seat this store does not know has no pin. */
  gate(seat: string): PinGateResult {
    const s = this.states.get(seat);
    if (s === undefined) return { ok: false, reason: 'policy_pin_missing' };
    if (s.pin === null) return { ok: false, reason: 'policy_pin_missing' };
    if (s.loaded === null) return { ok: false, reason: 'policy_not_loaded' };
    if (s.pin !== s.loaded) return { ok: false, reason: 'policy_hash_mismatch', detail: 'pin_stale' };
    return { ok: true, pin: s.pin };
  }

  snapshot(): PinView[] {
    return [...this.states.values()].map((s) => ({ seat: s.seat, loaded: s.loaded, pin: s.pin, phase: pinPhase(s) }));
  }

  /** the pin step: durable (journal entry fsync-ed) before it answers */
  pin(op: PinOp): Promise<PinOutcome> {
    return this.journal.exclusive(async () => this.pinNow(op));
  }

  /** the same step for a caller that already holds the journal's exclusive section (or runs before any request is served) */
  pinNow(op: PinOp): PinOutcome {
    const seat = op.seat;
    const state = typeof seat === 'string' ? this.states.get(seat) : undefined;
    if (state === undefined) return { ok: false, reason: 'pin_seat_unknown', detail: typeof seat === 'string' ? seat : 'seat' };
    const at = this.now();
    const r = applyPinOp(state, { op: 'pin', hash: op.hash, by: op.by, reason: op.reason, at });
    if (!r.result.ok) return { ok: false, reason: r.result.reason, ...(r.result.detail !== undefined ? { detail: r.result.detail } : {}) };
    const res = r.result as { ok: true; phase: PinPhase; idempotent?: boolean; previous?: string | null; log?: { kind: string; at: number; payload: Record<string, unknown> } };
    if (res.log !== undefined) {
      try {
        this.journal.appendNow(res.log.kind, res.log.at, res.log.payload);
      } catch (e) {
        if (e instanceof JournalError) return { ok: false, reason: e.reason, ...(e.detail !== undefined ? { detail: e.detail } : {}) };
        throw e;
      }
    }
    this.states.set(state.seat, r.state);
    return { ok: true, phase: res.phase, ...(res.idempotent === true ? { idempotent: true } : { previous: res.previous ?? null }) };
  }
}
