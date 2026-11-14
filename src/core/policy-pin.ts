/**
 * The policy pin of a bound seat: the two-phase boot and the pin step (DECISION.md section 4, decision OQ-DAX2-1; DE-93,
 * DE-94, DE-104). The pin is REQUIRED: a seat with no pin decides nothing and answers policy_pin_missing to every step.
 *
 *   Phase 1 (boot): the seat loads its rule set and computes its hash. With no pin it is `pin_pending`; with a pin equal to the
 *   hash it is `pinned` and decides; with a pin that differs it is `pin_stale` and refuses (policy_hash_mismatch, cause
 *   pin_stale) until the step is repeated.
 *   Phase 2 (pin): the explicit pin step by a named seat identity (`seat:` plus a name) with a reason of at least ten
 *   characters, naming the hash the seat HAS LOADED (the step pins what the seat computed and never an arbitrary hash:
 *   pin_hash_not_loaded; before any boot there is nothing to pin: pin_not_loaded). The pin is persisted and survives a restart;
 *   after a restart the seat boots again before it decides (policy_not_loaded). Pinning the pinned hash is idempotent and
 *   writes no second entry; every step that changes the pin is a `policy.pinned` entry of the decision log that names the
 *   previous pin (the log object the step answers).
 *
 * Pure: state in, `{ result, state }` out; the time of a step is its `at` argument. The persisted part of the state is the pin
 * alone (`pin`); `loaded` is what the running process computed and is gone after a restart. The vector harness switch
 * (the unpinned judging of the reference evaluators) is NOT here and in no production file (DE-93, DAX-4-A28).
 */
import { isHash, isSeatId, isTime } from './decision-identity.js';
import { isPlainObject } from './bytes.js';

export const MIN_PIN_REASON_LENGTH = 10;
const MAX_PIN_REASON_LENGTH = 1000;

export interface PinState {
  seat: string;
  /** the persisted pin, or null */
  pin: string | null;
  /** the hash the running process loaded, or null before the first boot and after a restart */
  loaded: string | null;
}
export type PinPhase = 'unloaded' | 'pin_pending' | 'pinned_unloaded' | 'pinned' | 'pin_stale';

export const emptyPinState = (seat: string): PinState => ({ seat, pin: null, loaded: null });

export function pinPhase(s: PinState): PinPhase {
  if (s.loaded === null) return s.pin === null ? 'unloaded' : 'pinned_unloaded';
  if (s.pin === null) return 'pin_pending';
  return s.pin === s.loaded ? 'pinned' : 'pin_stale';
}

export type PinResult = { ok: true; [member: string]: unknown } | { ok: false; reason: string; cause?: string; detail?: string };
const refuse = (reason: string, extra: { cause?: string; detail?: string } = {}): PinResult => ({ ok: false, reason, ...extra });

const OP_MEMBERS: Record<string, readonly string[]> = {
  boot: ['op', 'loadedHash'],
  pin: ['op', 'hash', 'by', 'reason', 'at'],
  decide: ['op', 'policyHash'],
  restart: ['op'],
};

/** one operation against the state; a refusal changes nothing */
export function applyPinOp(state: PinState, op: unknown): { result: PinResult; state: PinState } {
  const same = { result: undefined as unknown as PinResult, state };
  if (!isPlainObject(op) || typeof op['op'] !== 'string' || !Object.prototype.hasOwnProperty.call(OP_MEMBERS, op['op'])) return { ...same, result: refuse('pin_op_unknown') };
  const members = OP_MEMBERS[op['op']]!;
  const keys = Object.keys(op);
  // an operation carries exactly its own members: a restart carries nothing else (DE-74 pattern)
  if (keys.length !== members.length || !members.every((m) => keys.includes(m))) return { ...same, result: refuse('pin_op_unknown') };

  switch (op['op']) {
    case 'boot': {
      const h = op['loadedHash'];
      if (!isHash(h)) return { ...same, result: refuse('pin_hash_malformed') };
      const next: PinState = { ...state, loaded: h };
      const phase = pinPhase(next);
      return { result: { ok: true, phase, decides: phase === 'pinned' }, state: next };
    }
    case 'restart': {
      // the pin is persisted; what the process loaded is not
      const next: PinState = { ...state, loaded: null };
      return { result: { ok: true, restarted: true, phase: pinPhase(next) }, state: next };
    }
    case 'decide': {
      // the gate comes before anything of the step is read (DE-93)
      if (state.pin === null) return { ...same, result: refuse('policy_pin_missing') };
      if (state.loaded === null) return { ...same, result: refuse('policy_not_loaded') };
      if (state.pin !== state.loaded) return { ...same, result: refuse('policy_hash_mismatch', { cause: 'pin_stale' }) };
      if (!isHash(op['policyHash'])) return { ...same, result: refuse('decision_malformed') };
      if (op['policyHash'] !== state.pin) return { ...same, result: refuse('policy_hash_mismatch') };
      return { result: { ok: true }, state };
    }
    default: {
      // pin
      const by = op['by'];
      if (by === '') return { ...same, result: refuse('seat_required') };
      if (!isSeatId(by)) return { ...same, result: refuse('seat_invalid') };
      const reason = op['reason'];
      if (typeof reason !== 'string' || reason.length < MIN_PIN_REASON_LENGTH || reason.length > MAX_PIN_REASON_LENGTH) return { ...same, result: refuse('reason_required') };
      if (!isHash(op['hash'])) return { ...same, result: refuse('pin_hash_malformed') };
      if (!isTime(op['at'])) return { ...same, result: refuse('pin_input_malformed', { detail: 'at' }) };
      if (state.loaded === null) return { ...same, result: refuse('pin_not_loaded') };
      // the step pins what the seat computed, never an arbitrary hash
      if (op['hash'] !== state.loaded) return { ...same, result: refuse('pin_hash_not_loaded') };
      if (state.pin === op['hash']) return { result: { ok: true, idempotent: true, phase: 'pinned' }, state };
      const previous = state.pin;
      const next: PinState = { ...state, pin: op['hash'] };
      return {
        result: {
          ok: true,
          phase: 'pinned',
          previous,
          log: { kind: 'policy.pinned', at: op['at'], payload: { seat: state.seat, policyHash: op['hash'], by, reason, previous } },
        },
        state: next,
      };
    }
  }
}

/** a session of operations for one seat, as the policy-pin vectors describe it; the answer carries every result and the pin at the end */
export function runPinOps(input: unknown): { results: PinResult[]; pin: string | null } | { ok: false; reason: 'pin_input_malformed'; detail?: string } {
  if (!isPlainObject(input)) return { ok: false, reason: 'pin_input_malformed', detail: 'shape' };
  const keys = Object.keys(input);
  if (keys.length !== 2 || !keys.includes('seat') || !keys.includes('ops')) return { ok: false, reason: 'pin_input_malformed', detail: 'shape' };
  if (!isSeatId(input['seat'])) return { ok: false, reason: 'pin_input_malformed', detail: 'seat' };
  const ops = input['ops'];
  if (!Array.isArray(ops)) return { ok: false, reason: 'pin_input_malformed', detail: 'ops' };
  let state = emptyPinState(input['seat']);
  const results: PinResult[] = [];
  for (const op of ops) {
    const r = applyPinOp(state, op);
    results.push(r.result);
    state = r.state;
  }
  return { results, pin: state.pin };
}
