/**
 * The pause state machine (DECISION.md section 6, C4; DE-24 to DE-28). A pause has a scope (`seat` or `subject`), an id,
 * who set it (a named seat), a reason of at least the configured minimum length, and the time it was set. It is
 * enforced before ANY signature, a reject vote included. Pure: state in, result and new state out; time is an argument;
 * the state is plain data that serialises to canonical text and reloads equal, so that the signer can persist it and read
 * it at start and before each signature (the real restart of a process is DAX-4S, DE-28).
 *
 * The module records who paused and who resumed; WHO MAY pause or resume is an authorization of the caller (the signer
 * and the Console know which authenticated seat is acting) and is not decided here: this module adds no authority.
 * A resume lifts only its own scope and id. A state that cannot be read signs nothing (`pause_state_unreadable`), never
 * "not paused". The persisted text alone cannot show that a record was dropped from it; `checkPersistedPause` folds
 * the pause.set and pause.clear entries of a verified decision log and refuses a state that differs (DE-78, finding DAX4A-F6).
 */
import { CoreError, hasLoneSurrogate } from './bytes.js';
import { canonicalize, parseJson } from './jcs.js';
import { isAdiUrl } from './grant-profile.js';
import { closedObject, dataArray, dataObject, isSeatId, isTime } from './decision-identity.js';

export const PAUSE_SCOPES = ['seat', 'subject'] as const;
export type PauseScope = (typeof PAUSE_SCOPES)[number];
export const DEFAULT_MIN_REASON_LENGTH = 10;
export const MAX_REASON_LENGTH = 2000;
const MAX_PAUSES = 100000;

export interface PauseRecord { scope: PauseScope; id: string; by: string; reason: string; at: number }
export interface PauseState { version: 1; pauses: PauseRecord[] }
export interface PauseOptions { minReasonLength?: number }

export type PauseEvent =
  | { kind: 'pause.set'; payload: { scope: PauseScope; id: string; by: string; reason: string } }
  | { kind: 'pause.clear'; payload: { scope: PauseScope; id: string; by: string; reason: string; pausedBy: string; pausedAt: number } };

export type PauseChange =
  | { ok: true; state: PauseState; event: PauseEvent }
  /** pausing what is paused is not a refusal: the answer is idempotent, the first record stays, no second event is logged (pz-17) */
  | { ok: true; state: PauseState; idempotent: true; status: 'already_paused' }
  | { ok: false; reason: string; detail?: string };

export type SigningVerdict = { ok: true } | { ok: false; reason: 'paused'; scope: PauseScope; id: string; by: string; since: number } | { ok: false; reason: string; detail?: string };

const refuse = (reason: string, detail?: string): { ok: false; reason: string; detail?: string } => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });

export const emptyPauseState = (): PauseState => ({ version: 1, pauses: [] });

const byKey = (a: { scope: string; id: string }, b: { scope: string; id: string }): number => (a.scope === b.scope ? (a.id < b.id ? -1 : a.id > b.id ? 1 : 0) : a.scope < b.scope ? -1 : 1);
const isScope = (v: unknown): v is PauseScope => v === 'seat' || v === 'subject';
const idFits = (scope: PauseScope, id: unknown): id is string => (scope === 'seat' ? isSeatId(id) : typeof id === 'string' && isAdiUrl(id));
const reasonLength = (s: string): number => Array.from(s.trim()).length;

function readRecord(v: unknown, minReason: number): PauseRecord | string {
  const o = closedObject(v, ['scope', 'id', 'by', 'reason', 'at']);
  if (o === null) return 'record';
  if (!isScope(o['scope']) || !idFits(o['scope'], o['id'])) return 'target';
  if (!isSeatId(o['by'])) return 'by';
  if (typeof o['reason'] !== 'string' || o['reason'].length > MAX_REASON_LENGTH || hasLoneSurrogate(o['reason']) || reasonLength(o['reason']) < minReason) return 'reason';
  if (!isTime(o['at'])) return 'at';
  return { scope: o['scope'], id: o['id'], by: o['by'], reason: o['reason'], at: o['at'] };
}

/** a validated, canonically ordered copy of a state, or a named refusal; `minReason` is the floor the stored reasons must meet */
function readState(v: unknown, minReason: number): { ok: true; state: PauseState } | { ok: false; reason: string; detail: string } {
  const o = closedObject(v, ['version', 'pauses']);
  if (o === null) return { ok: false, reason: 'pause_state_malformed', detail: 'shape' };
  if (o['version'] !== 1) return { ok: false, reason: 'pause_state_version', detail: String(o['version']) };
  const list = dataArray(o['pauses'], MAX_PAUSES);
  if (list === null) return { ok: false, reason: 'pause_state_malformed', detail: 'pauses' };
  const pauses: PauseRecord[] = [];
  for (let i = 0; i < list.length; i++) {
    const r = readRecord(list[i], minReason);
    if (typeof r === 'string') return { ok: false, reason: 'pause_state_malformed', detail: 'record ' + i + ' ' + r };
    const prev = pauses[pauses.length - 1];
    if (prev !== undefined) {
      const c = byKey(prev, r);
      if (c === 0) return { ok: false, reason: 'pause_state_duplicate', detail: r.scope + ' ' + r.id };
      if (c > 0) return { ok: false, reason: 'pause_state_not_ordered', detail: 'record ' + i };
    }
    pauses.push(r);
  }
  return { ok: true, state: { version: 1, pauses } };
}

function minLength(opts: PauseOptions | undefined): number | null {
  const m = opts === undefined ? DEFAULT_MIN_REASON_LENGTH : opts.minReasonLength === undefined ? DEFAULT_MIN_REASON_LENGTH : opts.minReasonLength;
  return typeof m === 'number' && Number.isSafeInteger(m) && m >= 1 && m <= MAX_REASON_LENGTH ? m : null;
}

interface Op { scope: PauseScope; id: string; by: string; reason: string; at: number }

/** field order of the refusals: shape, scope, id, seat, reason, time */
function readOp(v: unknown, min: number): { ok: true; op: Op } | { ok: false; reason: string; detail?: string } {
  const o = closedObject(v, ['id', 'at'], ['scope', 'by', 'reason']);
  if (o === null) return refuse('pause_input_malformed', 'shape');
  if (!isScope(o['scope'])) return refuse('pause_scope_invalid');
  if (!idFits(o['scope'], o['id'])) return refuse('pause_input_malformed', 'id');
  const by = o['by'];
  if (typeof by !== 'string' || by.trim() === '') return refuse('seat_required');
  if (!isSeatId(by)) return refuse('seat_invalid');
  const reason = o['reason'];
  if (reason === undefined || reason === null || reason === '') return refuse('reason_required');
  if (typeof reason !== 'string' || reason.length > MAX_REASON_LENGTH || hasLoneSurrogate(reason)) return refuse('pause_input_malformed', 'reason');
  if (reasonLength(reason) < min) return refuse('reason_required');
  if (!isTime(o['at'])) return refuse('pause_input_malformed', 'at');
  return { ok: true, op: { scope: o['scope'], id: o['id'], by, reason, at: o['at'] } };
}

function open(state: unknown, opts: PauseOptions | undefined): { ok: true; state: PauseState; min: number } | { ok: false; reason: string; detail?: string } {
  const min = minLength(opts);
  if (min === null) return refuse('pause_input_malformed', 'minReasonLength');
  const s = readState(state, 1);
  if (!s.ok) return refuse(s.reason, s.detail);
  return { ok: true, state: s.state, min };
}

/** Set a pause. A pause that is already set is the idempotent answer `already_paused` (not a refusal): the first record, who and when, stays. */
export function applyPause(state: unknown, op: unknown, opts?: PauseOptions): PauseChange {
  const o = open(state, opts);
  if (!o.ok) return o;
  const parsed = readOp(op, o.min);
  if (!parsed.ok) return parsed;
  const f = parsed.op;
  if (o.state.pauses.some((p) => p.scope === f.scope && p.id === f.id)) return { ok: true, state: o.state, idempotent: true, status: 'already_paused' };
  const pauses = [...o.state.pauses, { scope: f.scope, id: f.id, by: f.by, reason: f.reason, at: f.at }].sort(byKey);
  return { ok: true, state: { version: 1, pauses }, event: { kind: 'pause.set', payload: { scope: f.scope, id: f.id, by: f.by, reason: f.reason } } };
}

/** Resume one scope and id, with a named seat and a reason. Another scope or id stays paused. */
export function applyResume(state: unknown, op: unknown, opts?: PauseOptions): PauseChange {
  const o = open(state, opts);
  if (!o.ok) return o;
  const parsed = readOp(op, o.min);
  if (!parsed.ok) return parsed;
  const f = parsed.op;
  const found = o.state.pauses.find((p) => p.scope === f.scope && p.id === f.id);
  if (found === undefined) return refuse('not_paused', f.scope + ' ' + f.id);
  const pauses = o.state.pauses.filter((p) => p !== found);
  return {
    ok: true,
    state: { version: 1, pauses },
    event: { kind: 'pause.clear', payload: { scope: f.scope, id: f.id, by: f.by, reason: f.reason, pausedBy: found.by, pausedAt: found.at } },
  };
}

/**
 * May this seat sign this vote about this subject? A paused seat or subject signs NOTHING, a reject vote included. The
 * subject is stated explicitly: an ADI, or null for a signature that involves no subject (a Grant-governed seat always
 * has one: the binding refuses `subject_unproven` before this is asked). The seat pause is reported before the subject's.
 */
export function checkSigning(state: unknown, request: unknown): SigningVerdict {
  const r = closedObject(request, ['seat', 'subject', 'vote']);
  if (r === null || !isSeatId(r['seat']) || (r['subject'] !== null && !(typeof r['subject'] === 'string' && isAdiUrl(r['subject']))) || (r['vote'] !== 'approve' && r['vote'] !== 'reject')) return refuse('sign_malformed');
  const s = readState(state, 1);
  if (!s.ok) return refuse('pause_state_unreadable', s.reason);
  const hit = s.state.pauses.find((p) => p.scope === 'seat' && p.id === r['seat']) ?? (r['subject'] === null ? undefined : s.state.pauses.find((p) => p.scope === 'subject' && p.id === r['subject']));
  if (hit !== undefined) return { ok: false, reason: 'paused', scope: hit.scope, id: hit.id, by: hit.by, since: hit.at };
  return { ok: true };
}

/** the canonical text of a state (RFC 8785), the form the signer persists; an invalid state is refused by throwing a CoreError */
export function serializePauseState(state: PauseState): string {
  const s = readState(state, 1);
  if (!s.ok) throw new CoreError(s.reason, s.detail);
  return canonicalize(s.state);
}

/** Reads a persisted state strictly (duplicate members, unknown members, an empty reason, an unordered or repeated record are all refused). */
export function parsePauseState(text: string): { ok: true; state: PauseState } | { ok: false; reason: string; detail?: string } {
  let parsed: unknown;
  try {
    parsed = parseJson(text);
  } catch (e) {
    if (e instanceof CoreError) return refuse('pause_state_unparseable', e.code);
    throw e;
  }
  // the minimum length is enforced when a pause is set, not when it is reloaded: a later change of the configured minimum must never make a stored pause unreadable
  const s = readState(parsed, 1);
  return s.ok ? s : refuse(s.reason, s.detail);
}

/**
 * One operation of a pause session: { op: 'pause' | 'resume', scope, id, by, reason, at }, { op: 'sign', seat, subject,
 * vote } or { op: 'restart' } (the state is serialised and read back, as after a restart of the process). Returns the
 * answer and the state after it (the state it was given when the operation is refused). An operation that is none of
 * these is pause_op_unknown and changes nothing (DE-74).
 */
export function applyPauseOp(state: PauseState, op: unknown, opts?: PauseOptions): { result: Record<string, unknown>; state: PauseState } {
  const o = dataObject(op);
  const name = o === null ? undefined : o['op'];
  if (o === null || (name !== 'pause' && name !== 'resume' && name !== 'sign' && name !== 'restart')) return { result: refuse('pause_op_unknown'), state };
  const rest: Record<string, unknown> = {};
  for (const k of Object.keys(o)) if (k !== 'op') rest[k] = o[k];
  if (name === 'sign') return { result: checkSigning(state, rest), state };
  if (name === 'restart') {
    if (Object.keys(rest).length > 0) return { result: refuse('pause_op_unknown'), state };
    const s = readState(state, 1);
    if (!s.ok) return { result: refuse('pause_state_unreadable', s.reason), state };
    const back = parsePauseState(serializePauseState(s.state));
    return back.ok ? { result: { ok: true, restarted: true, pauses: back.state.pauses.length }, state: back.state } : { result: refuse('pause_state_unreadable', back.reason), state };
  }
  const r = name === 'pause' ? applyPause(state, rest, opts) : applyResume(state, rest, opts);
  return { result: r, state: r.ok ? r.state : state };
}

/** the persisted text is read before the check; an unreadable text signs nothing */
export function checkSigningFromText(text: string, request: unknown): SigningVerdict {
  const s = parsePauseState(text);
  if (!s.ok) return refuse('pause_state_unreadable', s.reason);
  return checkSigning(s.state, request);
}

/**
 * A session of operations (DE-74): { ops: [...], state? } run in order from the given state (default empty) through
 * applyPauseOp; returns every answer and the final state. Operations that are not a list, or an input that is not an
 * operations object, are pause_input_malformed; a given state that is not readable is refused by its own name.
 */
export function runPauseOps(input: unknown): { results: Array<Record<string, unknown>>; state: PauseState } | { ok: false; reason: string; detail?: string } {
  const inp = closedObject(input, ['ops'], ['state']);
  if (inp === null) return refuse('pause_input_malformed');
  const ops = dataArray(inp['ops'], 0xffffffff);
  if (ops === null) return refuse('pause_input_malformed');
  let state = emptyPauseState();
  if (inp['state'] !== undefined) {
    const s = readState(inp['state'], 1);
    if (!s.ok) return refuse(s.reason, s.detail);
    state = s.state;
  }
  const results: Array<Record<string, unknown>> = [];
  for (const op of ops) {
    const r = applyPauseOp(state, op);
    state = r.state;
    results.push(r.result);
  }
  return { results, state };
}

/**
 * A persisted pause state against its pause log (DE-78): { state: { version?, pauses: [...] }, log: [...] }. The state must
 * equal the fold of the pause.set and pause.clear entries of the log (a set of a pause that is already set changes nothing,
 * as the operation is idempotent). Refused by name: pause_state_malformed or pause_state_version (a state of the wrong
 * shape), pause_state_duplicate (two entries for one scope and id), pause_log_malformed (a log that is not a list, an entry
 * of an unknown pause kind, a payload that is not a scope and id, a clear of what is not paused or that names another
 * pause), pause_state_log_mismatch (the state is not the fold). Entries of other kinds are ignored: the log holds every
 * kind. When an entry also carries who set the pause, why and when (by, reason, at), the state record must agree with
 * it (DE-102): an edited record is a mismatch that names the member (`member`: by, reason or at); a member the entry does not
 * carry is not compared, and a state with a version member is accepted only when it is the number 1 (pause_state_version).
 * The log itself is verified by verifyLog against a pinned head by the caller.
 */
export function checkPersistedPause(input: unknown): { ok: true; pauses: number } | { ok: false; reason: string; detail?: string; member?: 'by' | 'reason' | 'at' } {
  const inp = closedObject(input, ['state', 'log']);
  if (inp === null) return refuse('pause_input_malformed', 'shape');
  const st = closedObject(inp['state'], ['pauses'], ['version']);
  if (st === null) return refuse('pause_state_malformed', 'shape');
  if (st['version'] !== undefined && st['version'] !== 1) return refuse('pause_state_version', String(st['version']));
  const list = dataArray(st['pauses'], MAX_PAUSES);
  if (list === null) return refuse('pause_state_malformed', 'pauses');
  const have = new Map<string, PauseRecord>();
  for (let i = 0; i < list.length; i++) {
    const r = readRecord(list[i], 1);
    if (typeof r === 'string') return refuse('pause_state_malformed', 'record ' + i + ' ' + r);
    const key = r.scope + ' ' + r.id;
    if (have.has(key)) return refuse('pause_state_duplicate', key);
    have.set(key, r);
  }

  const log = dataArray(inp['log'], 0xffffffff);
  if (log === null) return refuse('pause_log_malformed', 'log');
  const folded = new Map<string, { by?: string; reason?: string; at?: number }>();
  for (let i = 0; i < log.length; i++) {
    const e = dataObject(log[i]);
    if (e === null || typeof e['kind'] !== 'string') return refuse('pause_log_malformed', 'entry ' + i);
    if (!e['kind'].startsWith('pause.')) continue;
    if (e['kind'] !== 'pause.set' && e['kind'] !== 'pause.clear') return refuse('pause_log_malformed', 'entry ' + i + ' ' + e['kind']);
    const p = dataObject(e['payload']);
    if (p === null || !isScope(p['scope']) || !idFits(p['scope'], p['id'])) return refuse('pause_log_malformed', 'entry ' + i + ' payload');
    if (e['at'] !== undefined && !isTime(e['at'])) return refuse('pause_log_malformed', 'entry ' + i + ' at');
    if (p['at'] !== undefined && !isTime(p['at'])) return refuse('pause_log_malformed', 'entry ' + i + ' payload at');
    if (p['by'] !== undefined && !isSeatId(p['by'])) return refuse('pause_log_malformed', 'entry ' + i + ' by');
    if (p['reason'] !== undefined && (typeof p['reason'] !== 'string' || p['reason'].length > MAX_REASON_LENGTH || hasLoneSurrogate(p['reason']))) return refuse('pause_log_malformed', 'entry ' + i + ' reason');
    const key = p['scope'] + ' ' + p['id'];
    if (e['kind'] === 'pause.set') {
      if (!folded.has(key)) folded.set(key, { ...(p['by'] !== undefined ? { by: p['by'] as string } : {}), ...(p['reason'] !== undefined ? { reason: p['reason'] as string } : {}), ...(p['at'] !== undefined ? { at: p['at'] as number } : e['at'] !== undefined ? { at: e['at'] as number } : {}) });
    } else {
      const was = folded.get(key);
      if (was === undefined) return refuse('pause_log_malformed', 'entry ' + i + ' clears what is not paused');
      if ((p['pausedBy'] !== undefined && was.by !== undefined && p['pausedBy'] !== was.by) || (p['pausedAt'] !== undefined && was.at !== undefined && p['pausedAt'] !== was.at)) return refuse('pause_log_malformed', 'entry ' + i + ' clears another pause');
      folded.delete(key);
    }
  }
  if (folded.size !== have.size) return refuse('pause_state_log_mismatch', 'the state holds ' + have.size + ' pauses, the log folds to ' + folded.size);
  for (const [key, f] of folded) {
    const r = have.get(key);
    if (r === undefined) return refuse('pause_state_log_mismatch', 'the log set ' + key + ', the state does not hold it');
    for (const member of ['by', 'reason', 'at'] as const) {
      if (f[member] !== undefined && f[member] !== r[member]) return { ok: false, reason: 'pause_state_log_mismatch', detail: key + ' ' + member + ' differs from the log', member };
    }
  }
  return { ok: true, pauses: have.size };
}
