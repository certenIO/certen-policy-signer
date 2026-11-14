/**
 * The leaf expiry bound (DECISION.md section 2, decision OQ-DAX4S-19, finding DAX6C-F1; DE-87, DE-88). The signer votes before
 * the validator commits the intent, so it cannot read the on-chain leaf's `notAfter`; what it can know is the header deadline
 * of the transaction and the legs' declared deadlines, and a transaction cannot commit after its header deadline, so
 *
 *   leafExpiry = min( every declared leg deadline (above 0), floor(header expiresAt) + settlementHorizonSeconds )
 *
 * is never below the real `notAfter` of a member that waits on no predecessor. It is an UPPER bound: everything built on it
 * errs towards a longer hold and a longer exposure window, never a shorter one. Pure functions of their arguments: no clock.
 *
 *   leafExpiryBound({ legDeadlines, headerExpiresAt, horizonSeconds }): the number a signer forwards as `leafExpiry`, absent
 *   (leaf_expiry_unavailable) when neither a leg deadline nor a header deadline exists, and refused for a horizon below the
 *   validator's one hour (leaf_horizon_below_minimum), a header deadline that is not an exact UTC instant
 *   (leaf_header_time_invalid) and a malformed input (leaf_expiry_input_malformed). The bound is claimed for a ONE-LEG
 *   transaction only (DE-88; the legs are counted by the binding check, DE-76).
 *   validatorWindow({ legDeadlines, commitTime, sequencePosition }): the validator's window of a member, notBefore = the commit
 *   time, notAfter = the earlier of the declared leg deadlines and commit + (position + 1) hours (`batch_mempool.go` Window and
 *   `batch_sequence.go` settlementHorizon, validator 15814ad5; maxGasDeferral is one hour).
 *   leafBoundHolds(...): whether the bound is sound against that window for a commit time; refused when the commit would be
 *   after the header deadline (the premise of the bound, live test DAX-4-A25).
 */
import { isPlainObject } from './bytes.js';

/** the validator's horizon of a member that waits on no predecessor: maxGasDeferral, one hour (DE-88) */
export const VALIDATOR_HORIZON_SECONDS = 3600;

export type LeafBasis = 'leg_deadline' | 'header_plus_horizon';
export type LeafBoundResult =
  | { ok: true; leafExpiry: number; basis: LeafBasis }
  | { ok: false; reason: 'leaf_expiry_unavailable' | 'leaf_horizon_below_minimum' | 'leaf_header_time_invalid' | 'leaf_expiry_input_malformed'; detail?: string };

const refuse = <R extends string>(reason: R, detail?: string): { ok: false; reason: R; detail?: string } => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
const UTC_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/;

/** floor of the Unix seconds of an exact UTC instant (`...Z`, no offset), or null when the text is not one */
function utcSeconds(text: string): number | null {
  const m = UTC_RE.exec(text);
  if (m === null) return null;
  const [y, mo, d, h, mi, s] = [m[1]!, m[2]!, m[3]!, m[4]!, m[5]!, m[6]!].map(Number) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return null;
  // a day that does not exist in its month (February 30th) is not an instant
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]!;
  if (d > monthDays) return null;
  // days since 1970-01-01 by the civil-from-days arithmetic (proleptic Gregorian), no Date object: the core reads no clock
  const yy = mo <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  const days = era * 146097 + doe - 719468;
  const seconds = days * 86400 + h * 3600 + mi * 60 + s;
  return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : null;
}

interface Read { deadlines: number[]; header: string | null; horizon: number }
function readBoundInput(input: unknown): Read | LeafBoundResult {
  if (!isPlainObject(input)) return refuse('leaf_expiry_input_malformed', 'shape');
  const legs = input['legDeadlines'];
  if (!Array.isArray(legs) || !legs.every(isCount)) return refuse('leaf_expiry_input_malformed', 'legDeadlines');
  const header = input['headerExpiresAt'];
  if (header !== null && typeof header !== 'string') return refuse('leaf_expiry_input_malformed', 'headerExpiresAt');
  const horizon = input['horizonSeconds'];
  if (!isCount(horizon)) return refuse('leaf_expiry_input_malformed', 'horizonSeconds');
  return { deadlines: legs as number[], header, horizon };
}
const isRead = (r: Read | LeafBoundResult): r is Read => !('ok' in r);

export function leafExpiryBound(input: unknown): LeafBoundResult {
  const r = readBoundInput(input);
  if (!isRead(r)) return r;
  // a seat horizon below the validator's would understate the bound: refused, never used (DE-88)
  if (r.horizon < VALIDATOR_HORIZON_SECONDS) return refuse('leaf_horizon_below_minimum', String(r.horizon));
  let headerSide: number | null = null;
  if (r.header !== null) {
    const t = utcSeconds(r.header);
    if (t === null) return refuse('leaf_header_time_invalid');
    headerSide = t + r.horizon;
  }
  const declared = r.deadlines.filter((d) => d > 0);
  const legSide = declared.length === 0 ? null : Math.min(...declared);
  if (legSide === null && headerSide === null) return refuse('leaf_expiry_unavailable');
  // a tie names the leg deadline as the basis
  if (legSide !== null && (headerSide === null || legSide <= headerSide)) return { ok: true, leafExpiry: legSide, basis: 'leg_deadline' };
  return { ok: true, leafExpiry: headerSide!, basis: 'header_plus_horizon' };
}

export type ValidatorWindowResult =
  | { ok: true; notBefore: number; notAfter: number }
  | { ok: false; reason: 'leaf_expiry_input_malformed'; detail?: string };

export function validatorWindow(input: unknown): ValidatorWindowResult {
  if (!isPlainObject(input)) return refuse('leaf_expiry_input_malformed', 'shape');
  const legs = input['legDeadlines'];
  if (!Array.isArray(legs) || !legs.every(isCount)) return refuse('leaf_expiry_input_malformed', 'legDeadlines');
  const commit = input['commitTime'];
  const pos = input['sequencePosition'];
  if (!isCount(commit)) return refuse('leaf_expiry_input_malformed', 'commitTime');
  if (!isCount(pos)) return refuse('leaf_expiry_input_malformed', 'sequencePosition');
  const declared = (legs as number[]).filter((d) => d > 0);
  const horizonEnd = commit + (pos + 1) * VALIDATOR_HORIZON_SECONDS;
  return { ok: true, notBefore: commit, notAfter: declared.length === 0 ? horizonEnd : Math.min(horizonEnd, ...declared) };
}

export type BoundHoldsResult =
  | { ok: true; notAfter: number; bound: number; sound: boolean }
  | { ok: false; reason: 'leaf_expiry_unavailable' | 'leaf_horizon_below_minimum' | 'leaf_header_time_invalid' | 'leaf_expiry_input_malformed' | 'commit_after_header_expiry'; detail?: string };

/**
 * Is the bound an upper bound of the validator's notAfter for a member at `sequencePosition` committed at `commitTime`? True
 * for a member that waits on no predecessor (position 0); at position 1 and above the real notAfter lies up to (position + 1)
 * hours past the commit, above the bound: that is why the bound is claimed for one-leg transactions only (DE-88).
 */
export function leafBoundHolds(input: unknown): BoundHoldsResult {
  if (!isPlainObject(input)) return refuse('leaf_expiry_input_malformed', 'shape');
  const bound = leafExpiryBound({ legDeadlines: input['legDeadlines'], headerExpiresAt: input['headerExpiresAt'], horizonSeconds: input['horizonSeconds'] });
  if (!bound.ok) return bound;
  const header = input['headerExpiresAt'];
  const commit = input['commitTime'];
  if (typeof header === 'string' && isCount(commit)) {
    const t = utcSeconds(header);
    // the premise of the bound: no transaction commits after its header deadline (live test DAX-4-A25)
    if (t !== null && commit > t) return refuse('commit_after_header_expiry');
  }
  const window = validatorWindow({ legDeadlines: input['legDeadlines'], commitTime: commit, sequencePosition: input['sequencePosition'] });
  if (!window.ok) return window;
  return { ok: true, notAfter: window.notAfter, bound: bound.leafExpiry, sound: window.notAfter <= bound.leafExpiry };
}
