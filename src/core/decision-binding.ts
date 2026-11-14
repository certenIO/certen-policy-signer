/**
 * The binding of a decision to the transaction it is about to sign (DECISION.md sections 3 and 4; DE-01 to DE-09, DE-54,
 * DE-61; GR-34, GR-35, GR-37). A pure function: the state (what the signer persists: the consumed nonces, the head of the
 * Grant lineage it read, its pins) and the clock reading come in as arguments, a verdict and the NEW state come out.
 * The module refuses to sign and does nothing else: it casts no vote, cancels nothing and touches no account (DE-10); it
 * adds no authority. The caller MUST persist the returned state (the consumed nonce) BEFORE it signs, so that a crash
 * between the two leaves the decision spent (DE-03).
 *
 * The refusals are evaluated in this fixed order, so that two implementations name the same reason:
 *   policy_pin_missing (a bound seat with no pin decides nothing: judged for every step before anything of it is read, a deny
 *   that would become a reject vote included, DE-93), presented_malformed, multi_leg_unsupported, raw_not_allowed,
 *   decision_malformed, nonce_malformed, decision_not_yet_valid, decision_expired, decision_window_too_long, request_mismatch,
 *   grant_required, grant_hash_mismatch, grant_unverified, grant_superseded, subject_unproven, grant_subject_mismatch,
 *   policy_hash_mismatch, seat_mismatch, approver_not_authorized, decision_replayed.
 * The pin is REQUIRED (decision OQ-DAX2-1, DE-93): expectedPolicyHash null is policy_pin_missing. The only unpinned judging is
 * the vector harness in src/testing, which is not exported from this package and reaches this module through its public
 * functions only (DE-93, DAX-4-A28).
 * The raw kind (decision RAW, DE-91): a presented request of kind raw is refused as raw_not_allowed unless the seat's
 * allowRaw is the boolean true (absent is false), judged right after the legs are counted and before the decision is read.
 * Input that is not decision data is refused before the order starts, by its own name: binding_input_malformed (the call
 * or the clock), binding_state_malformed (the state); then presented_malformed (the transaction as the signer decoded it),
 * decision_malformed (a member of the record other than its nonce) and nonce_malformed (the nonce is not 0x and 64 lowercase
 * hex) in that order, as step 1 of DECISION.md section 4 (DE-74). A Grant that is NAMED is checked by every seat:
 * grant_required applies only to a seat that requires one; a seat that does not still refuses a decision and a transaction
 * that disagree about a Grant (grant_hash_mismatch) and applies the subject join whenever a Grant is named; when the
 * authenticated head or its subject is not available the answer is grant_unverified, never an allow (DE-71, DE-72).
 * The request hash binds ONE action, so a multi-leg intent cannot be bound by one decision: the presented legCount must be
 * a positive integer (else presented_malformed) and a legCount other than 1 is multi_leg_unsupported (DE-76), judged right
 * after the presented transaction is read and before the decision (the specification names no place; finding DAX4A-F16).
 * A presented transaction that declares no legCount is a single action: that is for fixtures, the production caller must
 * derive legCount from the transaction's legs and always supply it.
 */
import { CoreError, hasLoneSurrogate } from './bytes.js';
import { SUBJECT_TYPES, isAdiUrl, type SubjectType } from './grant-profile.js';
import { hashDecision, hashRequest } from './hashes.js';
import { closedObject, dataArray, dataObject, isHash, isIdentity, isSeatId, isTime } from './decision-identity.js';

export const DECISION_SCHEMA = 'certen.decision/v1';
const NO_CAP = 0xffffffff;
const MAX_REASON = 4096;
const MAX_APPROVERS = 10000;

export interface BindingSubject { adi: string; type: SubjectType }

/** What the signer persists for one seat. Closed: no other member is accepted. */
export interface BindingState {
  /** a seat configured to require a Grant refuses a transaction or a decision that names none */
  requireGrant: boolean;
  /** the grant hash of the head of the lineage as read from Accumulate at decision time, or null when none was read */
  grantHeadHash: string | null;
  /** the subject and type of that head Grant */
  grantHeadSubject: BindingSubject | null;
  /** the policy hash the seat pins (DE-93): REQUIRED, null is policy_pin_missing for every step */
  expectedPolicyHash: string | null;
  /** the seat setting allowRaw (DE-91): absent means false; a raw request is refused as raw_not_allowed unless it is the boolean true */
  allowRaw?: boolean;
  /** identities (key or ADI) the seat authorises to decide */
  authorizedApprovers: string[];
  /** every nonce ever consumed or voided, never dropped */
  consumed: string[];
  /** the cap on expiresAt - issuedAt, in seconds */
  maxWindowSeconds: number;
}

export interface DecisionRecord {
  schema: 'certen.decision/v1';
  decision: 'approve' | 'deny';
  requestHash: string;
  grantHash: string | null;
  policyHash: string;
  seat: string;
  approver: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  reason: string;
}

export type BindResult =
  | {
      ok: true;
      verb: 'approve' | 'deny';
      requestHash: string;
      decisionHash: string;
      nonce: string;
      grantHash: string | null;
      policyHash: string;
      /** always true here: a seat with no pin is policy_pin_missing (DE-93) */
      policyPinned: boolean;
      approver: string;
      seat: string;
      /** the state with the nonce consumed: persist it before signing */
      state: BindingState;
      /** the decision-log entry of the consumption (DECISION.md section 9: decision.consumed) */
      event: { kind: 'decision.consumed'; payload: { requestHash: string; nonce: string } };
    }
  | { ok: false; reason: string; detail?: string };

const refuse = (reason: string, detail?: string): { ok: false; reason: string; detail?: string } => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });

function readSubject(v: unknown): BindingSubject | null | undefined {
  if (v === null) return null;
  const o = closedObject(v, ['adi', 'type']);
  if (o === null || !isAdiUrl(o['adi']) || typeof o['type'] !== 'string' || !(SUBJECT_TYPES as readonly string[]).includes(o['type'])) return undefined;
  return { adi: o['adi'], type: o['type'] as SubjectType };
}

export type BindingStateResult = { ok: true; state: BindingState } | { ok: false; reason: 'binding_state_malformed'; detail: string };

/** a validated copy of the state, or a named refusal */
export function validateBindingState(v: unknown): BindingStateResult {
  const bad = (detail: string): BindingStateResult => ({ ok: false, reason: 'binding_state_malformed', detail });
  const o = closedObject(v, ['requireGrant', 'grantHeadHash', 'grantHeadSubject', 'expectedPolicyHash', 'authorizedApprovers', 'consumed', 'maxWindowSeconds'], ['allowRaw']);
  if (o === null) return bad('shape');
  if (o['allowRaw'] !== undefined && typeof o['allowRaw'] !== 'boolean') return bad('allowRaw');
  if (typeof o['requireGrant'] !== 'boolean') return bad('requireGrant');
  const head = o['grantHeadHash'];
  if (head !== null && !isHash(head)) return bad('grantHeadHash');
  const subject = readSubject(o['grantHeadSubject']);
  if (subject === undefined) return bad('grantHeadSubject');
  const pin = o['expectedPolicyHash'];
  if (pin !== null && !isHash(pin)) return bad('expectedPolicyHash');
  const approvers = dataArray(o['authorizedApprovers'], MAX_APPROVERS);
  if (approvers === null || !approvers.every(isIdentity)) return bad('authorizedApprovers');
  const consumed = dataArray(o['consumed'], NO_CAP);
  if (consumed === null || !consumed.every(isHash)) return bad('consumed');
  const max = o['maxWindowSeconds'];
  if (typeof max !== 'number' || !Number.isSafeInteger(max) || max < 1) return bad('maxWindowSeconds');
  return {
    ok: true,
    state: {
      requireGrant: o['requireGrant'],
      grantHeadHash: head,
      grantHeadSubject: subject,
      expectedPolicyHash: pin,
      authorizedApprovers: approvers as string[],
      consumed: consumed as string[],
      maxWindowSeconds: max,
      ...(o['allowRaw'] === undefined ? {} : { allowRaw: o['allowRaw'] }),
    },
  };
}

/**
 * The decision record is a closed object; the approver is an identity, never a display name. A member other than the nonce
 * that is wrong is decision_malformed; only when the rest is valid is a nonce that is not exact lowercase hex
 * nonce_malformed (DE-74).
 */
function readDecision(v: unknown): DecisionRecord | 'decision_malformed' | 'nonce_malformed' {
  const o = closedObject(v, ['schema', 'decision', 'requestHash', 'grantHash', 'policyHash', 'seat', 'approver', 'nonce', 'issuedAt', 'expiresAt', 'reason']);
  if (o === null) return 'decision_malformed';
  const { schema, decision, requestHash, grantHash, policyHash, seat, approver, nonce, issuedAt, expiresAt, reason } = o;
  if (schema !== DECISION_SCHEMA) return 'decision_malformed';
  if (decision !== 'approve' && decision !== 'deny') return 'decision_malformed';
  if (!isHash(requestHash) || !isHash(policyHash)) return 'decision_malformed';
  if (grantHash !== null && !isHash(grantHash)) return 'decision_malformed';
  if (!isSeatId(seat) || !isIdentity(approver)) return 'decision_malformed';
  if (!isTime(issuedAt) || !isTime(expiresAt) || expiresAt <= issuedAt) return 'decision_malformed';
  if (typeof reason !== 'string' || reason.length > MAX_REASON || hasLoneSurrogate(reason)) return 'decision_malformed';
  if (!isHash(nonce)) return 'nonce_malformed';
  return { schema, decision, requestHash, grantHash, policyHash, seat, approver, nonce, issuedAt, expiresAt, reason };
}

interface Presented { requestHash: string; kind: string; grantRefHash: string | null; seat: string; subject: BindingSubject | null; legCount: number }

/**
 * The transaction as the signer decoded it: its request hash is RECOMPUTED here, never taken from the producer.
 * `operationId` in the request is the VALIDATOR's operation id (CertenIntent.OperationID: the canonical 4-blob hash of the
 * pending transaction's data entry, the value bound into the batch leaf; DECISION.md section 2). It is taken as an opaque
 * 0x-plus-64-hex input like every other request member, and it is neither the blob-0 intent_id UUID nor the blob-3
 * intent_hash. Recomputing it from the four blobs is the caller's test (DAX-4-A17, DAX-4S and DAX-4C), not this module's.
 */
function readPresented(v: unknown): Presented | null {
  const o = closedObject(v, ['request', 'grantRefHash', 'seat', 'subject'], ['legCount']);
  if (o === null) return null;
  const legs = o['legCount'] === undefined ? 1 : o['legCount'];
  if (typeof legs !== 'number' || !Number.isSafeInteger(legs) || legs < 1) return null;
  const request = dataObject(o['request']);
  if (request === null) return null;
  let requestHash: string;
  try {
    requestHash = hashRequest(request);
  } catch (e) {
    if (e instanceof CoreError) return null;
    throw e;
  }
  const ref = o['grantRefHash'];
  if (ref !== null && !isHash(ref)) return null;
  if (!isSeatId(o['seat'])) return null;
  const subject = readSubject(o['subject']);
  if (subject === undefined) return null;
  return { requestHash, kind: request['kind'] as string, grantRefHash: ref, seat: o['seat'], subject, legCount: legs };
}

export interface BindInput {
  state: unknown;
  /** Unix seconds from the caller's clock; the module has none */
  now: unknown;
  decision: unknown;
  presented: unknown;
}

export function bindDecision(input: BindInput): BindResult {
  const inp = closedObject(input, ['state', 'now', 'decision', 'presented']);
  if (inp === null) return refuse('binding_input_malformed', 'shape');

  // before step 1: the call, the clock and the state
  const now = inp['now'];
  if (!isTime(now)) return refuse('binding_input_malformed', 'now');
  const checked = validateBindingState(inp['state']);
  if (!checked.ok) return refuse(checked.reason, checked.detail);
  const state = checked.state;

  // the pin gate (DE-93): a seat with no pin decides nothing, and says so before anything of the step is read
  if (state.expectedPolicyHash === null) return refuse('policy_pin_missing');

  // 1. presented_malformed, multi_leg_unsupported, raw_not_allowed, decision_malformed, nonce_malformed
  const presented = readPresented(inp['presented']);
  if (presented === null) return refuse('presented_malformed');
  if (presented.legCount !== 1) return refuse('multi_leg_unsupported', 'legCount ' + presented.legCount);
  // DE-91: the raw kind is a property of the presented request alone, judged after the legs and before the decision is read
  if (presented.kind === 'raw' && state.allowRaw !== true) return refuse('raw_not_allowed');
  const decision = readDecision(inp['decision']);
  if (decision === 'decision_malformed' || decision === 'nonce_malformed') return refuse(decision);

  // 2, 3. time: valid from issuedAt up to but excluding expiresAt
  if (now < decision.issuedAt) return refuse('decision_not_yet_valid');
  if (now >= decision.expiresAt) return refuse('decision_expired');
  // 4. a window equal to the cap is allowed, one second above is not
  if (decision.expiresAt - decision.issuedAt > state.maxWindowSeconds) return refuse('decision_window_too_long');

  // 5. the decision is about exactly this request: same fields, same execution commitment, same Accumulate transaction
  if (decision.requestHash !== presented.requestHash) return refuse('request_mismatch');

  // 6. the Grant: required, then the same one named by decision and transaction, then the head, then the subject join
  if (state.requireGrant && (decision.grantHash === null || presented.grantRefHash === null)) return refuse('grant_required');
  if (decision.grantHash !== presented.grantRefHash) return refuse('grant_hash_mismatch');
  const named = decision.grantHash;
  if (named !== null) {
    // the grantRef of a transaction is a claim of its producer: only the head read from Accumulate decides
    if (state.grantHeadHash === null) return refuse('grant_unverified', 'head_hash');
    if (named !== state.grantHeadHash) return refuse('grant_superseded');
    if (presented.subject === null) return refuse('subject_unproven');
    if (state.grantHeadSubject === null) return refuse('grant_unverified', 'head_subject');
    if (presented.subject.adi !== state.grantHeadSubject.adi || presented.subject.type !== state.grantHeadSubject.type) return refuse('grant_subject_mismatch');
  }

  // 7. the policy the seat pins (the pin gate above guarantees there is one)
  if (decision.policyHash !== state.expectedPolicyHash) return refuse('policy_hash_mismatch');
  // 8. the seat that is about to sign
  if (decision.seat !== presented.seat) return refuse('seat_mismatch');
  // 9. the approver, by identity
  if (!state.authorizedApprovers.includes(decision.approver)) return refuse('approver_not_authorized');
  // 10. single use, last: a used decision for another request is a mismatch above, not a replay
  if (state.consumed.includes(decision.nonce)) return refuse('decision_replayed');

  return {
    ok: true,
    verb: decision.decision,
    requestHash: decision.requestHash,
    decisionHash: hashDecision(decision),
    nonce: decision.nonce,
    grantHash: decision.grantHash,
    policyHash: decision.policyHash,
    policyPinned: true,
    approver: decision.approver,
    seat: decision.seat,
    state: { ...state, consumed: [...state.consumed, decision.nonce] },
    event: { kind: 'decision.consumed', payload: { requestHash: decision.requestHash, nonce: decision.nonce } },
  };
}

/**
 * Marks nonces spent without a decision being accepted: the old nonce of a decision that a recheck voided (a denied,
 * expired or re-issued item), so that the old decision cannot be used even by a seat that pins no policy. Idempotent.
 */
export function voidNonces(state: unknown, nonces: unknown): { ok: true; state: BindingState } | { ok: false; reason: string; detail?: string } {
  const checked = validateBindingState(state);
  if (!checked.ok) return refuse(checked.reason, checked.detail);
  const list = dataArray(nonces, NO_CAP);
  if (list === null || !list.every(isHash)) return refuse('nonce_malformed', 'nonces');
  const have = new Set(checked.state.consumed);
  const added: string[] = [];
  for (const n of list as string[]) {
    if (!have.has(n)) {
      have.add(n);
      added.push(n);
    }
  }
  return { ok: true, state: { ...checked.state, consumed: [...checked.state.consumed, ...added] } };
}

export type BindRunResult = { results: BindResult[]; state: BindingState } | { ok: false; reason: string; detail?: string };

/**
 * The whole run the vectors describe: a state and a list of steps { now, decision, presented }, each step judged by
 * bindDecision against the state the previous accepted step left (the consumed nonces carry over, as a signer persists
 * them). A call that is not a state object and a list of steps is binding_input_malformed; a state with a wrong member is
 * binding_state_malformed (DE-74); a step that is not a step is answered binding_input_malformed in its place.
 */
export function bindDecisions(input: unknown): BindRunResult {
  const inp = closedObject(input, ['state', 'steps']);
  if (inp === null) return refuse('binding_input_malformed', 'shape');
  const steps = dataArray(inp['steps'], NO_CAP);
  if (steps === null) return refuse('binding_input_malformed', 'steps');
  const checked = validateBindingState(inp['state']);
  if (!checked.ok) return refuse(checked.reason, checked.detail);
  let state = checked.state;
  const results: BindResult[] = [];
  for (const raw of steps) {
    const step = closedObject(raw, ['now', 'decision', 'presented']);
    if (step === null) {
      results.push(refuse('binding_input_malformed', 'step'));
      continue;
    }
    const r = bindDecision({ state, now: step['now'], decision: step['decision'], presented: step['presented'] });
    if (r.ok) state = r.state;
    results.push(r);
  }
  return { results, state };
}
