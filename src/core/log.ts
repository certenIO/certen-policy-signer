/**
 * The hash-chained decision log (DECISION.md section 9, C5): append, verify the chain, detect tamper, never drop.
 * Entries are {seq, kind, at, payload, prev, hash}; hash = SHA-256 over the tagged fields (hashes.ts logEntryHash);
 * prev of entry 1 is the genesis hash of the log id. One writer per log; seq starts at 1.
 *
 * What the chain can and cannot see (DE-45): an edit, a deleted middle entry, a reorder, an insert, a foreign log and
 * an unknown kind are refused by name. A truncated tail and an edit followed by re-chaining every later entry are NOT
 * visible to any hash chain; a pinned head `{seq, hash}` held somewhere the writer cannot edit turns both into
 * refusals, and without a pin the verifier says `pinned: false` instead of claiming more.
 */
import { CoreError, HASH_RE, isAmount, isPlainObject } from './bytes.js';
import { genesisHash, logEntryHash } from './hashes.js';
import { canonicalize } from './jcs.js';
import { DEFAULT_MIN_REASON_LENGTH } from './pause.js';
import { isSeatId } from './decision-identity.js';
import { isAccUrl } from './grant-profile.js';

/** AGT-F135 (DE-109): the acts an intervention.recorded entry may name */
export const INTERVENTION_ACTS: readonly string[] = ['revoke', 'replace', 'reject'];

/**
 * the eighteen kinds (DECISION.md section 9, DE-103): binding.refused (DAX7E-R2-F2, the signer's refusal receipt) is the thirteenth, policy.pinned (the pin
 * step, DE-94) the fourteenth, intervention.recorded (AGT-F135, DE-109: a revoke, replace or cancel by reject vote held by a named seat with a reason) the
 * fifteenth; assessment.intake, epoch.published and platform.checked (finding EWA-F11, DE-116: the EWA intake, the published permission epoch and every
 * platform check answer) the sixteenth to eighteenth, appended after the fifteen; any other kind is refused by name
 */
export const LOG_KINDS = [
  'decision.issued',
  'decision.consumed',
  'approval.cast',
  'ledger.reserve',
  'ledger.settle',
  'ledger.release',
  'exception.consume',
  'pause.set',
  'pause.clear',
  'recheck.result',
  'outcome.recorded',
  'grant.observed',
  'binding.refused',
  'policy.pinned',
  'intervention.recorded',
  'assessment.intake',
  'epoch.published',
  'platform.checked',
] as const;
export type LogKind = (typeof LOG_KINDS)[number];

export interface LogEntry {
  seq: number;
  kind: LogKind;
  at: number;
  payload: Record<string, unknown>;
  prev: string;
  hash: string;
}
export interface LogHead { seq: number; hash: string }

const MAX_LOG_ID = 256;
const ENTRY_KEYS = ['seq', 'kind', 'at', 'payload', 'prev', 'hash'];

const isStr = (v: unknown): v is string => typeof v === 'string';
const isHash = (v: unknown): boolean => typeof v === 'string' && HASH_RE.test(v);
const isNullableStr = (v: unknown): boolean => v === null || typeof v === 'string';
const hashOrEmpty = (v: unknown): boolean => v === '' || isHash(v);
const present = (p: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(p, k);
const hashOrNull = (v: unknown): boolean => v === null || isHash(v);
const intFrom = (v: unknown, min: number): boolean => typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
/** a platform service string of the EWA catalogue (MAPPING.md section 1): `payout` or `service-access.<name>` with a service name */
const PLATFORM_SERVICE_RE = /^(payout|service-access\.[a-z0-9][a-z0-9-]{0,62})$/;

/**
 * The members the evidence check reads (DE-52): present and strings, except grantHash and policyHash of decision.issued
 * (a string or null: null is a value, absence is refused), grant.observed.version (a safe integer from 1) and the
 * exactly-one-of requestHash and exceptionHash of approval.cast. binding.refused (the refusal receipt, DE-97, DE-103) carries
 * requestHash, seat and reason as strings (requestHash is the empty string when the request could not be read) and, where
 * present, nonce and txHash each a 32-byte hash or the empty string, never any other value; policy.pinned (DE-94) carries
 * seat, by and reason as strings, policyHash a 32-byte hash and previous (PRESENT: null is a value, absence is refused) the
 * pin it replaces, a 32-byte hash or null. Further members are allowed. Enforced at append and at verify; the other kinds
 * are free-form.
 */
function payloadReadable(kind: string, p: Record<string, unknown>): boolean {
  const str = (...ks: string[]): boolean => ks.every((k) => present(p, k) && isStr(p[k]));
  switch (kind) {
    case 'decision.issued':
      return str('requestHash', 'decision', 'approver', 'nonce') && present(p, 'grantHash') && isNullableStr(p['grantHash']) && present(p, 'policyHash') && isNullableStr(p['policyHash']);
    case 'approval.cast':
      return present(p, 'requestHash') !== present(p, 'exceptionHash') && str('identity', 'book', 'vote') && isStr(present(p, 'requestHash') ? p['requestHash'] : p['exceptionHash']);
    case 'decision.consumed':
      return str('requestHash', 'nonce');
    case 'outcome.recorded':
      return str('requestHash', 'status', 'destinationTx');
    case 'binding.refused':
      return str('requestHash', 'seat', 'reason') && (!present(p, 'nonce') || hashOrEmpty(p['nonce'])) && (!present(p, 'txHash') || hashOrEmpty(p['txHash']));
    case 'policy.pinned':
      return str('seat', 'by', 'reason') && present(p, 'policyHash') && isHash(p['policyHash']) && present(p, 'previous') && (p['previous'] === null || isHash(p['previous']));
    case 'intervention.recorded':
      // AGT-F135 (DE-109): act one of revoke/replace/reject, subject an acc:// URL, seat the seat:<name> form, by non-empty, reason at least the core's
      // minimum reason length (trimmed), txHash the 32-byte hash of the Accumulate transaction that is the act
      return str('act', 'subject', 'seat', 'by', 'reason') && INTERVENTION_ACTS.includes(p['act'] as string) && isAccUrl(p['subject']) &&
        isSeatId(p['seat']) && (p['by'] as string).trim().length > 0 && (p['reason'] as string).trim().length >= DEFAULT_MIN_REASON_LENGTH &&
        present(p, 'txHash') && isHash(p['txHash']);
    case 'grant.observed':
      return str('grantId', 'grantHash') && typeof p['version'] === 'number' && Number.isSafeInteger(p['version']) && p['version'] >= 1;
    case 'assessment.intake':
      // EWA-F11 (DE-116, EWA RECORD.md section 3): assessmentId and subject strings; version a safe integer from 1 or null (the input did not parse); rawSha256 a
      // 32-byte hash; assessmentHash PRESENT, a 32-byte hash or null; result accepted (reason empty, assessmentHash a hash) or refused (reason the failure name)
      return str('assessmentId', 'subject', 'reason') && present(p, 'version') && (p['version'] === null || intFrom(p['version'], 1)) && isHash(p['rawSha256']) &&
        present(p, 'assessmentHash') && hashOrNull(p['assessmentHash']) &&
        (p['result'] === 'accepted' ? p['reason'] === '' && isHash(p['assessmentHash']) : p['result'] === 'refused' && p['reason'] !== '');
    case 'epoch.published':
      // EWA-F11 (DE-116): merchant an acc:// URL; epoch a safe integer from 1; epochHash and grantHash 32-byte hashes; previousEpochHash PRESENT, a hash or null
      // (the first epoch); expires a non-negative safe integer
      return isAccUrl(p['merchant']) && intFrom(p['epoch'], 1) && isHash(p['epochHash']) && isHash(p['grantHash']) && present(p, 'previousEpochHash') && hashOrNull(p['previousEpochHash']) && intFrom(p['expires'], 0);
    case 'platform.checked':
      // EWA-F11 (DE-116): merchant a string; service payout or service-access.<name>; amount decimal text; requestHash a 32-byte hash or the empty string (a call
      // that is not a payout); epochHash and grantHash PRESENT, a hash or null; answer allow (reason and seat empty), deny (a reason, seat empty) or route
      // (reason limit_per_transaction_exceeded, seat a named seat); cause call or review
      return str('merchant', 'service', 'reason', 'seat') && PLATFORM_SERVICE_RE.test(p['service'] as string) && isAmount(p['amount']) && hashOrEmpty(p['requestHash']) &&
        present(p, 'epochHash') && hashOrNull(p['epochHash']) && present(p, 'grantHash') && hashOrNull(p['grantHash']) &&
        (p['answer'] === 'allow' ? p['reason'] === '' && p['seat'] === '' : p['answer'] === 'deny' ? p['reason'] !== '' && p['seat'] === '' : p['answer'] === 'route' && p['reason'] === 'limit_per_transaction_exceeded' && isSeatId(p['seat'])) &&
        (p['cause'] === 'call' || p['cause'] === 'review');
    default:
      return true;
  }
}

const isSeq = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const isKind = (v: unknown): v is LogKind => typeof v === 'string' && (LOG_KINDS as readonly string[]).includes(v);

export interface AppendInput {
  logId: string;
  /** the current head of the log, or null for an empty log */
  head: unknown;
  kind: string;
  at: number;
  payload: unknown;
}
export type AppendResult = { ok: true; entry: LogEntry } | { ok: false; reason: string; detail?: string };

/**
 * Builds the next entry from the current head. A refusal is a refusal to append: the caller MUST fail the decision it
 * belongs to (back-pressure) and MUST NOT skip the entry (DE-47).
 */
export function appendEntry(input: AppendInput): AppendResult {
  if (!isStr(input.logId) || input.logId.length === 0 || input.logId.length > MAX_LOG_ID) return { ok: false, reason: 'log_id_malformed' };
  let seq = 1;
  let prev = genesisHash(input.logId);
  if (input.head !== null) {
    const h = input.head;
    if (!isPlainObject(h) || Object.keys(h).length !== 2 || !isSeq(h['seq']) || !isHash(h['hash'])) return { ok: false, reason: 'log_head_malformed' };
    seq = (h['seq'] as number) + 1;
    prev = h['hash'] as string;
  }
  if (!isKind(input.kind)) return { ok: false, reason: 'log_kind_unknown', detail: String(input.kind) };
  if (!isTime(input.at)) return { ok: false, reason: 'log_at_invalid' };
  if (!isPlainObject(input.payload)) return { ok: false, reason: 'log_entry_malformed', detail: 'payload' };
  try {
    canonicalize(input.payload);
  } catch (e) {
    if (e instanceof CoreError) return { ok: false, reason: 'log_payload_unhashable', detail: e.code };
    throw e;
  }
  if (!payloadReadable(input.kind, input.payload)) return { ok: false, reason: 'log_payload_invalid', detail: input.kind };
  const payload = input.payload;
  const hash = logEntryHash({ prev, seq, kind: input.kind, payload, at: input.at });
  return { ok: true, entry: { seq, kind: input.kind, at: input.at, payload, prev, hash } };
}

export interface VerifyLogInput {
  logId: string;
  entries: unknown;
  /** a pinned head held outside the log writer's reach; absent means the chain is checked on its own */
  expectedHead?: unknown;
}
export type VerifyLogResult =
  | { ok: true; head: LogHead | null; pinned: boolean }
  | { ok: false; reason: string; seq?: number; detail?: string };

type LogRefusal = { ok: false; reason: string; seq?: number; detail?: string };
const refuse = (reason: string, seq?: number, detail?: string): LogRefusal => {
  const r: { ok: false; reason: string; seq?: number; detail?: string } = { ok: false, reason };
  if (seq !== undefined) r.seq = seq;
  if (detail !== undefined) r.detail = detail;
  return r;
};

/**
 * The walk of the chain, shared by the full log and the slice from a checkpoint: `base` entries precede the first one carried (0 for a full log: seq
 * starts at 1), `prevHash` is the hash the first entry must link to (the genesis of the log id, or the hash of the checkpoint entry) and
 * `firstPrevReason` names a first entry that does not link to it.
 */
function walkChain(entries: unknown[], base: number, prevStart: string, firstPrevReason: string): { ok: true; prevHash: string } | { ok: false; refusal: LogRefusal } {
  let prevHash = prevStart;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const seq = isPlainObject(e) && isSeq(e['seq']) ? (e['seq'] as number) : undefined;
    if (!isPlainObject(e) || Object.keys(e).length !== ENTRY_KEYS.length || !ENTRY_KEYS.every((k) => k in e) || seq === undefined || !isPlainObject(e['payload']) || !isHash(e['prev']) || !isHash(e['hash']) || typeof e['kind'] !== 'string') {
      return { ok: false, refusal: refuse('log_entry_malformed', seq, 'entry ' + i) };
    }
    if (!isTime(e['at'])) return { ok: false, refusal: refuse('log_at_invalid', seq) };
    if (!isKind(e['kind'])) return { ok: false, refusal: refuse('log_kind_unknown', seq) };
    let recomputed: string;
    try {
      recomputed = logEntryHash({ prev: e['prev'] as string, seq, kind: e['kind'], payload: e['payload'], at: e['at'] as number });
    } catch (err) {
      if (err instanceof CoreError) return { ok: false, refusal: refuse('log_entry_malformed', seq, err.code) };
      throw err;
    }
    if (recomputed !== e['hash']) return { ok: false, refusal: refuse('log_entry_hash_mismatch', seq) };
    const expected = base + i + 1;
    if (seq !== expected) {
      if (seq < expected) return { ok: false, refusal: refuse('log_seq_duplicate', seq) };
      const laterHasExpected = entries.slice(i + 1).some((x) => isPlainObject(x) && x['seq'] === expected);
      return { ok: false, refusal: refuse(laterHasExpected ? 'log_seq_out_of_order' : 'log_seq_gap', seq) };
    }
    if (!payloadReadable(e['kind'], e['payload'])) return { ok: false, refusal: refuse('log_payload_invalid', seq, e['kind']) };
    if (e['prev'] !== prevHash) return { ok: false, refusal: refuse(i === 0 ? firstPrevReason : 'log_prev_mismatch', seq) };
    prevHash = e['hash'] as string;
  }
  return { ok: true, prevHash };
}

/**
 * Per entry, in order: shape, known kind, hash recomputed from the fields, sequence (gap, out of order, duplicate),
 * readable payload members, then the link to the previous hash (the genesis for entry 1). Then the pin, if given:
 * a log shorter than the pin is truncated, a different hash at the pin's seq is a head mismatch.
 */
export function verifyLog(input: VerifyLogInput): VerifyLogResult {
  if (!isStr(input.logId) || input.logId.length === 0 || input.logId.length > MAX_LOG_ID) return refuse('log_id_malformed');
  const pin = input.expectedHead;
  let pinned: LogHead | null = null;
  if (pin !== undefined && pin !== null) {
    if (!isPlainObject(pin) || Object.keys(pin).length !== 2 || !isSeq(pin['seq']) || !isHash(pin['hash'])) return refuse('log_pin_malformed');
    pinned = { seq: pin['seq'] as number, hash: pin['hash'] as string };
  }
  const entries = input.entries;
  if (!Array.isArray(entries)) return refuse('log_entries_malformed');

  const walked = walkChain(entries, 0, genesisHash(input.logId), 'log_genesis_mismatch');
  if (!walked.ok) return walked.refusal;
  const prevHash = walked.prevHash;

  const head: LogHead | null = entries.length === 0 ? null : { seq: entries.length, hash: prevHash };
  if (pinned !== null) {
    if (entries.length < pinned.seq) return refuse('log_truncated');
    if ((entries[pinned.seq - 1] as { hash: string }).hash !== pinned.hash) return refuse('log_head_mismatch');
    return { ok: true, head, pinned: true };
  }
  return { ok: true, head, pinned: false };
}

export interface VerifyLogFromInput {
  logId: string;
  /** the entry the slice follows: `{seq, hash}` of entry `seq` of the log; the first entry carried is `seq + 1` and links to `hash` */
  checkpoint: unknown;
  entries: unknown;
  /** a pinned head the slice must reach (round 8, EVIDENCE.md section 3b): one AFTER the checkpoint is reached by the chain; one AT the checkpoint must be the checkpoint itself (and pins the checkpoint, not the slice); one BEFORE it is refused: the slice does not reach it */
  expectedHead?: unknown;
}
export type VerifyLogFromResult =
  | { ok: true; checkpoint: LogHead; head: LogHead | null; pinned: boolean; checkpointPinned: boolean }
  | { ok: false; reason: string; seq?: number; detail?: string };

/**
 * The slice of a log that follows a CHECKPOINT (round 8, OQ-7P-3, EVIDENCE.md section 3b): the entries from `checkpoint.seq + 1`, each checked as in
 * `verifyLog`, the first one linking to the checkpoint hash instead of the genesis (`log_checkpoint_mismatch`). It proves the chain FROM the checkpoint
 * forward and nothing about what precedes it: whether the checkpoint is the log's own entry is the caller's commitment (a pin or an earlier verified head),
 * never this function's. Entries before the checkpoint are neither carried nor read.
 */
export function verifyLogFrom(input: VerifyLogFromInput): VerifyLogFromResult {
  if (!isStr(input.logId) || input.logId.length === 0 || input.logId.length > MAX_LOG_ID) return refuse('log_id_malformed');
  const cp = input.checkpoint;
  if (!isPlainObject(cp) || Object.keys(cp).length !== 2 || !isSeq(cp['seq']) || !isHash(cp['hash'])) return refuse('log_checkpoint_malformed');
  const checkpoint: LogHead = { seq: cp['seq'] as number, hash: cp['hash'] as string };
  const pin = input.expectedHead;
  let pinned: LogHead | null = null;
  if (pin !== undefined && pin !== null) {
    if (!isPlainObject(pin) || Object.keys(pin).length !== 2 || !isSeq(pin['seq']) || !isHash(pin['hash'])) return refuse('log_pin_malformed');
    pinned = { seq: pin['seq'] as number, hash: pin['hash'] as string };
    if (pinned.seq < checkpoint.seq) return refuse('log_pin_before_checkpoint');
  }
  const atCheckpoint = pinned !== null && pinned.seq === checkpoint.seq;
  if (atCheckpoint && pinned!.hash !== checkpoint.hash) return refuse('log_head_mismatch');
  const entries = input.entries;
  if (!Array.isArray(entries)) return refuse('log_entries_malformed');
  const walked = walkChain(entries, checkpoint.seq, checkpoint.hash, 'log_checkpoint_mismatch');
  if (!walked.ok) return walked.refusal;
  const head: LogHead | null = entries.length === 0 ? null : { seq: checkpoint.seq + entries.length, hash: walked.prevHash };
  if (pinned !== null && !atCheckpoint) {
    if (checkpoint.seq + entries.length < pinned.seq) return refuse('log_truncated');
    if ((entries[pinned.seq - checkpoint.seq - 1] as { hash: string }).hash !== pinned.hash) return refuse('log_head_mismatch');
    return { ok: true, checkpoint, head, pinned: true, checkpointPinned: true };
  }
  return { ok: true, checkpoint, head, pinned: false, checkpointPinned: atCheckpoint };
}
