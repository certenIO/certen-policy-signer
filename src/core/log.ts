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
import { CoreError, HASH_RE, isPlainObject } from './bytes.js';
import { genesisHash, logEntryHash } from './hashes.js';
import { canonicalize } from './jcs.js';

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
const present = (p: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(p, k);

/**
 * The members the evidence check reads (DE-52): present and strings, except grantHash and policyHash of decision.issued
 * (a string or null: null is a value, absence is refused), grant.observed.version (a safe integer from 1) and the
 * exactly-one-of requestHash and exceptionHash of approval.cast. Further members are allowed. Enforced at append and
 * at verify; the other kinds are free-form.
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
    case 'grant.observed':
      return str('grantId', 'grantHash') && typeof p['version'] === 'number' && Number.isSafeInteger(p['version']) && p['version'] >= 1;
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

const refuse = (reason: string, seq?: number, detail?: string): VerifyLogResult => {
  const r: { ok: false; reason: string; seq?: number; detail?: string } = { ok: false, reason };
  if (seq !== undefined) r.seq = seq;
  if (detail !== undefined) r.detail = detail;
  return r;
};

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

  let prevHash = genesisHash(input.logId);
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const seq = isPlainObject(e) && isSeq(e['seq']) ? (e['seq'] as number) : undefined;
    if (!isPlainObject(e) || Object.keys(e).length !== ENTRY_KEYS.length || !ENTRY_KEYS.every((k) => k in e) || seq === undefined || !isPlainObject(e['payload']) || !isHash(e['prev']) || !isHash(e['hash']) || typeof e['kind'] !== 'string') {
      return refuse('log_entry_malformed', seq, 'entry ' + i);
    }
    if (!isTime(e['at'])) return refuse('log_at_invalid', seq);
    if (!isKind(e['kind'])) return refuse('log_kind_unknown', seq);
    let recomputed: string;
    try {
      recomputed = logEntryHash({ prev: e['prev'] as string, seq, kind: e['kind'], payload: e['payload'], at: e['at'] as number });
    } catch (err) {
      if (err instanceof CoreError) return refuse('log_entry_malformed', seq, err.code);
      throw err;
    }
    if (recomputed !== e['hash']) return refuse('log_entry_hash_mismatch', seq);
    const expected = i + 1;
    if (seq !== expected) {
      if (seq < expected) return refuse('log_seq_duplicate', seq);
      const laterHasExpected = entries.slice(i + 1).some((x) => isPlainObject(x) && x['seq'] === expected);
      return refuse(laterHasExpected ? 'log_seq_out_of_order' : 'log_seq_gap', seq);
    }
    if (!payloadReadable(e['kind'], e['payload'])) return refuse('log_payload_invalid', seq, e['kind']);
    if (e['prev'] !== prevHash) return refuse(i === 0 ? 'log_genesis_mismatch' : 'log_prev_mismatch', seq);
    prevHash = e['hash'] as string;
  }

  const head: LogHead | null = entries.length === 0 ? null : { seq: entries.length, hash: prevHash };
  if (pinned !== null) {
    if (entries.length < pinned.seq) return refuse('log_truncated');
    if ((entries[pinned.seq - 1] as { hash: string }).hash !== pinned.hash) return refuse('log_head_mismatch');
    return { ok: true, head, pinned: true };
  }
  return { ok: true, head, pinned: false };
}
