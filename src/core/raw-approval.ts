/**
 * The raw approval kind (GRANT.md section 6a, DECISION.md section 2; decision RAW; DE-90, DE-91, DE-92). `raw` is the fourth
 * action kind: the kind of a single call that no typed kind describes. A decoder never answers raw; it is what is left when no
 * typed kind fits, and it is bound only at a seat that allows it.
 *
 *   mapOutcome({ mapped, allowRaw }): what a signer binds for a decoded call. `mapped` is the typed kind the decoder found
 *   (erc20.transfer, erc20.approve, native.transfer) or null when none fits. A typed kind is bound whatever allowRaw says; a
 *   call no typed kind describes is bound as raw at a seat whose allowRaw is the boolean true, and at every other seat it is
 *   NOT BOUND (binding_absent, nothing is signed: it is not an UNDECODED review that a person could approve past, finding
 *   DAX7C-F5). A decoder that answers raw, a kind outside the closed set and an allowRaw that is not a boolean are malformed.
 *
 *   reviewRaw({ binding, execution }): the review of a raw call: the wire binding is parsed by the one reference parser, the
 *   binding must be of kind raw, its execution is REQUIRED and is authenticated by the bound commitment, the three mapped
 *   members (beneficiary = target, asset = native, amount = native value) are compared with it, and the review then shows the
 *   target, the native value, the calldata as bytes with its length and its keccak256 hash, and says the token effect is
 *   UNKNOWN and that the call needs the rawEffect exception. It never shows a decoded token amount (DE-92).
 */
import { fromHex, isPlainObject } from './bytes.js';
import { keccak256Hex } from './calldata-keccak.js';
import { authenticateExecution, parseWireBinding } from './decision-wire.js';
import { ACTION_KINDS } from './grant-profile.js';

const TYPED_KINDS = ACTION_KINDS.filter((k) => k !== 'raw');

export type MapOutcomeResult =
  | { ok: true; bound: true; kind: string }
  | { ok: false; reason: 'binding_absent'; bound: false }
  | { ok: false; reason: 'map_input_malformed'; detail?: string };

export function mapOutcome(input: unknown): MapOutcomeResult {
  if (!isPlainObject(input)) return { ok: false, reason: 'map_input_malformed', detail: 'shape' };
  for (const k of Object.keys(input)) if (k !== 'mapped' && k !== 'allowRaw') return { ok: false, reason: 'map_input_malformed', detail: 'unknown member ' + k };
  if (!('mapped' in input)) return { ok: false, reason: 'map_input_malformed', detail: 'mapped' };
  const mapped = input['mapped'];
  if (input['allowRaw'] !== undefined && typeof input['allowRaw'] !== 'boolean') return { ok: false, reason: 'map_input_malformed', detail: 'allowRaw' };
  // raw is never a decoder result; a kind outside the closed set is not one either
  if (mapped !== null && (typeof mapped !== 'string' || !(TYPED_KINDS as readonly string[]).includes(mapped))) return { ok: false, reason: 'map_input_malformed', detail: 'mapped' };
  if (mapped !== null) return { ok: true, bound: true, kind: mapped };
  return input['allowRaw'] === true ? { ok: true, bound: true, kind: 'raw' } : { ok: false, reason: 'binding_absent', bound: false };
}

export type RawReviewResult =
  | {
      ok: true;
      kind: 'raw';
      tokenEffect: 'unknown';
      needsException: true;
      members: { chainId: number; source: string; target: string; value: string; calldata: string };
      calldataHash: string;
      calldataBytes: number;
    }
  | { ok: false; reason: string; detail?: string };

export function reviewRaw(input: unknown): RawReviewResult {
  if (!isPlainObject(input)) return { ok: false, reason: 'raw_review_malformed', detail: 'shape' };
  for (const k of Object.keys(input)) if (k !== 'binding' && k !== 'execution') return { ok: false, reason: 'raw_review_malformed', detail: 'unknown member ' + k };
  // the binding by the one reference parser (DE-96); a binding that is not valid is refused as the parser says
  const p = parseWireBinding({ binding: input['binding'] });
  if (!p.ok) return p;
  // a typed kind has its own review
  if (p.binding.kind !== 'raw') return { ok: false, reason: 'raw_review_kind' };
  // legs, execution (required), shape, chain, source, target, the commitment, then the raw mapping
  const auth = authenticateExecution(input['binding'], input['execution']);
  if (!auth.ok) return auth;
  const e = input['execution'] as { chainId: number; source: string; target: string; value: string; calldata: string };
  const bytes = fromHex(e.calldata.slice(2));
  return {
    ok: true,
    kind: 'raw',
    tokenEffect: 'unknown',
    needsException: true,
    members: { chainId: e.chainId, source: e.source, target: e.target, value: e.value, calldata: e.calldata },
    calldataHash: keccak256Hex(bytes),
    calldataBytes: bytes.length,
  };
}

/**
 * What a signer binds for the answer of the DAX-7A decoder (DE-91): a call is bound as a typed kind only when the decoder
 * DECODED it, which it does only on an exact match (the selector, whole-word arguments, an address padded with twelve zero bytes,
 * nothing after the arguments, no value on a token call); every undecoded answer, whatever its reason, is "no typed kind
 * describes this call": raw at a seat that allows it, NOT BOUND everywhere else. A decoder that answers raw is malformed.
 */
export function mapDecoded(decoded: unknown, allowRaw?: unknown): MapOutcomeResult {
  if (!isPlainObject(decoded) || (decoded['status'] !== 'decoded' && decoded['status'] !== 'undecoded')) return { ok: false, reason: 'map_input_malformed', detail: 'decoded' };
  return mapOutcome({ mapped: decoded['status'] === 'decoded' ? decoded['kind'] : null, ...(allowRaw === undefined ? {} : { allowRaw }) });
}
