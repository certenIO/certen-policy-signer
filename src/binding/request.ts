/**
 * The REQUEST of DECISION.md section 2, built from the transaction the signer is ABOUT TO SIGN.
 *
 * `requestHash` is recomputed by the core (`hashRequest`) over this object; the decision's own `requestHash` is only ever
 * compared with it, never used to build it. Everything here comes from the pending Accumulate transaction's own data entry:
 * the four blobs (the validator operation id is recomputed from their bytes), the single leg and its execution payload. Nothing
 * is taken from the policy reply, the Console or the producer's declared ids.
 *
 * What a request can be, and what it cannot (a refusal is a named `presented_malformed` detail, never a guess):
 *   - ONE leg. A multi-leg intent is several executions under one operation and cannot be bound by a one-leg request hash: the
 *     presented legCount is derived from the legs and the core refuses a legCount other than 1 as `multi_leg_unsupported` (DE-76).
 *   - kind `native.transfer` (empty calldata), `erc20.transfer` or `erc20.approve` (the calldata decoded EXACTLY by the core decoder, DE-91:
 *     the selector, whole-word arguments, an address padded with twelve zero bytes, nothing after the arguments, no native value on a token
 *     call), or `raw` (below). The calldata TEXT is read as the core reads it: `0x` and LOWER-case hex of whole bytes. Upper-case digits, a
 *     missing prefix, an odd number of digits and a size above the limit are refused (`presented_malformed`, the decoder reason as the detail):
 *     the text is never normalised, because two readings of one text is how a review and a signature disagree (DAX7A-F2).
 *   - a call that no typed kind describes (an unknown selector, `transferFrom`, a dirty address pad, trailing bytes, native value on a token
 *     call, a wrapper) is mapped by the core's `mapDecoded`: `raw` at a seat whose `allowRaw` is the boolean true (beneficiary = target,
 *     asset = native, amount = the native value, DE-90), and NOT BOUND at every other seat (`binding_absent`, nothing is signed, DE-91). The
 *     signer has no token registry, so the decoder is given a one-entry registry naming the called address: it binds raw base units and
 *     addresses, and the display units are the decision service's own (a token its registry does not know is shown undecoded there).
 *   - the leaf expiry bound (`leafExpiry`, DE-87, DE-88): the smaller of the leg's declared deadline (`deadline_timestamp`) and the floor of the
 *     transaction header deadline plus the seat's settlement horizon (never below the validator's one hour); absent when neither exists; claimed
 *     for a ONE-leg transaction only. It is an upper bound of the contract's expiry, so a ledger errs towards a longer hold.
 *   - `executionCommitment` is the value the intent STATES (`executionPayload.executionCommitment`); the signer does not
 *     recompute its keccak (DECISION.md section 2: taken from the intent; DAX-7 recomputes the displayed view from the bytes).
 *   - `chainId` must be numeric (`executionPayload.chainId` or `chainId`; both present must agree). A chain NAME is not an id.
 * The mapping is the signer's reading of the intent format; the Console must build the same object (OQ-DAX4S-2).
 */
import { ADDRESS_RE, HASH_RE, isAmount } from '../core/bytes.js';
import { singleCommitment } from '../core/calldata-keccak.js';
import { decode } from '../core/calldata.js';
import { leafExpiryBound, VALIDATOR_HORIZON_SECONDS } from '../core/leaf-expiry.js';
import { mapDecoded } from '../core/raw-approval.js';
import type { PolicyExecution, ResolvedTx, TransactionHeaderInfo } from '../types.js';
import { OperationIdError, validatorOperationId } from './operation-id.js';

export interface PresentedRequest {
  /** the closed object the core hashes (`hashRequest`): ten members */
  request: Record<string, string | number>;
  /** the number of legs of the intent, derived from the transaction and ALWAYS supplied to the core (DE-76); 1 for a bindable request */
  legCount: number;
  /** the producer's CLAIM of the Grant (blob 0 `grantRef`), or null when the intent names none; the head is read from Accumulate, never from this */
  grantRef: { grantId: string; version: number; grantHash: string } | null;
  /** `grantRef.grantHash` or null: the core's `grantRefHash` */
  grantRefHash: string | null;
  /** the intent's asserted subject, or null; the world resolves it, the signer never trusts it */
  assertedSubject: { adi: string; assertedBy: string } | null;
  /** the validator operation id (also inside `request.operationId`) */
  operationId: string;
  /**
   * What the single leg executes (chainId, source, target, value, calldata), AUTHENTICATED: the core's single-call commitment recomputed over it
   * equals `request.executionCommitment`. null for an intent with several legs (its commitment is a batch form, not recomputed here).
   */
  execution: PolicyExecution | null;
  /** the leaf expiry bound in Unix seconds (DE-87), or null when the transaction has no deadline or has several legs: forwarded as `binding.leafExpiry` */
  leafExpiry: number | null;
}

export type BuildResult =
  | { ok: true; value: PresentedRequest }
  /** `reason` is set only for a call that no typed kind describes at a seat without allowRaw: NOT BOUND (`binding_absent`); otherwise the refusal is `presented_malformed` with `detail` */
  | { ok: false; detail: string; reason?: 'binding_absent' };

/** The seat settings the request depends on. The policy request and the binding check pass the SAME options (`presentOptionsOf`). */
export interface BuildOptions {
  /** the seat setting allowRaw (DE-91): absent means false */
  allowRaw?: boolean;
  /** the seat settlement horizon in seconds (DE-88): at least the validator's one hour, which is the default */
  horizonSeconds?: number;
}

/** the builder options of a seat's rules, in one place */
export function presentOptionsOf(r: { allowRaw?: boolean; settlementHorizonSeconds?: number }): Required<BuildOptions> {
  return { allowRaw: r.allowRaw === true, horizonSeconds: r.settlementHorizonSeconds ?? VALIDATOR_HORIZON_SECONDS };
}

const GRANT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const bad = (detail: string): BuildResult => ({ ok: false, detail });
/** the decoder's reasons about the calldata TEXT: the text is not calldata at all, so no kind, raw included, can describe it */
const TEXT_REASONS = new Set(['calldata_prefix_invalid', 'calldata_too_large', 'calldata_hex_invalid', 'calldata_odd_length']);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function blobBytes(hex: unknown): Uint8Array | null {
  if (typeof hex !== 'string') return null;
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) return null;
  return new Uint8Array(Buffer.from(h, 'hex'));
}

function chainIdOf(leg: Record<string, unknown>, payload: Record<string, unknown>): number | null {
  const norm = (v: unknown): number | null | undefined => {
    if (v === undefined || v === null) return undefined;
    const n = typeof v === 'string' && /^[1-9][0-9]*$/.test(v) ? Number(v) : v;
    return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : null;
  };
  const a = norm(payload['chainId']);
  const b = norm(leg['chainId']);
  if (a === null || b === null) return null;
  if (a !== undefined && b !== undefined && a !== b) return null;
  return a ?? b ?? null;
}

/** a canonical address: 0x and 40 LOWER-case hex digits, exactly as the core hashes it. A checksum-case spelling is refused, as the strict decoder refuses it (DAX7A-F2). */
const lowerAddress = (v: unknown): string | null => (typeof v === 'string' && ADDRESS_RE.test(v) ? v : null);

export function buildPresentedRequest(tx: Pick<ResolvedTx, 'txHash' | 'rawTransaction' | 'summary'> & { header?: Pick<TransactionHeaderInfo, 'expiresAt'> }, opts: BuildOptions = {}): BuildResult {
  const allowRaw = opts.allowRaw === true;
  const horizonSeconds = opts.horizonSeconds ?? VALIDATOR_HORIZON_SECONDS;
  const raw = tx.rawTransaction;
  const body = isObj(raw) && isObj(raw['body']) ? raw['body'] : undefined;
  if (body === undefined || body['type'] !== 'writeData') return bad('not_write_data');
  const entry = body['entry'];
  const data = isObj(entry) ? entry['data'] : undefined;
  if (!Array.isArray(data) || data.length !== 4) return bad('entry_shape');
  const bytes: Uint8Array[] = [];
  for (const el of data) {
    const b = blobBytes(el);
    if (b === null) return bad('entry_not_hex');
    bytes.push(b);
  }
  let operationId: string;
  try {
    operationId = validatorOperationId(bytes);
  } catch (e) {
    if (e instanceof OperationIdError) return bad(`operation_id:${e.reason}`);
    throw e;
  }
  const blobs = bytes.map((b) => JSON.parse(Buffer.from(b).toString('utf8')) as unknown);
  const blob0 = blobs[0];
  const crossChain = blobs[1];
  if (!isObj(blob0) || !isObj(crossChain)) return bad('blob_not_object');

  // the claim of a Grant (conditional spread at the producer: absent is "none", present but malformed is refused)
  let grantRef: PresentedRequest['grantRef'] = null;
  if ('grantRef' in blob0) {
    const g = blob0['grantRef'];
    if (!isObj(g)) return bad('grantref_malformed');
    const { grantId, version, grantHash } = g;
    if (typeof grantId !== 'string' || !GRANT_ID_RE.test(grantId) || typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1 || typeof grantHash !== 'string' || !HASH_RE.test(grantHash)) return bad('grantref_malformed');
    grantRef = { grantId, version, grantHash };
  }

  const legs = crossChain['legs'];
  if (!Array.isArray(legs) || legs.length === 0) return bad('no_leg');
  // DE-76: legCount is DERIVED from the transaction's legs and ALWAYS supplied; the core refuses a legCount other than 1
  // (multi_leg_unsupported) before it compares anything. A request is still built from the first leg so the core can read the
  // presented transaction; when that leg cannot be mapped either, a placeholder that the core can hash stands in. It is never
  // compared (the refusal comes first). It IS sent to a Console, as the `binding` of a several-leg intent with `legCount` above 1
  // (DAX-4S round 4): the Console refuses a count other than 1 by name before it compares anything, so the members only have to be
  // hashable, and a decision for it is never issued.
  const txHash = '0x' + tx.txHash.replace(/^0x/, '').toLowerCase();
  if (!HASH_RE.test(txHash)) return bad('tx_hash');
  const mapped = mapLeg(legs[0], txHash, operationId, allowRaw);
  let request: Record<string, string | number>;
  let execution: PolicyExecution | null = null;
  let leafExpiry: number | null = null;
  if (mapped.ok) {
    request = mapped.request;
    if (legs.length === 1) {
      // AUTHENTICATE the execution a decision service will decode (DAX7C-F1): the commitment the intent STATES must be the core's single-call
      // commitment of the bytes this leg executes. The signer never sends a request it cannot verify itself, and never votes on one.
      const e = mapped.execution;
      const bytes = new Uint8Array(Buffer.from(e.calldata.slice(2), 'hex'));
      if (singleCommitment(e.chainId, e.target, e.value, bytes) !== request['executionCommitment']) return bad('execution_commitment_mismatch');
      execution = e;
      // DE-87, DE-88: the leaf expiry bound of a ONE-leg transaction, from the leg's declared deadline and the header deadline. A leg deadline that is
      // negative or not an integer, a header deadline that is not an exact UTC instant and a horizon below the validator's hour are refused, never
      // repaired; a transaction with neither deadline has no bound (null: the member is omitted, never guessed).
      const leg0 = legs[0];
      const declared = isObj(leg0) && leg0['deadline_timestamp'] !== undefined && leg0['deadline_timestamp'] !== null ? leg0['deadline_timestamp'] : 0;
      const lb = leafExpiryBound({ legDeadlines: [declared], headerExpiresAt: tx.header?.expiresAt ?? null, horizonSeconds });
      if (lb.ok) leafExpiry = lb.leafExpiry;
      else if (lb.reason !== 'leaf_expiry_unavailable') return bad(lb.detail === undefined ? lb.reason : `${lb.reason}:${lb.detail}`);
    }
  }
  else if (legs.length !== 1) request = unboundPlaceholder(txHash, operationId);
  else return mapped.reason === undefined ? bad(mapped.detail) : { ok: false, detail: mapped.detail, reason: mapped.reason };

  const s = tx.summary.subject;
  const assertedSubject = s !== undefined && typeof s.adi === 'string' && typeof s.assertedBy === 'string' ? { adi: s.adi, assertedBy: s.assertedBy } : null;

  return {
    ok: true,
    value: {
      request,
      legCount: legs.length,
      grantRef,
      grantRefHash: grantRef === null ? null : grantRef.grantHash,
      assertedSubject,
      operationId,
      execution,
      leafExpiry,
    },
  };
}

const ZERO20 = '0x' + '00'.repeat(20);
const ZERO32 = '0x' + '00'.repeat(32);

/** The request the core reads when the transaction has more than one leg: hashable, never compared (see buildPresentedRequest). */
function unboundPlaceholder(txHash: string, operationId: string): Record<string, string | number> {
  return { chainId: 1, kind: 'native.transfer', source: ZERO20, target: ZERO20, beneficiary: ZERO20, asset: 'native', amount: '0', executionCommitment: ZERO32, operationId, txHash };
}

type Mapped = { ok: true; request: Record<string, string | number>; execution: PolicyExecution } | { ok: false; detail: string; reason?: 'binding_absent' };

/** One leg of the intent as the ten members of the request (the mapping of the header comment). */
function mapLeg(leg: unknown, txHash: string, operationId: string, allowRaw: boolean): Mapped {
  const fail = (detail: string): Mapped => ({ ok: false, detail });
  if (!isObj(leg)) return fail('leg_not_object');
  const payload = isObj(leg['executionPayload']) ? leg['executionPayload'] : undefined;
  if (payload === undefined) return fail('no_execution_payload');

  const chainId = chainIdOf(leg, payload);
  if (chainId === null) return fail('chain_id');
  const source = lowerAddress(leg['from'] ?? payload['from']);
  if (source === null) return fail('source_address');
  const targetPayload = lowerAddress(payload['target']);
  const targetLeg = lowerAddress(leg['to']);
  if (targetPayload === null && targetLeg === null) return fail('target_address');
  if (targetPayload !== null && targetLeg !== null && targetPayload !== targetLeg) return fail('target_disagrees');
  const target = (targetPayload ?? targetLeg)!;
  const commitment = typeof payload['executionCommitment'] === 'string' ? payload['executionCommitment'].toLowerCase() : '';
  if (!HASH_RE.test(commitment)) return fail('execution_commitment');

  // native value of the call: the payload's `value` and the leg's `amountWei` must agree when both are stated
  const valueP = payload['value'] === undefined || payload['value'] === null ? undefined : String(payload['value']);
  const valueL = leg['amountWei'] === undefined || leg['amountWei'] === null ? undefined : String(leg['amountWei']);
  if (valueP !== undefined && valueL !== undefined && valueP !== valueL) return fail('value_disagrees');
  const value = valueP ?? valueL;

  // the calldata text is the core's: `0x` and lower-case hex of whole bytes (DE-91). An absent member is no calldata. What the text is not (not a
  // string, no prefix, upper case, an odd number of digits, too large) is refused HERE by the decoder's own reason and is never normalised.
  const cd = payload['callData'];
  if (cd !== undefined && cd !== null && typeof cd !== 'string') return fail('calldata_not_text');
  const calldata = typeof cd === 'string' ? cd : '0x';
  const nativeCall = calldata === '0x';
  if (nativeCall ? value === undefined || !isAmount(value) : value !== undefined && !isAmount(value)) return fail(nativeCall ? 'native_amount' : 'value_malformed');

  // The strict decode: the core decoder reads the bytes. The signer has no token registry, so it names the called address as the token (and the
  // chain's native currency): the STRUCTURE is decoded exactly and raw base units and addresses are bound. Everything else is undecoded.
  const registry = { schema: 'certen.tokenreg/v1', tokens: [{ chainId, address: 'native', symbol: 'NATIVE', decimals: 0 }, { chainId, address: target, symbol: 'TOKEN', decimals: 0 }] };
  const decoded = decode({ chainId, source, target, value: value ?? '0', calldata }, registry, { allowRaw });
  if (decoded.status === 'undecoded') {
    if (TEXT_REASONS.has(decoded.reason)) return fail(decoded.reason);
    // the input of the decoder is built and checked above: a decoder that cannot read it is a defect, refused by name and never bound
    if (decoded.reason === 'input_malformed' || decoded.reason === 'registry_invalid' || decoded.reason === 'policy_invalid') return fail(`decoder_${decoded.reason}`);
  }
  // DE-91: a typed kind only when the decoder DECODED; otherwise raw at a seat that allows it, NOT BOUND at every other
  const m = mapDecoded(decoded, allowRaw);
  if (!m.ok) return m.reason === 'binding_absent' ? { ok: false, reason: 'binding_absent', detail: decoded.status === 'undecoded' ? decoded.reason : 'undecoded' } : fail('map_input_malformed');
  let kind: string;
  let beneficiary: string;
  let asset: string;
  let amount: string;
  if (m.kind === 'raw') {
    // DE-90: the three members a raw call maps are the target, native and the native value
    kind = 'raw';
    beneficiary = target;
    asset = 'native';
    amount = value ?? '0';
  } else if (decoded.status === 'decoded') {
    kind = decoded.kind;
    beneficiary = decoded.beneficiary;
    asset = decoded.asset;
    amount = decoded.amount;
  } else return fail('map_input_malformed');
  // the execution of this leg: the same chainId, source and target as the request, the native value as a decimal string ('0' for a call that sends
  // none) and exactly the calldata text that was decoded (`0x` alone for a native transfer)
  const execution: PolicyExecution = { chainId, source, target, value: value ?? '0', calldata };
  return { ok: true, request: { chainId, kind, source, target, beneficiary, asset, amount, executionCommitment: commitment, operationId, txHash }, execution };
}
