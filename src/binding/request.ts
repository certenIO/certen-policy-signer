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
 *   - kind `native.transfer` (empty calldata), `erc20.transfer` or `erc20.approve` (the calldata decoded exactly: one 32-byte
 *     word per parameter). `transferFrom`, any other selector and any call that forwards native value with calldata are refused.
 *   - `executionCommitment` is the value the intent STATES (`executionPayload.executionCommitment`); the signer does not
 *     recompute its keccak (DECISION.md section 2: taken from the intent; DAX-7 recomputes the displayed view from the bytes).
 *   - `chainId` must be numeric (`executionPayload.chainId` or `chainId`; both present must agree). A chain NAME is not an id.
 * The mapping is the signer's reading of the intent format; the Console must build the same object (OQ-DAX4S-2).
 */
import { ADDRESS_RE, HASH_RE, isAmount } from '../core/bytes.js';
import { singleCommitment } from '../core/calldata-keccak.js';
import { decodeErc20Calldata } from '../decode/decoders/certen-intent.js';
import type { PolicyExecution, ResolvedTx } from '../types.js';
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
}

export type BuildResult = { ok: true; value: PresentedRequest } | { ok: false; detail: string };

const GRANT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const bad = (detail: string): BuildResult => ({ ok: false, detail });
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

export function buildPresentedRequest(tx: Pick<ResolvedTx, 'txHash' | 'rawTransaction' | 'summary'>): BuildResult {
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
  const mapped = mapLeg(legs[0], txHash, operationId);
  let request: Record<string, string | number>;
  let execution: PolicyExecution | null = null;
  if (mapped.ok) {
    request = mapped.request;
    if (legs.length === 1) {
      // AUTHENTICATE the execution a decision service will decode (DAX7C-F1): the commitment the intent STATES must be the core's single-call
      // commitment of the bytes this leg executes. The signer never sends a request it cannot verify itself, and never votes on one.
      const e = mapped.execution;
      const bytes = new Uint8Array(Buffer.from(e.calldata.slice(2), 'hex'));
      if (singleCommitment(e.chainId, e.target, e.value, bytes) !== request['executionCommitment']) return bad('execution_commitment_mismatch');
      execution = e;
    }
  }
  else if (legs.length !== 1) request = unboundPlaceholder(txHash, operationId);
  else return bad(mapped.detail);

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
    },
  };
}

const ZERO20 = '0x' + '00'.repeat(20);
const ZERO32 = '0x' + '00'.repeat(32);

/** The request the core reads when the transaction has more than one leg: hashable, never compared (see buildPresentedRequest). */
function unboundPlaceholder(txHash: string, operationId: string): Record<string, string | number> {
  return { chainId: 1, kind: 'native.transfer', source: ZERO20, target: ZERO20, beneficiary: ZERO20, asset: 'native', amount: '0', executionCommitment: ZERO32, operationId, txHash };
}

type Mapped = { ok: true; request: Record<string, string | number>; execution: PolicyExecution } | { ok: false; detail: string };

/** One leg of the intent as the ten members of the request (the mapping of the header comment). */
function mapLeg(leg: unknown, txHash: string, operationId: string): Mapped {
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

  // the calldata text is read as strictly as the strict core decoder reads it (DAX7A-F2): `0x` in lower case is required (an absent
  // member is no calldata), the digits are hex of either case, an even number of them
  const cd = payload['callData'];
  if (cd !== undefined && cd !== null && typeof cd !== 'string') return fail('calldata_not_text');
  if (typeof cd === 'string' && !cd.startsWith('0x')) return fail('calldata_prefix_invalid');
  const callData = typeof cd === 'string' ? cd.slice(2) : '';

  let kind: string;
  let beneficiary: string;
  let asset: string;
  let amount: string;
  if (callData === '') {
    if (value === undefined || !isAmount(value)) return fail('native_amount');
    kind = 'native.transfer';
    beneficiary = target;
    asset = 'native';
    amount = value;
  } else {
    const dec = decodeErc20Calldata('0x' + callData);
    if (dec === undefined) return fail('calldata_unsupported');
    if (dec.fn === 'transferFrom') return fail('action_unsupported');
    // the address word must be a clean 32-byte word (12 zero bytes, then the address): the reading below takes the low 20 bytes, and
    // another reading must not take a different address from the same bytes (u08, u31 of the golden cases)
    if (!/^0{24}/.test(callData.slice(8, 72))) return fail('address_pad_dirty');
    if (value !== undefined && value !== '0') return fail('value_with_call');
    const who = dec.fn === 'transfer' ? dec.args['to'] : dec.args['spender'];
    const b = lowerAddress(who);
    if (b === null || !isAmount(dec.amount)) return fail('calldata_arguments');
    kind = dec.fn === 'transfer' ? 'erc20.transfer' : 'erc20.approve';
    beneficiary = b;
    asset = target;
    amount = dec.amount;
  }
  // the execution of this leg: the same chainId, source and target as the request, the native value as a decimal string ('0' for a call that sends
  // none) and exactly the calldata bytes, `0x` and lower-case hex (`0x` alone for a native transfer)
  const execution: PolicyExecution = { chainId, source, target, value: value ?? '0', calldata: '0x' + callData.toLowerCase() };
  return { ok: true, request: { chainId, kind, source, target, beneficiary, asset, amount, executionCommitment: commitment, operationId, txHash }, execution };
}
