/**
 * The REQUEST of DECISION.md section 2, built from the transaction the signer is ABOUT TO SIGN.
 *
 * `requestHash` is recomputed by the core (`hashRequest`) over this object; the decision's own `requestHash` is only ever
 * compared with it, never used to build it. Everything here comes from the pending Accumulate transaction's own data entry:
 * the four blobs (the validator operation id is recomputed from their bytes), the single leg and its execution payload. Nothing
 * is taken from the policy reply, the Console or the producer's declared ids.
 *
 * What a request can be, and what it cannot (a refusal is a named `presented_malformed` detail, never a guess):
 *   - ONE leg. A multi-leg intent is several executions under one operation and cannot be bound by a one-leg request hash.
 *   - kind `native.transfer` (empty calldata), `erc20.transfer` or `erc20.approve` (the calldata decoded exactly: one 32-byte
 *     word per parameter). `transferFrom`, any other selector and any call that forwards native value with calldata are refused.
 *   - `executionCommitment` is the value the intent STATES (`executionPayload.executionCommitment`); the signer does not
 *     recompute its keccak (DECISION.md section 2: taken from the intent; DAX-7 recomputes the displayed view from the bytes).
 *   - `chainId` must be numeric (`executionPayload.chainId` or `chainId`; both present must agree). A chain NAME is not an id.
 * The mapping is the signer's reading of the intent format; the Console must build the same object (OQ-DAX4S-2).
 */
import { ADDRESS_RE, HASH_RE, isAmount } from '../core/bytes.js';
import { decodeErc20Calldata } from '../decode/decoders/certen-intent.js';
import type { ResolvedTx } from '../types.js';
import { OperationIdError, validatorOperationId } from './operation-id.js';

export interface PresentedRequest {
  /** the closed object the core hashes (`hashRequest`): ten members */
  request: Record<string, string | number>;
  /** the producer's CLAIM of the Grant (blob 0 `grantRef`), or null when the intent names none; the head is read from Accumulate, never from this */
  grantRef: { grantId: string; version: number; grantHash: string } | null;
  /** `grantRef.grantHash` or null: the core's `grantRefHash` */
  grantRefHash: string | null;
  /** the intent's asserted subject, or null; the world resolves it, the signer never trusts it */
  assertedSubject: { adi: string; assertedBy: string } | null;
  /** the validator operation id (also inside `request.operationId`) */
  operationId: string;
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

const lowerAddress = (v: unknown): string | null => {
  if (typeof v !== 'string') return null;
  const l = v.toLowerCase();
  return ADDRESS_RE.test(l) ? l : null;
};

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
  if (legs.length !== 1) return bad('multi_leg');
  const leg = legs[0];
  if (!isObj(leg)) return bad('leg_not_object');
  const payload = isObj(leg['executionPayload']) ? leg['executionPayload'] : undefined;
  if (payload === undefined) return bad('no_execution_payload');

  const chainId = chainIdOf(leg, payload);
  if (chainId === null) return bad('chain_id');
  const source = lowerAddress(leg['from'] ?? payload['from']);
  if (source === null) return bad('source_address');
  const targetPayload = lowerAddress(payload['target']);
  const targetLeg = lowerAddress(leg['to']);
  if (targetPayload === null && targetLeg === null) return bad('target_address');
  if (targetPayload !== null && targetLeg !== null && targetPayload !== targetLeg) return bad('target_disagrees');
  const target = (targetPayload ?? targetLeg)!;
  const commitment = typeof payload['executionCommitment'] === 'string' ? payload['executionCommitment'].toLowerCase() : '';
  if (!HASH_RE.test(commitment)) return bad('execution_commitment');

  // native value of the call: the payload's `value` and the leg's `amountWei` must agree when both are stated
  const valueP = payload['value'] === undefined || payload['value'] === null ? undefined : String(payload['value']);
  const valueL = leg['amountWei'] === undefined || leg['amountWei'] === null ? undefined : String(leg['amountWei']);
  if (valueP !== undefined && valueL !== undefined && valueP !== valueL) return bad('value_disagrees');
  const value = valueP ?? valueL;

  const cd = payload['callData'];
  const callData = typeof cd === 'string' ? cd.replace(/^0x/, '') : cd === undefined || cd === null ? '' : null;
  if (callData === null) return bad('calldata_not_text');

  let kind: string;
  let beneficiary: string;
  let asset: string;
  let amount: string;
  if (callData === '') {
    if (value === undefined || !isAmount(value)) return bad('native_amount');
    kind = 'native.transfer';
    beneficiary = target;
    asset = 'native';
    amount = value;
  } else {
    const dec = decodeErc20Calldata('0x' + callData);
    if (dec === undefined) return bad('calldata_unsupported');
    if (dec.fn === 'transferFrom') return bad('action_unsupported');
    if (value !== undefined && value !== '0') return bad('value_with_call');
    const who = dec.fn === 'transfer' ? dec.args['to'] : dec.args['spender'];
    const b = lowerAddress(who);
    if (b === null || !isAmount(dec.amount)) return bad('calldata_arguments');
    kind = dec.fn === 'transfer' ? 'erc20.transfer' : 'erc20.approve';
    beneficiary = b;
    asset = target;
    amount = dec.amount;
  }

  const txHash = '0x' + tx.txHash.replace(/^0x/, '').toLowerCase();
  if (!HASH_RE.test(txHash)) return bad('tx_hash');

  const s = tx.summary.subject;
  const assertedSubject = s !== undefined && typeof s.adi === 'string' && typeof s.assertedBy === 'string' ? { adi: s.adi, assertedBy: s.assertedBy } : null;

  return {
    ok: true,
    value: {
      request: { chainId, kind, source, target, beneficiary, asset, amount, executionCommitment: commitment, operationId, txHash },
      grantRef,
      grantRefHash: grantRef === null ? null : grantRef.grantHash,
      assertedSubject,
      operationId,
    },
  };
}
