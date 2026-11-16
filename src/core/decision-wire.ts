/**
 * The wire shape of the bound request and the execution member handed to a seat (DECISION.md section 2: the conformance
 * table, DE-79, DE-80, DE-85). These are the SINGLE reference implementations the Console and the signer share instead of
 * two private parsers (finding DAX4C-F16: the signer's type lacked legCount and the Console's parser refused every real
 * request, and no test saw the disagreement).
 *
 *   parseWireBinding({ binding, requestTxHash? }) parses `PolicyRequest.binding`. It answers binding_absent (absent or
 *   null), binding_malformed (not an object, an unknown member, a missing member, a grantRef of another shape) or
 *   binding_field_invalid (a member of the wrong type or range, a txHash that is not the transaction's), each with a
 *   `detail` that names the member; or ok with the ten request members (validatorOperationId carried as the request member
 *   `operationId`), the request hash, legCount and the optional grantRef (a CLAIM of the producer, never trusted) and
 *   leafExpiry. The order of the checks is the specification's: absent, object, unknown members, missing members in the
 *   order of the table, grantRef, leafExpiry, txHash (and its equality with the transaction), validatorOperationId,
 *   legCount, chainId, kind, the addresses, asset, amount, executionCommitment.
 *
 *   authenticateExecution(binding, execution) authenticates the raw execution by the bound commitment:
 *   keccak256(chainId as 32 bytes || target || value as 32 bytes || keccak256(calldata)). The order: the binding
 *   (binding_*), multi_leg_unsupported (legCount 2 or more: the binding is valid, the SEAT refuses it, and its execution is
 *   omitted), execution_absent (undefined: the member is omitted, never null), execution_malformed (null included), the
 *   chain, source and target, then the commitment (request_execution_mismatch, the detail names the member), then, for a binding of
 *   kind raw only, the raw mapping (DE-90): beneficiary = target, asset = native, amount = the native value, else
 *   raw_mapping_mismatch with the detail naming the member. The execution of a raw call is REQUIRED (execution_absent).
 *
 * Pure functions of their arguments: no I/O, no clock; the keccak is the core's own (calldata-keccak.ts).
 */
import { HASH_RE, fromHex, hasLoneSurrogate, isAmount } from './bytes.js';
import { MAX_CALLDATA_BYTES } from './calldata.js';
import { normalizeAddress, singleCommitment } from './calldata-keccak.js';
import { ACTION_KINDS } from './grant-profile.js';
import { hashRequest } from './hashes.js';
import { dataObject, isPositiveInt, isTime } from './decision-identity.js';

/** the members of `binding` in the order of the conformance table */
export const WIRE_BINDING_MEMBERS = ['chainId', 'kind', 'source', 'target', 'beneficiary', 'asset', 'amount', 'executionCommitment', 'validatorOperationId', 'txHash', 'legCount'] as const;
export const WIRE_BINDING_OPTIONAL = ['grantRef', 'leafExpiry'] as const;
export const EXECUTION_MEMBERS = ['chainId', 'source', 'target', 'value', 'calldata'] as const;
const GRANT_REF_MEMBERS = ['grantId', 'version', 'grantHash'] as const;
const MAX_GRANT_ID = 256;

export interface WireRequest {
  chainId: number;
  kind: string;
  source: string;
  target: string;
  beneficiary: string;
  asset: string;
  amount: string;
  executionCommitment: string;
  operationId: string;
  txHash: string;
}
export interface GrantRefClaim { grantId: string; version: number; grantHash: string }
export interface WireBinding extends Omit<WireRequest, 'operationId'> { validatorOperationId: string; legCount: number }

export type WireBindingResult =
  | { ok: true; binding: WireBinding; request: WireRequest; requestHash: string; legCount: number; grantRef: GrantRefClaim | null; leafExpiry: number | null }
  | { ok: false; reason: 'binding_absent' | 'binding_malformed' | 'binding_field_invalid' | 'address_checksum_invalid'; detail?: string };

const refuse = (reason: 'binding_absent' | 'binding_malformed' | 'binding_field_invalid' | 'address_checksum_invalid', detail?: string): { ok: false; reason: typeof reason; detail?: string } => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });
const isHash = (v: unknown): v is string => typeof v === 'string' && HASH_RE.test(v);
/** an address that arrived in lower case or in the EIP-55 checksum case, as its lower-case canonical form; the refusal names the member (round 8, DE-106) */
function addressOf(v: unknown, member: string): { ok: true; address: string } | { ok: false; reason: 'binding_field_invalid' | 'address_checksum_invalid'; detail: string } {
  const a = normalizeAddress(v);
  return a.ok ? a : { ok: false, reason: a.reason === 'address_checksum_invalid' ? 'address_checksum_invalid' : 'binding_field_invalid', detail: member };
}

export function parseWireBinding(input: unknown): WireBindingResult {
  const inp = dataObject(input);
  if (inp === null) return refuse('binding_absent');
  const raw = inp['binding'];
  if (raw === undefined || raw === null) return refuse('binding_absent');
  const o = dataObject(raw);
  if (o === null) return refuse('binding_malformed', 'not an object');
  for (const k of Object.keys(o)) {
    if (!(WIRE_BINDING_MEMBERS as readonly string[]).includes(k) && !(WIRE_BINDING_OPTIONAL as readonly string[]).includes(k)) return refuse('binding_malformed', 'unknown member ' + k);
  }
  for (const m of WIRE_BINDING_MEMBERS) if (o[m] === undefined) return refuse('binding_malformed', 'missing member ' + m);

  // grantRef: the producer's claim, exactly { grantId, version, grantHash }
  let grantRef: GrantRefClaim | null = null;
  if (o['grantRef'] !== undefined && o['grantRef'] !== null) {
    const g = dataObject(o['grantRef']);
    if (g === null) return refuse('binding_malformed', 'grantRef');
    const keys = Object.keys(g);
    if (keys.length !== GRANT_REF_MEMBERS.length || !GRANT_REF_MEMBERS.every((k) => keys.includes(k))) return refuse('binding_malformed', 'grantRef');
    const id = g['grantId'];
    if (typeof id !== 'string' || id.length < 1 || id.length > MAX_GRANT_ID || hasLoneSurrogate(id) || !isPositiveInt(g['version']) || !isHash(g['grantHash'])) return refuse('binding_field_invalid', 'grantRef');
    grantRef = { grantId: id, version: g['version'], grantHash: g['grantHash'] };
  }
  let leafExpiry: number | null = null;
  if (o['leafExpiry'] !== undefined) {
    if (!isTime(o['leafExpiry'])) return refuse('binding_field_invalid', 'leafExpiry');
    leafExpiry = o['leafExpiry'];
  }

  if (!isHash(o['txHash'])) return refuse('binding_field_invalid', 'txHash');
  const requestTxHash = inp['requestTxHash'];
  if (requestTxHash !== undefined && requestTxHash !== o['txHash']) return refuse('binding_field_invalid', 'txHash differs from the request');
  if (!isHash(o['validatorOperationId'])) return refuse('binding_field_invalid', 'validatorOperationId');
  if (!isPositiveInt(o['legCount'])) return refuse('binding_field_invalid', 'legCount');
  if (!isPositiveInt(o['chainId'])) return refuse('binding_field_invalid', 'chainId');
  if (typeof o['kind'] !== 'string' || !(ACTION_KINDS as readonly string[]).includes(o['kind'])) return refuse('binding_field_invalid', 'kind');
  // every address is read once, in lower case or the checksum case, and is the lower-case form from here on: the hash, the commitment and every comparison are over it
  const addr: Record<'source' | 'target' | 'beneficiary' | 'asset', string> = { source: '', target: '', beneficiary: '', asset: '' };
  for (const m of ['source', 'target', 'beneficiary'] as const) {
    const a = addressOf(o[m], m);
    if (!a.ok) return refuse(a.reason, a.detail);
    addr[m] = a.address;
  }
  if (o['asset'] === 'native') addr.asset = 'native';
  else {
    const a = addressOf(o['asset'], 'asset');
    if (!a.ok) return refuse(a.reason, a.detail);
    addr.asset = a.address;
  }
  if (!isAmount(o['amount'])) return refuse('binding_field_invalid', 'amount');
  if (!isHash(o['executionCommitment'])) return refuse('binding_field_invalid', 'executionCommitment');

  const request: WireRequest = {
    chainId: o['chainId'],
    kind: o['kind'],
    source: addr.source,
    target: addr.target,
    beneficiary: addr.beneficiary,
    asset: addr.asset,
    amount: o['amount'],
    executionCommitment: o['executionCommitment'],
    operationId: o['validatorOperationId'],
    txHash: o['txHash'],
  };
  const binding: WireBinding = {
    chainId: request.chainId,
    kind: request.kind,
    source: request.source,
    target: request.target,
    beneficiary: request.beneficiary,
    asset: request.asset,
    amount: request.amount,
    executionCommitment: request.executionCommitment,
    validatorOperationId: request.operationId,
    txHash: request.txHash,
    legCount: o['legCount'],
  };
  return { ok: true, binding, request, requestHash: hashRequest(request), legCount: o['legCount'], grantRef, leafExpiry };
}

export type ExecutionResult =
  | { ok: true; commitment: string }
  | { ok: false; reason: 'binding_absent' | 'binding_malformed' | 'binding_field_invalid' | 'address_checksum_invalid' | 'multi_leg_unsupported' | 'execution_absent' | 'execution_malformed' | 'request_execution_mismatch' | 'raw_mapping_mismatch'; detail?: string };

const refuseExec = (reason: 'address_checksum_invalid' | 'multi_leg_unsupported' | 'execution_absent' | 'execution_malformed' | 'request_execution_mismatch' | 'raw_mapping_mismatch', detail?: string): ExecutionResult => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });
const CALLDATA_RE = /^0x([0-9a-f]{2})*$/;

/**
 * The execution member of the request handed to a one-leg seat: chainId, source, target, value (decimal text, never a
 * number) and calldata (0x plus lowercase hex of whole bytes). It is authenticated, never trusted, by the bound
 * executionCommitment. `binding` is the wire binding as sent (the same parse as parseWireBinding); `execution` is
 * undefined when the member is omitted.
 */
export function authenticateExecution(binding: unknown, execution: unknown): ExecutionResult {
  const p = parseWireBinding({ binding });
  if (!p.ok) return p;
  if (p.legCount !== 1) return refuseExec('multi_leg_unsupported', 'legCount ' + p.legCount);
  if (execution === undefined) return refuseExec('execution_absent');
  const e = dataObject(execution);
  if (e === null) return refuseExec('execution_malformed', 'not an object');
  for (const k of Object.keys(e)) if (!(EXECUTION_MEMBERS as readonly string[]).includes(k)) return refuseExec('execution_malformed', 'unknown member ' + k);
  for (const m of EXECUTION_MEMBERS) if (e[m] === undefined) return refuseExec('execution_malformed', 'missing member ' + m);
  if (!isPositiveInt(e['chainId'])) return refuseExec('execution_malformed', 'chainId');
  const exSource = normalizeAddress(e['source']);
  if (!exSource.ok) return refuseExec(exSource.reason === 'address_checksum_invalid' ? 'address_checksum_invalid' : 'execution_malformed', 'source');
  const exTarget = normalizeAddress(e['target']);
  if (!exTarget.ok) return refuseExec(exTarget.reason === 'address_checksum_invalid' ? 'address_checksum_invalid' : 'execution_malformed', 'target');
  if (!isAmount(e['value'])) return refuseExec('execution_malformed', 'value');
  const calldata = e['calldata'];
  if (typeof calldata !== 'string' || !CALLDATA_RE.test(calldata) || (calldata.length - 2) / 2 > MAX_CALLDATA_BYTES) return refuseExec('execution_malformed', 'calldata');

  if (e['chainId'] !== p.binding.chainId) return refuseExec('request_execution_mismatch', 'chainId');
  if (exSource.address !== p.binding.source) return refuseExec('request_execution_mismatch', 'source');
  if (exTarget.address !== p.binding.target) return refuseExec('request_execution_mismatch', 'target');
  const commitment = singleCommitment(e['chainId'], exTarget.address, e['value'], fromHex(calldata.slice(2)));
  if (commitment === null || commitment !== p.binding.executionCommitment) return refuseExec('request_execution_mismatch', 'executionCommitment');
  // DE-90: the three members a raw binding maps are compared with the AUTHENTICATED execution, after the commitment
  if (p.binding.kind === 'raw') {
    if (p.binding.beneficiary !== exTarget.address) return refuseExec('raw_mapping_mismatch', 'beneficiary');
    if (p.binding.asset !== 'native') return refuseExec('raw_mapping_mismatch', 'asset');
    if (p.binding.amount !== e['value']) return refuseExec('raw_mapping_mismatch', 'amount');
  }
  return { ok: true, commitment };
}
