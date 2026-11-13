/**
 * Sign what you see (DAX-7A, DESIGN.md section 4 D12 and D13; DAX-7-A2 at module level; DECISION.md DE-53). The values a human
 * is shown are RECOMPUTED from the bound transaction, never taken from the screen, and a screen's claim is compared with them
 * member by member; any mismatch is refused by name. This is the module, not the screen: the Console wiring is DAX-7C.
 *
 * The bound transaction is { request, execution }: the request of DECISION.md section 2 (chainId, kind, source, target,
 * beneficiary, asset, amount, executionCommitment, operationId, txHash) and the execution it commits to (chainId, source,
 * target, value, calldata). The request's decoded members are not trusted: the execution is decoded, the request must agree
 * with the execution (chain, source, target, and the single-call commitment recomputed from the raw calldata) and with what the
 * decoder says (kind, beneficiary, asset, amount). The module only recomputes the single-call commitment of
 * CertenAccountV7.computeSingleCommitment; a request carrying a multi-leg batch commitment is refused as
 * request_execution_mismatch{executionCommitment}.
 *
 * Refusals, in the order they are decided: bound_malformed, request_malformed{member}, input_malformed, registry_invalid,
 * policy_invalid (from the decode), decode_required{detail: why it is undecoded}, request_execution_mismatch{member},
 * request_decode_mismatch{member}; then the screen: display_malformed, display_incomplete{member}, display_mode_mismatch, and the
 * members in a fixed order. Decoded: kind, chainId, source, asset, assetSymbol, beneficiary, amountBase, amountText
 * (display_kind_mismatch, display_chain_mismatch, display_source_mismatch, display_asset_mismatch,
 * display_beneficiary_mismatch, display_amount_mismatch). Raw: chainId, source, target, value, calldataHash, text
 * (display_target_mismatch, display_amount_mismatch for the value, display_calldata_mismatch, display_raw_label_missing).
 */
import { CoreError } from './bytes.js';
import { dataObject } from './decision-identity.js';
import { requestPreimage } from './hashes.js';
import { singleCommitment, toChecksumAddress } from './calldata-keccak.js';
import { calldataBytes, decode } from './calldata.js';

export interface DecodedDisplaySet {
  mode: 'decoded';
  kind: string;
  chainId: number;
  source: string;
  beneficiary: string;
  /** the token address, or `native` */
  asset: string;
  assetSymbol: string;
  /** base units, decimal string */
  amountBase: string;
  /** the exact decimal expansion */
  amountText: string;
}
export interface RawDisplaySet {
  mode: 'raw';
  chainId: number;
  source: string;
  target: string;
  value: string;
  /** keccak256 of the calldata */
  calldataHash: string;
  /** must carry the word RAW and the calldata hash */
  text: string;
}
export type DisplayRefusal = { ok: false; reason: string; member?: string; detail?: string };
export type ExpectedDisplay =
  | { ok: true; mode: 'decoded'; expected: DecodedDisplaySet; unverified: string[] }
  | { ok: true; mode: 'raw'; expected: RawDisplaySet; unverified: string[] }
  | DisplayRefusal;
export type DisplayCheck = ExpectedDisplay;

/**
 * The ten members of the request of DECISION.md section 2, in the order hashes.ts hashes them. The last one is `txHash` (the
 * Accumulate transaction hash): the specification text and the DAX-7A brief spell it accumulateTxHash, the vectors and the code
 * do not, and no alias is accepted (DAX7A-F1). A test reads REQUEST_KEYS from hashes.ts and fails if this list differs.
 */
export const BOUND_REQUEST_MEMBERS = ['chainId', 'kind', 'source', 'target', 'beneficiary', 'asset', 'amount', 'executionCommitment', 'operationId', 'txHash'] as const;

const DECODED_MEMBERS = ['mode', 'kind', 'chainId', 'source', 'beneficiary', 'asset', 'assetSymbol', 'amountBase', 'amountText'] as const;
const RAW_MEMBERS = ['mode', 'chainId', 'source', 'target', 'value', 'calldataHash', 'text'] as const;
/** request members a raw approval cannot verify: they are the producer's claims about calldata nobody decoded */
const RAW_UNVERIFIED = ['kind', 'beneficiary', 'asset', 'amount'];

function refuse(reason: string, member?: string, detail?: string): DisplayRefusal {
  const out: DisplayRefusal = { ok: false, reason };
  if (member !== undefined) out.member = member;
  if (detail !== undefined) out.detail = detail;
  return out;
}

function expectedInner(bound: unknown, registry: unknown, policy: unknown): ExpectedDisplay {
  const b = dataObject(bound);
  if (b === null) return refuse('bound_malformed', undefined, 'shape');
  for (const k of Object.keys(b)) if (k !== 'request' && k !== 'execution') return refuse('bound_malformed', undefined, 'unknown:' + k);
  for (const k of ['request', 'execution']) if (b[k] === undefined) return refuse('bound_malformed', undefined, 'missing:' + k);

  const request = dataObject(b['request']);
  if (request === null) return refuse('request_malformed', undefined, 'shape');
  try {
    requestPreimage(request);
  } catch (e) {
    if (e instanceof CoreError) return refuse('request_malformed', e.detail);
    throw e;
  }

  const d = decode(b['execution'], registry, policy);
  let chainId: number;
  let source: string;
  let target: string;
  let value: string;
  if (d.status === 'undecoded') {
    if (d.reason === 'input_malformed' || d.reason === 'registry_invalid' || d.reason === 'policy_invalid') return refuse(d.reason, undefined, d.detail);
    if (d.approval !== 'raw_only' || d.execution === undefined || d.calldataHash === undefined) return refuse('decode_required', undefined, d.reason);
    ({ chainId, source, target, value } = d.execution);
  } else {
    ({ chainId, source, target, value } = d);
  }

  // the request against the execution it commits to
  if (request['chainId'] !== chainId) return refuse('request_execution_mismatch', 'chainId');
  if (request['source'] !== source) return refuse('request_execution_mismatch', 'source');
  if (request['target'] !== target) return refuse('request_execution_mismatch', 'target');
  const exec = dataObject(b['execution'])!;
  const bytes = calldataBytes(exec['calldata']);
  if (!bytes.ok) return refuse('request_execution_mismatch', 'executionCommitment');
  if (request['executionCommitment'] !== singleCommitment(chainId, target, value, bytes.bytes)) return refuse('request_execution_mismatch', 'executionCommitment');

  if (d.status === 'undecoded') {
    const raw: RawDisplaySet = { mode: 'raw', chainId, source, target, value, calldataHash: d.calldataHash!, text: d.text! };
    return { ok: true, mode: 'raw', expected: raw, unverified: [...RAW_UNVERIFIED] };
  }

  // the request against what the decoder says the bytes mean
  if (request['kind'] !== d.kind) return refuse('request_decode_mismatch', 'kind');
  if (request['beneficiary'] !== d.beneficiary) return refuse('request_decode_mismatch', 'beneficiary');
  if (request['asset'] !== d.asset) return refuse('request_decode_mismatch', 'asset');
  if (request['amount'] !== d.amount) return refuse('request_decode_mismatch', 'amount');
  const expected: DecodedDisplaySet = { mode: 'decoded', kind: d.kind, chainId, source, beneficiary: d.beneficiary, asset: d.asset, assetSymbol: d.assetSymbol, amountBase: d.amount, amountText: d.amountText };
  return { ok: true, mode: 'decoded', expected, unverified: [] };
}

/**
 * What a screen MUST show for the bound transaction { request, execution }, recomputed from it, or the named refusal that
 * stops the approval before any screen exists. Build the screen from this. Never throws.
 */
export function expectedDisplay(bound: unknown, registry: unknown, policy: unknown): ExpectedDisplay {
  try {
    return expectedInner(bound, registry, policy);
  } catch {
    return refuse('bound_malformed', undefined, 'unreadable');
  }
}

/** an address as a screen may show it: the lowercase canonical form, or its valid EIP-55 checksum form, nothing else */
const sameAddress = (shown: string, canonical: string): boolean => shown === canonical || shown === toChecksumAddress(canonical);

const RAW_WORD_RE = /(^|[^A-Za-z])RAW([^A-Za-z]|$)/;

function compareDisplayed(expected: ExpectedDisplay & { ok: true }, displayed: unknown): DisplayCheck {
  const s = dataObject(displayed);
  if (s === null) return refuse('display_malformed', undefined, 'shape');
  if (s['mode'] === undefined) return refuse('display_incomplete', 'mode');
  if (s['mode'] !== 'decoded' && s['mode'] !== 'raw') return refuse('display_malformed', 'mode');
  if (s['mode'] !== expected.mode) return refuse('display_mode_mismatch');

  const members: readonly string[] = expected.mode === 'decoded' ? DECODED_MEMBERS : RAW_MEMBERS;
  for (const m of members) if (s[m] === undefined) return refuse('display_incomplete', m);
  for (const k of Object.keys(s)) if (!members.includes(k)) return refuse('display_malformed', k);
  for (const m of members) {
    const v = s[m];
    if (m === 'chainId' ? typeof v !== 'number' || !Number.isSafeInteger(v) : typeof v !== 'string') return refuse('display_malformed', m);
  }

  if (expected.mode === 'decoded') {
    const e = expected.expected;
    if (s['kind'] !== e.kind) return refuse('display_kind_mismatch', 'kind');
    if (s['chainId'] !== e.chainId) return refuse('display_chain_mismatch', 'chainId');
    if (!sameAddress(s['source'] as string, e.source)) return refuse('display_source_mismatch', 'source');
    if (e.asset === 'native' ? s['asset'] !== 'native' : !sameAddress(s['asset'] as string, e.asset)) return refuse('display_asset_mismatch', 'asset');
    if (s['assetSymbol'] !== e.assetSymbol) return refuse('display_asset_mismatch', 'assetSymbol');
    if (!sameAddress(s['beneficiary'] as string, e.beneficiary)) return refuse('display_beneficiary_mismatch', 'beneficiary');
    if (s['amountBase'] !== e.amountBase) return refuse('display_amount_mismatch', 'amountBase');
    if (s['amountText'] !== e.amountText) return refuse('display_amount_mismatch', 'amountText');
    return expected;
  }

  const e = expected.expected;
  if (s['chainId'] !== e.chainId) return refuse('display_chain_mismatch', 'chainId');
  if (!sameAddress(s['source'] as string, e.source)) return refuse('display_source_mismatch', 'source');
  if (!sameAddress(s['target'] as string, e.target)) return refuse('display_target_mismatch', 'target');
  if (s['value'] !== e.value) return refuse('display_amount_mismatch', 'value');
  if (s['calldataHash'] !== e.calldataHash) return refuse('display_calldata_mismatch', 'calldataHash');
  const text = s['text'] as string;
  if (!RAW_WORD_RE.test(text) || !text.includes(e.calldataHash)) return refuse('display_raw_label_missing');
  return expected;
}

/**
 * DAX-7-A2: compare what a screen claims to show with what is bound. The displayed set is closed: decoded mode has the nine
 * members mode, kind, chainId, source, beneficiary, asset, assetSymbol, amountBase, amountText; raw mode the seven members
 * mode, chainId, source, target, value, calldataHash, text. Returns { ok: true, mode, expected, unverified } or the first
 * refusal in the documented order. Never throws.
 */
export function checkDisplayed(bound: unknown, displayed: unknown, registry: unknown, policy: unknown): DisplayCheck {
  try {
    const e = expectedInner(bound, registry, policy);
    if (!e.ok) return e;
    return compareDisplayed(e, displayed);
  } catch {
    return refuse('display_malformed', undefined, 'unreadable');
  }
}
