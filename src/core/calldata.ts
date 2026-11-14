/**
 * The calldata decoder (DAX-7A, DESIGN.md section 4; DAX-7-A1). It says what a transaction that is about to be approved MEANS
 * in the three actions of the closed Grant set (erc20.transfer, erc20.approve, native.transfer), or it says `undecoded` and
 * why. Unknown or malformed calldata is NEVER shown as if it were understood: an undecoded answer carries a reason from a
 * closed table, no amount, symbol or beneficiary as understood members, and `approval: decode_required` unless the policy
 * explicitly allows raw (then `raw_only`, and the screen must say RAW and show the calldata hash).
 *
 * Pure: no clock, no network, no chain read. Units and symbols come from the policy token registry and are the registry's
 * statement (a token whose registry decimals disagree with the chain is the registry's problem). Amounts are BigInt and
 * decimal strings throughout: no floating point, no rounding of any kind.
 *
 * decode(execution, registry, policy) never throws. The decisions are taken in this order and the first one that applies names
 * the result: input_malformed, registry_invalid, policy_invalid, then the calldata text (calldata_prefix_invalid,
 * calldata_too_large, calldata_hex_invalid, calldata_odd_length), the byte reading (calldata_selector_missing, selector_unknown,
 * proxy_not_named, calldata_too_short, calldata_trailing_bytes, address_pad_dirty, offset_noncanonical, padding_dirty,
 * proxy_nested, proxy_inner_unsupported), token_call_carries_value, token_unknown.
 */
import { ADDRESS_RE, isAmount, toHex } from './bytes.js';
import { closedObject, dataObject } from './decision-identity.js';
import { keccak256Hex } from './calldata-keccak.js';
import { findToken, isNamedProxy, validateTokenRegistry, type TokenEntry, type TokenRegistry } from './calldata-registry.js';

export const SELECTOR_TRANSFER = 'a9059cbb';
export const SELECTOR_APPROVE = '095ea7b3';
/** execute(address,uint256,bytes): the one wrapper form understood, and only for a wrapper the registry names */
export const SELECTOR_EXECUTE = 'b61d27f6';
/** transfer and approve calldata is exactly 4 + 64 bytes; a wrapper's head is 4 + 4 words */
export const MAX_CALLDATA_BYTES = 65536;
const ERC20_LENGTH = 68;
const EXECUTE_MIN_LENGTH = 132;

type Kind = 'erc20.transfer' | 'erc20.approve' | 'native.transfer';
type Refusal = { ok: false; reason: string; detail?: string };
const refuse = (reason: string, detail?: string): Refusal => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });

// ---- the text of calldata -----------------------------------------------------------------------------------------------

/**
 * `0x` (lowercase x, required) and LOWER-CASE hex digits only, an even number of them, at most 65,536 bytes (DE-91, DECISION.md
 * section 2: calldata is `0x` plus lowercase hex of whole bytes, never upper case, never without the prefix). An upper-case digit
 * (A-F, in any position, mixed case included) is `calldata_hex_invalid` here, in the decoder itself, exactly as it is at the seat's
 * wire path, so the review screen and the signer never disagree about what a calldata text means (DAX-CORE-2 R1, DAXCORE1-F2).
 * The size is judged from the length before any character is read. Nothing is trimmed or skipped: whitespace and every other
 * character are named.
 */
function parseHexBytes(v: unknown): { ok: true; bytes: Uint8Array } | Refusal {
  if (typeof v !== 'string') return refuse('calldata_not_text');
  if (v.length < 2 || v.charCodeAt(0) !== 0x30 || v.charCodeAt(1) !== 0x78) return refuse('calldata_prefix_invalid');
  const digits = v.length - 2;
  if (digits > 2 * MAX_CALLDATA_BYTES) return refuse('calldata_too_large');
  for (let i = 2; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return refuse('calldata_hex_invalid', 'index ' + i);
  }
  if (digits % 2 !== 0) return refuse('calldata_odd_length');
  const bytes = new Uint8Array(digits / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(v.slice(2 + 2 * i, 4 + 2 * i), 16);
  return { ok: true, bytes };
}

// ---- the bytes ----------------------------------------------------------------------------------------------------------

export type CalldataReading =
  | { ok: true; shape: 'native' }
  | { ok: true; shape: 'erc20'; kind: 'erc20.transfer' | 'erc20.approve'; address: string; amount: string }
  | { ok: true; shape: 'execute'; dest: string; value: string; data: string }
  | Refusal;

const hexOf = (b: Uint8Array, from: number, to: number): string => toHex(b.subarray(from, to));
const wordValue = (b: Uint8Array, from: number): bigint => BigInt('0x' + hexOf(b, from, from + 32));
const zeroPad = (b: Uint8Array, from: number, to: number): boolean => {
  for (let i = from; i < to; i++) if (b[i] !== 0) return false;
  return true;
};

/**
 * The structural reading of already-parsed calldata bytes: strict ABI, nothing guessed. For transfer and approve exactly
 * 4 + 64 bytes, an address word with 12 zero bytes, an amount word of any 32 bytes (so at most 2^256-1 by construction), and
 * nothing after it. For execute(address,uint256,bytes) the same strictness: zero pad, offset exactly 96, a length word, the
 * data, zero padding to a multiple of 32 and nothing after. Anything else is a named refusal; an unknown selector is
 * selector_unknown whatever follows it.
 */
function readBytes(b: Uint8Array): CalldataReading {
  if (b.length === 0) return { ok: true, shape: 'native' };
  if (b.length < 4) return refuse('calldata_selector_missing', 'got ' + b.length);
  const selector = hexOf(b, 0, 4);
  if (selector === SELECTOR_TRANSFER || selector === SELECTOR_APPROVE) {
    if (b.length < ERC20_LENGTH) return refuse('calldata_too_short', 'expected ' + ERC20_LENGTH + ' got ' + b.length);
    if (b.length > ERC20_LENGTH) return refuse('calldata_trailing_bytes', 'expected ' + ERC20_LENGTH + ' got ' + b.length);
    if (!zeroPad(b, 4, 16)) return refuse('address_pad_dirty');
    return { ok: true, shape: 'erc20', kind: selector === SELECTOR_TRANSFER ? 'erc20.transfer' : 'erc20.approve', address: '0x' + hexOf(b, 16, 36), amount: wordValue(b, 36).toString() };
  }
  if (selector === SELECTOR_EXECUTE) {
    if (b.length < EXECUTE_MIN_LENGTH) return refuse('calldata_too_short', 'expected at least ' + EXECUTE_MIN_LENGTH + ' got ' + b.length);
    if (!zeroPad(b, 4, 16)) return refuse('address_pad_dirty');
    if (wordValue(b, 68) !== 96n) return refuse('offset_noncanonical');
    const len = wordValue(b, 100);
    const expected = BigInt(EXECUTE_MIN_LENGTH) + ((len + 31n) / 32n) * 32n;
    if (BigInt(b.length) < expected) return refuse('calldata_too_short', 'expected ' + expected + ' got ' + b.length);
    if (BigInt(b.length) > expected) return refuse('calldata_trailing_bytes', 'expected ' + expected + ' got ' + b.length);
    const end = EXECUTE_MIN_LENGTH + Number(len);
    if (!zeroPad(b, end, b.length)) return refuse('padding_dirty');
    return { ok: true, shape: 'execute', dest: '0x' + hexOf(b, 16, 36), value: wordValue(b, 36).toString(), data: '0x' + hexOf(b, EXECUTE_MIN_LENGTH, end) };
  }
  return refuse('selector_unknown', selector);
}

/** The structural reading of calldata text (no units, no registry): `readCalldata('0x')` is the native shape. Never throws. */
export function readCalldata(calldata: unknown): CalldataReading {
  try {
    const p = parseHexBytes(calldata);
    return p.ok ? readBytes(p.bytes) : p;
  } catch {
    return refuse('calldata_not_text');
  }
}

/** The bytes of calldata text, or the named refusal of the text (used by the display check to recompute the commitment). */
export function calldataBytes(calldata: unknown): { ok: true; bytes: Uint8Array } | Refusal {
  try {
    return parseHexBytes(calldata);
  } catch {
    return refuse('calldata_not_text');
  }
}

// ---- exact units --------------------------------------------------------------------------------------------------------

/**
 * The exact decimal expansion of a base-unit amount with exactly `decimals` fractional digits: no trimming of trailing zeros,
 * no grouping, no rounding, no floating point (1 base unit of an 18-decimals token is 0.000000000000000001, 1500000 of a
 * 6-decimals token is 1.500000, a 0-decimals token has no point). Null for an amount that is not a base-unit decimal string
 * of at most 2^256-1 or decimals that are not an integer from 0 to 36.
 */
export function formatUnitsExact(amount: unknown, decimals: unknown): string | null {
  if (!isAmount(amount)) return null;
  if (typeof decimals !== 'number' || !Number.isInteger(decimals) || decimals < 0 || decimals > 36 || Object.is(decimals, -0)) return null;
  const n = BigInt(amount);
  if (decimals === 0) return n.toString();
  const unit = 10n ** BigInt(decimals);
  return (n / unit).toString() + '.' + (n % unit).toString().padStart(decimals, '0');
}

// ---- the result ---------------------------------------------------------------------------------------------------------

export interface DecodeExecution {
  chainId: number;
  source: string;
  target: string;
  value: string;
}
export interface DecodedCall {
  status: 'decoded';
  approval: 'decoded';
  kind: Kind;
  chainId: number;
  source: string;
  /** the contract that is called: the token, the named wrapper, or the recipient of a native send */
  target: string;
  /** the recipient of a transfer or a native send, the SPENDER of an approve */
  beneficiary: string;
  beneficiaryRole: 'recipient' | 'spender';
  /** the token address, or `native` */
  asset: string;
  assetSymbol: string;
  decimals: number;
  /** base units, decimal string */
  amount: string;
  /** the exact decimal expansion with exactly `decimals` fraction digits */
  amountText: string;
  unlimitedAllowance: boolean;
  viaProxy: string | null;
  /** native value of the outer call (0 for a token call) */
  value: string;
  /** keccak256 of the calldata bytes */
  calldataHash: string;
  text: string;
}
export interface UndecodedCall {
  status: 'undecoded';
  /** decode_required: cannot be approved; raw_only: the policy allows raw and there are bytes to show */
  approval: 'raw_only' | 'decode_required';
  reason: string;
  detail?: string;
  unknownToken: boolean;
  execution?: DecodeExecution;
  calldataHash?: string;
  calldataBytes?: number;
  /** what the bytes say structurally, NOT understood and not verified against anything: raw base units only */
  rawReading?: { kind: Kind; beneficiary: string; amount: string; understood: false };
  text?: string;
}
export type DecodeResult = DecodedCall | UndecodedCall;

interface Context {
  execution?: DecodeExecution;
  hash?: string;
  nbytes?: number;
  allowRaw: boolean;
}

function undecoded(ctx: Context, reason: string, detail?: string, extra: { unknownToken?: boolean; reading?: { kind: Kind; beneficiary: string; amount: string } } = {}): UndecodedCall {
  const rawOk = ctx.allowRaw && ctx.execution !== undefined && ctx.hash !== undefined;
  const out: UndecodedCall = { status: 'undecoded', approval: rawOk ? 'raw_only' : 'decode_required', reason, unknownToken: extra.unknownToken === true };
  if (detail !== undefined) out.detail = detail;
  if (ctx.execution !== undefined) out.execution = { ...ctx.execution };
  if (ctx.hash !== undefined && ctx.nbytes !== undefined) {
    out.calldataHash = ctx.hash;
    out.calldataBytes = ctx.nbytes;
  }
  if (extra.reading !== undefined) out.rawReading = { kind: extra.reading.kind, beneficiary: extra.reading.beneficiary, amount: extra.reading.amount, understood: false };
  if (ctx.execution !== undefined && ctx.hash !== undefined && ctx.nbytes !== undefined) {
    const e = ctx.execution;
    out.text = `RAW CALL, NOT DECODED (${reason}): ${ctx.nbytes} bytes of calldata, keccak256 ${ctx.hash}, native value ${e.value} wei, to ${e.target}, from ${e.source}, on chain ${e.chainId}` + (extra.reading !== undefined ? `; unverified reading: ${extra.reading.kind} of ${extra.reading.amount} base units to ${extra.reading.beneficiary}` : '');
  }
  return out;
}

const EXEC_MEMBERS = ['chainId', 'source', 'target', 'value', 'calldata'] as const;

function readExecution(input: unknown): { ok: true; execution: DecodeExecution; calldata: string } | { ok: false; detail: string } {
  // a data snapshot: a non-object, an accessor, a symbol key or another prototype is a shape problem
  const probe = dataObject(input);
  if (probe === null) return { ok: false, detail: 'shape' };
  for (const k of Object.keys(probe)) if (!(EXEC_MEMBERS as readonly string[]).includes(k)) return { ok: false, detail: 'unknown:' + k };
  for (const k of EXEC_MEMBERS) if (probe[k] === undefined) return { ok: false, detail: 'missing:' + k };
  const chainId = probe['chainId'];
  if (typeof chainId !== 'number' || !Number.isSafeInteger(chainId) || chainId < 1 || Object.is(chainId, -0)) return { ok: false, detail: 'chainId' };
  const source = probe['source'];
  if (typeof source !== 'string' || !ADDRESS_RE.test(source)) return { ok: false, detail: 'source' };
  const target = probe['target'];
  if (typeof target !== 'string' || !ADDRESS_RE.test(target)) return { ok: false, detail: 'target' };
  const value = probe['value'];
  if (!isAmount(value)) return { ok: false, detail: 'value' };
  const calldata = probe['calldata'];
  if (typeof calldata !== 'string') return { ok: false, detail: 'calldata' };
  return { ok: true, execution: { chainId, source, target, value }, calldata };
}

function readPolicy(policy: unknown): boolean | null {
  try {
    const p = closedObject(policy, ['allowRaw']);
    return p !== null && typeof p['allowRaw'] === 'boolean' ? p['allowRaw'] : null;
  } catch {
    return null;
  }
}

function decodedCall(ex: DecodeExecution, hash: string, entry: TokenEntry, kind: Kind, beneficiary: string, asset: string, amount: string, via: string | null): DecodedCall {
  const amountText = formatUnitsExact(amount, entry.decimals) as string;
  const unlimited = kind === 'erc20.approve' && amount === '115792089237316195423570985008687907853269984665640564039457584007913129639935';
  let text: string;
  if (kind === 'erc20.transfer') text = `TRANSFER ${amountText} ${entry.symbol} from ${ex.source} to ${beneficiary} on chain ${ex.chainId} (token ${asset})`;
  else if (kind === 'erc20.approve') text = `APPROVE ${unlimited ? 'UNLIMITED ' : ''}ALLOWANCE (not a transfer): spender ${beneficiary} may spend up to ${amountText} ${entry.symbol} of ${ex.source} on chain ${ex.chainId} (token ${asset})`;
  else text = `SEND ${amountText} ${entry.symbol} (native) from ${ex.source} to ${beneficiary} on chain ${ex.chainId}`;
  if (via !== null) text += ` via proxy ${via}`;
  return {
    status: 'decoded',
    approval: 'decoded',
    kind,
    chainId: ex.chainId,
    source: ex.source,
    target: ex.target,
    beneficiary,
    beneficiaryRole: kind === 'erc20.approve' ? 'spender' : 'recipient',
    asset,
    assetSymbol: entry.symbol,
    decimals: entry.decimals,
    amount,
    amountText,
    unlimitedAllowance: unlimited,
    viaProxy: via,
    value: ex.value,
    calldataHash: hash,
    text,
  };
}

function decodeInner(input: unknown, registryInput: unknown, policyInput: unknown): DecodeResult {
  const policyAllows = readPolicy(policyInput);
  const ctx: Context = { allowRaw: policyAllows === true };

  const e = readExecution(input);
  if (!e.ok) return undecoded({ allowRaw: false }, 'input_malformed', e.detail);
  ctx.execution = e.execution;
  const ex = e.execution;

  const reg = validateTokenRegistry(registryInput);
  if (!reg.ok) return undecoded({ execution: ex, allowRaw: false }, 'registry_invalid', reg.detail === undefined ? reg.reason : reg.reason + ' ' + reg.detail);
  const registry: TokenRegistry = reg.registry;
  if (policyAllows === null) return undecoded({ execution: ex, allowRaw: false }, 'policy_invalid');

  const parsed = parseHexBytes(e.calldata);
  if (!parsed.ok) return undecoded(ctx, parsed.reason, parsed.detail);
  const bytes = parsed.bytes;
  ctx.hash = keccak256Hex(bytes);
  ctx.nbytes = bytes.length;

  // a wrapper selector at a contract the registry does not name is refused before the wrapper is read
  if (bytes.length >= 4 && hexOf(bytes, 0, 4) === SELECTOR_EXECUTE && !isNamedProxy(registry, ex.chainId, ex.target)) return undecoded(ctx, 'proxy_not_named', SELECTOR_EXECUTE);

  const r = readBytes(bytes);
  if (!r.ok) return undecoded(ctx, r.reason, r.detail);

  if (r.shape === 'native') {
    const native = findToken(registry, ex.chainId, 'native');
    if (native === null) return undecoded(ctx, 'token_unknown', `chain ${ex.chainId} address native`, { unknownToken: true });
    return decodedCall(ex, ctx.hash, native, 'native.transfer', ex.target, 'native', ex.value, null);
  }

  if (r.shape === 'erc20') {
    const reading = { kind: r.kind, beneficiary: r.address, amount: r.amount };
    if (ex.value !== '0') return undecoded(ctx, 'token_call_carries_value', undefined, { reading });
    const token = findToken(registry, ex.chainId, ex.target);
    if (token === null) return undecoded(ctx, 'token_unknown', `chain ${ex.chainId} address ${ex.target}`, { unknownToken: true, reading });
    return decodedCall(ex, ctx.hash, token, r.kind, r.address, ex.target, r.amount, null);
  }

  // a wrapper the registry names: it must be named for the token the wrapper acts on
  const dest = findToken(registry, ex.chainId, r.dest);
  if (dest === null || dest.proxies === undefined || !dest.proxies.includes(ex.target)) return undecoded(ctx, 'proxy_not_named', SELECTOR_EXECUTE);
  const innerParsed = parseHexBytes(r.data);
  if (!innerParsed.ok) return undecoded(ctx, innerParsed.reason, innerParsed.detail);
  const inner = innerParsed.bytes;
  if (inner.length === 0) return undecoded(ctx, 'proxy_inner_unsupported');
  if (inner.length >= 4 && hexOf(inner, 0, 4) === SELECTOR_EXECUTE) return undecoded(ctx, 'proxy_nested');
  const ir = readBytes(inner);
  if (!ir.ok) return undecoded(ctx, ir.reason, ir.detail);
  if (ir.shape !== 'erc20') return undecoded(ctx, 'proxy_inner_unsupported');
  if (ex.value !== '0' || r.value !== '0') return undecoded(ctx, 'token_call_carries_value');
  return decodedCall(ex, ctx.hash, dest, ir.kind, ir.address, r.dest, ir.amount, ex.target);
}

/**
 * Decode what a transaction means. `execution` is the closed object { chainId, source, target, value, calldata } (lowercase
 * addresses, value a decimal string of wei, calldata hex with a lowercase 0x); `registry` the policy token registry;
 * `policy` exactly { allowRaw: boolean }. Never throws: an input that cannot be read answers input_malformed.
 */
export function decode(execution: unknown, registry: unknown, policy: unknown): DecodeResult {
  try {
    return decodeInner(execution, registry, policy);
  } catch {
    return undecoded({ allowRaw: false }, 'input_malformed', 'unreadable');
  }
}
