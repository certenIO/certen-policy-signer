/**
 * Byte and framing primitives of the core: the proof v2 length-prefix convention, hex, big-endian integers, SHA-256.
 * Pure functions; the only platform dependency of the whole package is node:crypto (createHash here).
 */
import { createHash } from 'node:crypto';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Every refusal that a pure helper raises is a CoreError with a stable machine-readable code (never prose). */
export class CoreError extends Error {
  readonly code: string;
  readonly detail: string | undefined;
  constructor(code: string, detail?: string) {
    super(detail === undefined ? code : code + ': ' + detail);
    this.name = 'CoreError';
    this.code = code;
    this.detail = detail;
  }
}

export const HASH_RE = /^0x[0-9a-f]{64}$/;
export const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
export const AMOUNT_RE = /^(0|[1-9][0-9]*)$/;
export const MAX_UINT256 = (1n << 256n) - 1n;
const HEX_RE = /^([0-9a-f]{2})*$/;

const ENCODER = new TextEncoder();
const STRICT_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (n >= 0xdc00 && n <= 0xdfff) i++;
      else return true;
    } else if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

/** UTF-8 of a string; a lone surrogate is refused instead of being silently replaced. */
export function utf8(s: string): Uint8Array {
  if (hasLoneSurrogate(s)) throw new CoreError('lone_surrogate');
  return ENCODER.encode(s);
}

/** Number of bytes a string takes in UTF-8 (a lone surrogate counts as the three bytes of its replacement). */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

/** Strict UTF-8 decode: invalid sequences are refused, a byte order mark is kept (and so refused by the JSON parser). */
export function utf8Decode(bytes: Uint8Array): string {
  try {
    return STRICT_DECODER.decode(bytes);
  } catch {
    throw new CoreError('not_utf8');
  }
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += (bytes[i]! >> 4).toString(16) + (bytes[i]! & 15).toString(16);
  return out;
}

/** Lowercase hex only, even length; anything else is refused. */
export function fromHex(s: string): Uint8Array {
  if (typeof s !== 'string' || !HEX_RE.test(s)) throw new CoreError('hex_invalid');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Big-endian unsigned 64-bit integer. */
export function be64(n: number | bigint): Uint8Array {
  let v: bigint;
  if (typeof n === 'bigint') v = n;
  else if (Number.isSafeInteger(n)) v = BigInt(n);
  else throw new CoreError('integer_invalid');
  if (v < 0n || v > 0xffffffffffffffffn) throw new CoreError('integer_invalid');
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** lp(x): the four-byte big-endian length of x followed by x (proof v2 convention). */
export function lp(x: Uint8Array): Uint8Array {
  if (x.length > 0xffffffff) throw new CoreError('field_too_long');
  const head = new Uint8Array(4);
  head[0] = (x.length >>> 24) & 255;
  head[1] = (x.length >>> 16) & 255;
  head[2] = (x.length >>> 8) & 255;
  head[3] = x.length & 255;
  return concat(head, x);
}

/** `0x` plus 64 lowercase hex digits to its 32 bytes. */
export function hash32(s: unknown, what: string): Uint8Array {
  if (typeof s !== 'string' || !HASH_RE.test(s)) throw new CoreError('hash_invalid', what);
  return fromHex(s.slice(2));
}

/** `0x` plus 40 lowercase hex digits to its 20 bytes. */
export function address20(s: unknown, what: string): Uint8Array {
  if (typeof s !== 'string' || !ADDRESS_RE.test(s)) throw new CoreError('address_invalid', what);
  return fromHex(s.slice(2));
}

/** Decimal unsigned integer text with no sign and no leading zero, at most 2^256-1. */
export function isAmount(s: unknown): s is string {
  return typeof s === 'string' && s.length <= 78 && AMOUNT_RE.test(s) && BigInt(s) <= MAX_UINT256;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
