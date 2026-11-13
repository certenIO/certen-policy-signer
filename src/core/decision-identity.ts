/**
 * Shared vocabulary and input discipline of the decision modules (DECISION.md section 2): the identity of an approver,
 * the seat, and the rule that every input is DATA. A caller's object is copied once into a snapshot of its own data
 * properties (no accessor, no symbol, no inherited member, no prototype other than Object's), so what a check reads is
 * what the result is built from, and a getter cannot answer differently the second time.
 */
import { HASH_RE, hasLoneSurrogate, isPlainObject } from './bytes.js';
import { isAccUrl, isUnderAdi } from './grant-profile.js';

/** `key:<sha256 of the public key, lowercase hex>`: the identity of one key. */
const KEY_IDENTITY_RE = /^key:[0-9a-f]{64}$/;
/** `seat:<name>`: a named approval seat. */
export const SEAT_RE = /^seat:[a-z0-9][a-z0-9._-]{0,62}$/;

/** An approver is a key or an ADI, never a display name; case and spelling are exact so that no variant is a second identity. */
export function isIdentity(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  if (KEY_IDENTITY_RE.test(v)) return true;
  return v.startsWith('adi:') && isAccUrl(v.slice(4));
}
export const isSeatId = (v: unknown): v is string => typeof v === 'string' && SEAT_RE.test(v);
export const isHash = (v: unknown): v is string => typeof v === 'string' && HASH_RE.test(v);
/** a Unix-seconds time or a count: a non-negative safe integer (not -0, not a float) */
export const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
export const isPositiveInt = (v: unknown): v is number => isTime(v) && v >= 1;
export const isText = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max && !hasLoneSurrogate(v);

/** the identity of an ADI as an identity string */
export const adiIdentity = (adiUrl: string): string => 'adi:' + adiUrl;

/**
 * True when the identity is the subject itself or lies under the subject: its ADI, or an ADI under it (a sub-ADI host is
 * `<name>.<subject host>`; a text prefix is NOT the relation). Keys of the subject's books are matched by the caller's set.
 */
export function isSubjectAdiIdentity(identity: string, subjectAdi: string): boolean {
  return identity.startsWith('adi:') && isUnderAdi(identity.slice(4), subjectAdi);
}

/**
 * A snapshot of the own data properties of a plain object, or null: the value is not a plain object, has a symbol key,
 * or has a member that is an accessor or not enumerable. The snapshot has no prototype, so a member named `__proto__`
 * is an ordinary own key (and an unknown key to every closed shape).
 */
export function dataObject(v: unknown): Record<string, unknown> | null {
  if (!isPlainObject(v)) return null;
  if (Object.getOwnPropertySymbols(v).length > 0) return null;
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const k of Object.getOwnPropertyNames(v)) {
    const d = Object.getOwnPropertyDescriptor(v, k);
    if (d === undefined || !('value' in d) || d.enumerable !== true) return null;
    out[k] = d.value;
  }
  return out;
}

/** a snapshot of the elements of an array (own data elements only, no holes, no extra members), or null */
export function dataArray(v: unknown, max: number): unknown[] | null {
  if (!Array.isArray(v) || v.length > max) return null;
  if (Object.getPrototypeOf(v) !== Array.prototype) return null;
  const names = Object.getOwnPropertyNames(v);
  if (names.length !== v.length + 1) return null;
  const out: unknown[] = [];
  for (let i = 0; i < v.length; i++) {
    const d = Object.getOwnPropertyDescriptor(v, String(i));
    if (d === undefined || !('value' in d) || d.enumerable !== true) return null;
    out.push(d.value);
  }
  return out;
}

/** a closed object: exactly the `required` members and any of the `optional` ones, nothing else; null when it is not */
export function closedObject(v: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> | null {
  const o = dataObject(v);
  if (o === null) return null;
  const keys = Object.keys(o);
  for (const k of keys) if (!required.includes(k) && !optional.includes(k)) return null;
  for (const k of required) if (!(k in o)) return null;
  return o;
}
