/**
 * The subject's consent (GRANT.md GR-54 to GR-57): a chain-native data entry that the SUBJECT writes in
 * `<subject-adi>/certen-acceptances`, an account whose authority set is the subject's own key book alone, with exactly
 * one element: the canonical text of `certen.acceptance/v1` {schema, subject, principal, registry, action}. Accumulate
 * enforces the subject's authority at write time, so no key of the subject needs to be verified later and a rotation of
 * the subject's book cannot invalidate an earlier acceptance (GR-59).
 */
import { CoreError, isPlainObject, utf8, utf8Decode, utf8Length, type Json } from './bytes.js';
import { isAdiUrl, isUnderAdi } from './grant-profile.js';
import { canonicalize, parseJson } from './jcs.js';

export const ACCEPTANCE_SCHEMA = 'certen.acceptance/v1';
export const ACCEPTANCE_ACCOUNT = 'certen-acceptances';
export const ACCEPTANCE_ACTIONS = ['accept', 'revoke'] as const;
/** A bound of this library (the specification names none): the text is a five-member object. */
export const ACCEPTANCE_TEXT_BYTES = 2048;

export interface Acceptance {
  schema: 'certen.acceptance/v1';
  subject: string;
  principal: string;
  /** `<principal>/certen-subjects` */
  registry: string;
  action: 'accept' | 'revoke';
}

const KEYS = ['schema', 'subject', 'principal', 'registry', 'action'];

export type AcceptanceValidation = { ok: true; acceptance: Acceptance } | { ok: false; reason: string; detail?: string };

export function validateAcceptance(v: unknown): AcceptanceValidation {
  if (!isPlainObject(v)) return { ok: false, reason: 'acceptance_malformed', detail: 'not an object' };
  const have = Object.keys(v);
  for (const k of have) if (!KEYS.includes(k)) return { ok: false, reason: 'acceptance_unknown_field', detail: k };
  for (const k of KEYS) if (!have.includes(k)) return { ok: false, reason: 'acceptance_missing_field', detail: k };
  if (v['schema'] !== ACCEPTANCE_SCHEMA) return { ok: false, reason: 'acceptance_malformed', detail: 'schema' };
  if (!isAdiUrl(v['subject'])) return { ok: false, reason: 'acceptance_malformed', detail: 'subject' };
  if (!isAdiUrl(v['principal'])) return { ok: false, reason: 'acceptance_malformed', detail: 'principal' };
  if (v['registry'] !== v['principal'] + '/certen-subjects') return { ok: false, reason: 'acceptance_malformed', detail: 'registry' };
  if (v['action'] !== 'accept' && v['action'] !== 'revoke') return { ok: false, reason: 'acceptance_malformed', detail: 'action' };
  // the principal is neither the subject nor a sub-ADI of it (GR-31 for the consent)
  if (isUnderAdi(v['principal'] as string, v['subject'] as string)) return { ok: false, reason: 'acceptance_principal_is_subject' };
  return { ok: true, acceptance: parseJson(canonicalize(v), { integersOnly: true }) as unknown as Acceptance };
}

export type ParseAcceptanceResult = { ok: true; acceptance: Acceptance; canonical: string } | { ok: false; reason: string; detail?: string };

/** Strict parse of acceptance text: size, duplicates, lone surrogates, number spellings, then the closed members. */
export function parseAcceptanceText(text: string): ParseAcceptanceResult {
  if (utf8Length(text) > ACCEPTANCE_TEXT_BYTES) return { ok: false, reason: 'acceptance_too_large' };
  let value: Json;
  try {
    value = parseJson(text, { integersOnly: true });
  } catch (e) {
    if (e instanceof CoreError) return { ok: false, reason: 'acceptance_' + e.code };
    throw e;
  }
  const v = validateAcceptance(value);
  return v.ok ? { ok: true, acceptance: v.acceptance, canonical: canonicalize(v.acceptance) } : v;
}

export type DecodedAcceptanceEntry = { ok: true; acceptance: Acceptance } | { ok: false; reason: string; detail?: string };

/**
 * An entry of certen-acceptances has exactly one element, UTF-8 text, the canonical text of the acceptance byte for byte.
 * Refusals: entry_shape, entry_not_text, entry_undecodable, entry_not_canonical.
 */
export function decodeAcceptanceEntry(elements: unknown): DecodedAcceptanceEntry {
  if (!Array.isArray(elements) || elements.length !== 1 || !(elements[0] instanceof Uint8Array)) return { ok: false, reason: 'entry_shape' };
  let text: string;
  try {
    text = utf8Decode(elements[0]);
  } catch {
    return { ok: false, reason: 'entry_not_text' };
  }
  const p = parseAcceptanceText(text);
  if (!p.ok) return { ok: false, reason: 'entry_undecodable', detail: p.reason };
  if (p.canonical !== text) return { ok: false, reason: 'entry_not_canonical' };
  return { ok: true, acceptance: p.acceptance };
}

export function encodeAcceptanceEntry(acceptance: unknown): Uint8Array[] {
  const v = validateAcceptance(acceptance);
  if (!v.ok) throw new CoreError(v.reason, v.detail);
  return [utf8(canonicalize(v.acceptance))];
}
