/**
 * The subject registration (GRANT.md section 8, certen.subject/v1): the closed object, its strict validation and its
 * canonical text. The registration hash lives in hashes.ts; resolution (the sr vectors) lives in registry.ts.
 */
import { CoreError, HASH_RE, isPlainObject, utf8Length, type Json } from './bytes.js';
import { isAccUrl, isAdiUrl, SUBJECT_TYPES, type SubjectType } from './grant-profile.js';
import { canonicalize, parseJson } from './jcs.js';

/** certen.subject/v1: the single record (kept: two v1 rows for one ADI are ambiguous). certen.subject/v2: a version lineage (GR-29, GR-49 to GR-52). */
export const REGISTRATION_SCHEMA_V1 = 'certen.subject/v1';
export const REGISTRATION_SCHEMA = 'certen.subject/v2';
export const REGISTRATION_LIMITS = { textBytes: 8192, submitters: 32 };
export const SUBJECT_STATUSES = ['active', 'suspended', 'retired'] as const;
export type SubjectStatus = (typeof SUBJECT_STATUSES)[number];

export interface Registration {
  schema: 'certen.subject/v1' | 'certen.subject/v2';
  adi: string;
  /** present in certen.subject/v2 only */
  version?: number;
  /** present in certen.subject/v2 only: null for version 1, else the hash of the previous version */
  priorHash?: string | null;
  type: SubjectType;
  principal: { adi: string; keyBook: string };
  responsibleSeat: string;
  submitters: string[];
  status: SubjectStatus;
  registeredAt: number;
}

export type RegistrationValidation = { ok: true; registration: Registration } | { ok: false; reason: string; detail?: string };

const SEAT_RE = /^seat:[a-z0-9][a-z0-9._-]{0,62}$/;

class Refusal extends Error {
  constructor(readonly reason: string, readonly detail: string) {
    super(reason);
  }
}
const fail = (reason: string, path: string): never => {
  throw new Refusal(reason, path);
};
function obj(v: unknown, path: string, keys: readonly string[]): Record<string, unknown> {
  if (!isPlainObject(v)) return fail('registration_field_invalid', path);
  const have = Object.keys(v);
  for (const k of have) if (!keys.includes(k)) fail('registration_unknown_field', path + '.' + k);
  for (const k of keys) if (!have.includes(k)) fail('registration_missing_field', path + '.' + k);
  return v;
}

const KEYS_V1 = ['schema', 'adi', 'type', 'principal', 'responsibleSeat', 'submitters', 'status', 'registeredAt'];
const KEYS_V2 = [...KEYS_V1, 'version', 'priorHash'];

function validate(v: unknown): void {
  if (!isPlainObject(v)) return fail('registration_field_invalid', '$');
  const schema = v['schema'];
  if (schema !== REGISTRATION_SCHEMA_V1 && schema !== REGISTRATION_SCHEMA) return fail('registration_field_invalid', '$.schema');
  const r = obj(v, '$', schema === REGISTRATION_SCHEMA ? KEYS_V2 : KEYS_V1);
  if (!isAdiUrl(r['adi'])) fail('registration_field_invalid', '$.adi');
  if (typeof r['type'] !== 'string' || !(SUBJECT_TYPES as readonly string[]).includes(r['type'])) fail('registration_field_invalid', '$.type');
  const p = obj(r['principal'], '$.principal', ['adi', 'keyBook']);
  if (!isAdiUrl(p['adi'])) fail('registration_field_invalid', '$.principal.adi');
  const book = p['keyBook'];
  if (!isAccUrl(book) || !book.startsWith((p['adi'] as string) + '/')) fail('registration_field_invalid', '$.principal.keyBook');
  if (typeof r['responsibleSeat'] !== 'string' || !SEAT_RE.test(r['responsibleSeat'])) fail('registration_field_invalid', '$.responsibleSeat');
  const subs = r['submitters'];
  if (Array.isArray(subs) && subs.length > REGISTRATION_LIMITS.submitters) fail('registration_too_large', '$.submitters');
  if (!Array.isArray(subs) || !subs.every(isAdiUrl) || new Set(subs).size !== subs.length) fail('registration_field_invalid', '$.submitters');
  if (typeof r['status'] !== 'string' || !(SUBJECT_STATUSES as readonly string[]).includes(r['status'])) fail('registration_field_invalid', '$.status');
  const at = r['registeredAt'];
  if (typeof at !== 'number' || !Number.isSafeInteger(at) || at < 0 || Object.is(at, -0)) fail('registration_field_invalid', '$.registeredAt');
  if (schema === REGISTRATION_SCHEMA) {
    const version = r['version'];
    if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) fail('registration_field_invalid', '$.version');
    const prior = r['priorHash'];
    if (prior !== null && (typeof prior !== 'string' || !HASH_RE.test(prior))) fail('registration_field_invalid', '$.priorHash');
    if ((version === 1) !== (prior === null)) fail('registration_lineage_invalid', '$.priorHash');
  }
}

export function validateRegistration(value: unknown): RegistrationValidation {
  try {
    validate(value);
    const canonicalText = canonicalize(value);
    if (utf8Length(canonicalText) > REGISTRATION_LIMITS.textBytes) fail('registration_too_large', '$');
    return { ok: true, registration: parseJson(canonicalText, { integersOnly: true }) as unknown as Registration };
  } catch (e) {
    if (e instanceof Refusal) return { ok: false, reason: e.reason, detail: e.detail };
    if (e instanceof CoreError) return { ok: false, reason: 'registration_field_invalid', detail: e.code };
    throw e;
  }
}

export function canonicalRegistration(value: unknown): string {
  const v = validateRegistration(value);
  if (!v.ok) throw new CoreError(v.reason, v.detail);
  return canonicalize(v.registration);
}

export function parseRegistrationTextUnhashed(text: string): { ok: true; registration: Registration; canonical: string } | { ok: false; reason: string; detail?: string } {
  if (utf8Length(text) > REGISTRATION_LIMITS.textBytes) return { ok: false, reason: 'registration_too_large' };
  let value: Json;
  try {
    value = parseJson(text, { integersOnly: true });
  } catch (e) {
    if (e instanceof CoreError) return { ok: false, reason: 'registration_' + e.code };
    throw e;
  }
  const v = validateRegistration(value);
  if (!v.ok) return v;
  return { ok: true, registration: v.registration, canonical: canonicalize(v.registration) };
}
