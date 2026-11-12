/**
 * Subject resolution (GRANT.md section 8, GR-30, GR-31, C1): an asserted subject is replaced by a resolved one, or the
 * named state subject_unproven{reason} is returned. The registry rows come from the principal's certen-subjects account
 * (reader.ts reads and verifies them); this function decides over rows it is handed and never talks to a network.
 */
import { isPlainObject } from './bytes.js';
import { isAdiUrl, isUnderAdi, SUBJECT_TYPES } from './grant-profile.js';
import { hashRegistration } from './hashes.js';
import { parseRegistrationTextUnhashed, validateRegistration, type Registration } from './registry-profile.js';

export type ParseRegistrationResult =
  | { ok: true; registration: Registration; canonical: string; registrationHash: string }
  | { ok: false; reason: string; detail?: string };

/** Strict parse of registration text (duplicates, lone surrogates and non-integer numbers refuse), then the profile and the hash. */
export function parseRegistrationText(text: string): ParseRegistrationResult {
  const p = parseRegistrationTextUnhashed(text);
  if (!p.ok) return p;
  return { ok: true, registration: p.registration, canonical: p.canonical, registrationHash: hashRegistration(p.registration) };
}

export interface ResolveSubjectInput {
  asserted: unknown;
  expectType: unknown;
  /** rows `{record, envelopeVerdict}` or null when the registry could not be read */
  registry: unknown;
}

export type ResolveSubjectResult =
  | { ok: true; subject: { adi: string; type: string; principal: string; seat: string } }
  | { ok: false; state: 'subject_unproven'; reason: string; detail?: string };

const unproven = (reason: string, detail?: string): ResolveSubjectResult => (detail === undefined ? { ok: false, state: 'subject_unproven', reason } : { ok: false, state: 'subject_unproven', reason, detail });

type Row = Record<string, unknown>;

/**
 * Resolution (GR-30, GR-31, GR-49 to GR-52). Order of reasons: asserted_malformed, expect_type_malformed,
 * registry_unreadable, not_registered, registration_schema_mixed (a v1 record beside a v2 lineage), then
 *   v1 record(s): registry_ambiguous (two rows, never "newest wins"), registration_unverified, registration_malformed,
 *   v2 lineage: registration_unverified (any version), registration_malformed (any version), registration_fork,
 *     then per version registration_version_gap, registration_prior_mismatch, registration_principal_changed,
 *     registration_type_changed, registration_time_regress, registration_status_transition_invalid (retired is terminal);
 * then for the head: principal_is_subject, subject_retired, subject_suspended, subject_type_mismatch,
 * submitter_not_authorized. A failed version refuses the WHOLE lineage; the head decides the status.
 */
export function resolveSubject(input: ResolveSubjectInput): ResolveSubjectResult {
  const a = input.asserted;
  if (!isPlainObject(a) || Object.keys(a).length !== 2 || !isAdiUrl(a['adi']) || !isAdiUrl(a['assertedBy'])) return unproven('asserted_malformed');
  if (typeof input.expectType !== 'string' || !(SUBJECT_TYPES as readonly string[]).includes(input.expectType)) return unproven('expect_type_malformed');
  const adi = a['adi'] as string;
  const assertedBy = a['assertedBy'] as string;

  const rows = input.registry;
  if (!Array.isArray(rows)) return unproven('registry_unreadable');
  const mine: Row[] = [];
  for (const row of rows) {
    if (!isPlainObject(row)) return unproven('registry_unreadable', 'row');
    const rec = row['record'];
    if (isPlainObject(rec) && rec['adi'] === adi) mine.push(row);
  }
  if (mine.length === 0) return unproven('not_registered');

  const schemaOf = (r: Row): unknown => (r['record'] as Row)['schema'];
  if (!mine.every((r) => schemaOf(r) === 'certen.subject/v1' || schemaOf(r) === 'certen.subject/v2')) return unproven('registration_malformed', 'schema');
  const v1 = mine.filter((r) => schemaOf(r) === 'certen.subject/v1');
  if (v1.length > 0 && v1.length < mine.length) return unproven('registration_schema_mixed');
  if (v1.length > 1) return unproven('registry_ambiguous');

  const verdictOf = (r: Row): string | undefined => (typeof r['envelopeVerdict'] === 'string' && r['envelopeVerdict'] ? (r['envelopeVerdict'] as string) : undefined);
  for (const r of mine) if (r['envelopeVerdict'] !== 'ok') return unproven('registration_unverified', verdictOf(r));
  const regs: Registration[] = [];
  for (const r of mine) {
    const v = validateRegistration(r['record']);
    if (!v.ok) return unproven('registration_malformed', v.reason + (v.detail ? ' ' + v.detail : ''));
    regs.push(v.registration);
  }

  if (v1.length === 0) {
    const versions = new Set<number>();
    for (const r of regs) {
      if (versions.has(r.version!)) return unproven('registration_fork', 'version ' + r.version);
      versions.add(r.version!);
    }
    for (let i = 0; i < regs.length; i++) {
      const r = regs[i]!;
      if (r.version !== i + 1) return unproven('registration_version_gap', 'entry ' + i + ' has version ' + r.version);
      if (i === 0) continue;
      const p = regs[i - 1]!;
      if (r.priorHash !== hashRegistration(p)) return unproven('registration_prior_mismatch', 'version ' + r.version);
      if (r.principal.adi !== p.principal.adi || r.principal.keyBook !== p.principal.keyBook) return unproven('registration_principal_changed', 'version ' + r.version);
      if (r.type !== p.type) return unproven('registration_type_changed', 'version ' + r.version);
      if (r.registeredAt < p.registeredAt) return unproven('registration_time_regress', 'version ' + r.version);
      if (p.status === 'retired') return unproven('registration_status_transition_invalid', 'version ' + r.version + ' follows a retirement');
    }
  }

  const head = regs[regs.length - 1]!;
  if (isUnderAdi(head.principal.adi, head.adi)) return unproven('principal_is_subject');
  if (head.status === 'retired') return unproven('subject_retired');
  if (head.status === 'suspended') return unproven('subject_suspended');
  if (head.type !== input.expectType) return unproven('subject_type_mismatch');
  if (assertedBy !== head.principal.adi && !head.submitters.includes(assertedBy)) return unproven('submitter_not_authorized');
  return { ok: true, subject: { adi: head.adi, type: head.type, principal: head.principal.adi, seat: head.responsibleSeat } };
}
