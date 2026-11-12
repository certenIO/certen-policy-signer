/**
 * The ONLINE subject resolver (GRANT.md GR-54 to GR-57, GR-62, section 4a). Pure: every fact is an input.
 *
 * A Grant's subject is resolved ONLY through the registry of the Grant's GRANTOR ADI, `<grant.grantor.adi>/certen-subjects`
 * (a registration by any other ADI is invisible to the Grant, GR-62). The registry account is read under the account
 * authority rule (checkAccountAuthority, GR-58) with the grantor's book as its owner; the subject's consent is the
 * chain-native entry the subject wrote in `<subject>/certen-acceptances` (GR-54), an account owned by the subject's own
 * book alone. The consent in force at time t is the action of the latest entry that names this principal and this
 * registry with chain time at or before t (GR-55). Acceptance gates INCREASES of authority only (GR-56): it must be in
 * force at the entry time of a version that registers (an active version 1) and of a version that reactivates
 * (suspended to active), and never gates a suspension or a retirement; while the head is active the consent must still
 * stand now (GR-57). No online verdict reads a key page, at any time; the principal's envelope on a registration is
 * OFFLINE evidence (GR-60).
 */
import { isPlainObject } from './bytes.js';
import { checkAccountAuthority, SAFE_AFTER } from './account.js';
import { decodeAcceptanceEntry, type Acceptance } from './acceptance.js';
import { decodeEntry } from './envelope.js';
import { isUnderAdi, validateGrant } from './grant-profile.js';
import { headDecision, lineageParts, type ResolveSubjectResult } from './registry.js';
import type { Registration } from './registry-profile.js';

export interface OnlineEntry {
  /** the data items of the entry, as bytes */
  elements: unknown;
  /** chain time of the entry (Unix seconds); required, a registry or acceptance entry without it cannot be placed */
  entryTime?: unknown;
}
export interface OnlineAccountEntries {
  account: { ownerBook: unknown; authorities: unknown; history: unknown; incomplete?: unknown };
  entries: unknown;
}

export interface ResolveSubjectOnlineInput {
  grant: unknown;
  asserted: unknown;
  expectType: unknown;
  /** the registries read, keyed by the ADI that owns each; only `grant.grantor.adi` is ever looked at */
  registries: unknown;
  /** the acceptance account of the SUBJECT, or null/absent when the subject never consented */
  acceptances?: unknown;
  /** the key books in the authority set of the subject ADI, read now */
  subjectBooks: unknown;
  safeAfter?: unknown;
}

export type ResolveSubjectOnlineResult = ResolveSubjectResult | { ok: true; subject: { adi: string; type: string; principal: string; seat: string }; evidence: 'chain_enforced' };

const unproven = (reason: string, extra: Record<string, unknown> = {}): ResolveSubjectResult => ({ ok: false, state: 'subject_unproven', reason, ...extra } as ResolveSubjectResult);

interface Placed<T> { value: T; time: number }

export function resolveSubjectOnline(input: ResolveSubjectOnlineInput): ResolveSubjectOnlineResult {
  const g = validateGrant(input.grant);
  if (!g.ok) return unproven('asserted_malformed', { detail: 'grant ' + g.reason });
  const grant = g.grant;
  const safeAfter = input.safeAfter === undefined ? SAFE_AFTER : input.safeAfter;
  const subjectBooks = Array.isArray(input.subjectBooks) && input.subjectBooks.every((b) => typeof b === 'string') ? (input.subjectBooks as string[]) : null;
  const grantorAdi = grant.grantor.adi;

  // asserted and expectType are checked by the lineage step as for the offline resolver; run it once with no rows to learn them early
  const early = lineageParts({ asserted: input.asserted, expectType: input.expectType, registry: [] });
  if ('ok' in early && !early.ok && early.reason !== 'not_registered') return early;
  const asserted = input.asserted as { adi: string; assertedBy: string };

  // 1. the registry of the grantor, and only that
  const registries = input.registries;
  if (!isPlainObject(registries)) return unproven('registry_unreadable');
  if (!Object.prototype.hasOwnProperty.call(registries, grantorAdi)) return unproven('not_registered');
  const reg = registries[grantorAdi];
  if (!isPlainObject(reg) || !isPlainObject(reg['account']) || !Array.isArray(reg['entries'])) return unproven('registry_unreadable');
  const account = reg['account'] as { ownerBook?: unknown; authorities?: unknown; history?: unknown; incomplete?: unknown };
  if (account.ownerBook !== grant.grantor.keyBook) return unproven('registry_owner_mismatch');
  if (subjectBooks === null) return unproven('account_authority_unreadable', { detail: 'subject books' });
  const gate = checkAccountAuthority({ ownerBook: account.ownerBook, forbiddenBooks: subjectBooks, subjectAdi: asserted.adi, authorities: account.authorities, history: account.history, incomplete: account.incomplete, safeAfter });
  if (!gate.ok) return unproven(gate.reason, gate.index === undefined ? {} : { index: gate.index });

  // 2. canonical registry entries; the rows of THIS subject must name the grantor as principal
  const rows: Array<{ record: Registration; envelopeVerdict: 'ok'; entryTime: number }> = [];
  const entries = reg['entries'] as unknown[];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const d = decodeEntry({ account: 'subjects', elements: isPlainObject(e) ? e['elements'] : undefined });
    if (!d.ok) return unproven('account_entry_undecodable', { index: i, cause: d.reason });
    if (d.account !== 'subjects') continue;
    const t = isPlainObject(e) ? e['entryTime'] : undefined;
    if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0) return unproven('account_entry_undecodable', { index: i, cause: 'entry_time_missing' });
    if (d.registration.adi === asserted.adi && d.registration.principal.adi !== grantorAdi) return unproven('registration_principal_mismatch');
    rows.push({ record: d.registration, envelopeVerdict: 'ok', entryTime: t });
  }

  // 3. the lineage of the subject (versions, prior hashes, no envelope verdict: the principal's envelope is offline evidence)
  const parts = lineageParts({ asserted: input.asserted, expectType: input.expectType, registry: rows }, false);
  if ('ok' in parts) return parts;
  const times = parts.rows.map((r) => (r as { entryTime: number }).entryTime);

  // 4. the subject's consent, read from its own account under the same authority rule
  const needsAt: number[] = [];
  parts.regs.forEach((r, i) => {
    const registers = i === 0 && r.status === 'active';
    const reactivates = i > 0 && parts.regs[i - 1]!.status === 'suspended' && r.status === 'active';
    if (registers || reactivates) needsAt.push(times[i]!);
  });
  const head = parts.regs[parts.regs.length - 1]!;
  const consentNeeded = needsAt.length > 0 || head.status === 'active';
  const accepted: Array<Placed<Acceptance>> = [];
  if (consentNeeded) {
    const acc = input.acceptances;
    if (acc === undefined || acc === null) return unproven('subject_acceptance_missing');
    if (!isPlainObject(acc) || !isPlainObject(acc['account']) || !Array.isArray(acc['entries'])) return unproven('subject_acceptance_missing', { detail: 'acceptance account unreadable' });
    const a = acc['account'] as { ownerBook?: unknown; authorities?: unknown; history?: unknown; incomplete?: unknown };
    const owner = a.ownerBook;
    if (typeof owner !== 'string' || !(subjectBooks.includes(owner) || isUnderAdi(owner, asserted.adi))) return unproven('acceptance_account_not_subject');
    const ag = checkAccountAuthority({ ownerBook: owner, forbiddenBooks: [], authorities: a.authorities, history: a.history, incomplete: a.incomplete, safeAfter });
    if (!ag.ok) return unproven(ag.reason, ag.index === undefined ? {} : { index: ag.index });
    const aEntries = acc['entries'] as unknown[];
    for (let i = 0; i < aEntries.length; i++) {
      const e = aEntries[i];
      const d = decodeAcceptanceEntry(isPlainObject(e) ? e['elements'] : undefined);
      if (!d.ok) return unproven('account_entry_undecodable', { index: i, cause: d.reason });
      const t = isPlainObject(e) ? e['entryTime'] : undefined;
      if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0) return unproven('account_entry_undecodable', { index: i, cause: 'entry_time_missing' });
      if (d.acceptance.subject !== asserted.adi) return unproven('account_entry_undecodable', { index: i, cause: 'acceptance_names_another_subject' });
      accepted.push({ value: d.acceptance, time: t });
    }
  }
  /** GR-55: the action of the latest entry that names this principal and this registry at or before t (a later list position wins a tie) */
  const inForceAt = (t: number): 'accept' | 'revoke' | null => {
    let best: Placed<Acceptance> | null = null;
    for (const x of accepted) if (x.value.principal === grantorAdi && x.value.registry === grantorAdi + '/certen-subjects' && x.time <= t && (best === null || x.time >= best.time)) best = x;
    return best === null ? null : best.value.action;
  };
  for (const t of needsAt) {
    const s = inForceAt(t);
    if (s === null) return unproven('subject_acceptance_missing');
    if (s === 'revoke') return unproven('subject_acceptance_revoked');
  }

  // 5. the head decides the status, type and submitter; while it is active the consent must still stand now (GR-57)
  const decided = headDecision(parts);
  if (!decided.ok) return decided;
  const nowState = inForceAt(Number.MAX_SAFE_INTEGER);
  if (nowState === null) return unproven('subject_acceptance_missing');
  if (nowState === 'revoke') return unproven('subject_acceptance_revoked');
  return { ...decided, evidence: 'chain_enforced' };
}
