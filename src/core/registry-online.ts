/**
 * The ONLINE subject resolver (GRANT.md GR-54 to GR-57, GR-62, section 4a). Pure: every fact is an input.
 *
 * A Grant's subject is resolved ONLY through the registry of the Grant's GRANTOR ADI, `<grant.grantor.adi>/certen-subjects`
 * (a registration by any other ADI is invisible to the Grant, GR-62). The registry account is read under the account
 * authority rule (checkAccountAuthority, GR-58) with the grantor's book as its owner; the subject's consent is the
 * chain-native entry the subject wrote in `<subject>/certen-acceptances` (GR-54), an account owned by the subject's own
 * book alone. The consent in force at time t is the action of the latest entry that names this principal and this
 * registry with chain time at or before t (GR-55). Acceptance gates INCREASES of authority only (GR-56), PROSPECTIVELY
 * (GR-82, decision R4-3, DAX-2 round 6): a version that registers (an active version 1) or reactivates (suspended to
 * active) is never refused for lack of an acceptance at its entry time; it WAITS and is in force from the later of its
 * entry time and the entry time of the acceptance in force, never before; a suspension, a retirement or a change while
 * active keeps its own entry time and the head by version decides the status. The verdict is about a stated time `at`
 * (default: now, the end of time for the reader) and needs the acceptance in force at that time (GR-57, GR-83); an
 * entry written after `at` does not exist for it; the answer for a registration in force carries `activeSince`. The
 * legacy rule (every increase judged at its own entry time) has no place here: ERRATA.md E6-02 keeps it in the
 * reference evaluators only. No online verdict reads a key page, at any time; the principal's envelope on a
 * registration is OFFLINE evidence (GR-60). Only certen.subject/v2 entries are read online (GR-89).
 */
import { isPlainObject } from './bytes.js';
import { checkAccountAuthority, SAFE_AFTER } from './account.js';
import { decodeAcceptanceEntry, type Acceptance } from './acceptance.js';
import { decodeEntry } from './envelope.js';
import { validateGrant } from './grant-profile.js';
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
  /** the evaluation time (Unix seconds, a non-negative safe integer); absent means now. An entry written after it does not exist for the verdict (GR-83). */
  at?: unknown;
  /** absent only: the activation is prospective. Any member present is refused as `resolve_input_malformed` (the legacy mode exists in the reference evaluators only). */
  activation?: unknown;
}

export type ResolveSubjectOnlineResult =
  | { ok: true; state?: never; subject: { adi: string; type: string; principal: string; seat: string }; evidence: 'chain_enforced'; activeSince: number }
  | ResolveSubjectResult
  | { ok: false; reason: 'resolve_input_malformed'; detail: string };

const unproven = (reason: string, extra: Record<string, unknown> = {}): ResolveSubjectResult => ({ ok: false, state: 'subject_unproven', reason, ...extra } as ResolveSubjectResult);

interface Placed<T> { value: T; time: number }

/** the acceptance account as the resolver gets it: the value read, or the refusal that reading it produced (read only when a version needs the consent, GR-56) */
export type AcceptanceLoad = { ok: true; value: unknown } | { ok: false; result: ResolveSubjectResult };

/** the refusals that need no account: a Grant that does not validate, an asserted subject or an expected type that is malformed (shared by the readers) */
export function resolveEarlyRefusal(grantInput: unknown, asserted: unknown, expectType: unknown): ResolveSubjectResult | null {
  const g = validateGrant(grantInput);
  if (!g.ok) return unproven('asserted_malformed', { detail: 'grant ' + g.reason });
  const early = lineageParts({ asserted, expectType, registry: [] });
  if ('ok' in early && !early.ok && early.reason !== 'not_registered') return early;
  return null;
}

export function resolveSubjectOnline(input: ResolveSubjectOnlineInput): ResolveSubjectOnlineResult {
  return resolveSubjectOnlineWith(input, () => ({ ok: true, value: input.acceptances }));
}

/** resolveSubjectOnline with the acceptance account loaded lazily: it is asked for only when a version of the registration needs the consent */
export function resolveSubjectOnlineWith(input: Omit<ResolveSubjectOnlineInput, 'acceptances'>, loadAcceptances: () => AcceptanceLoad): ResolveSubjectOnlineResult {
  // the shape of the call itself, before any fact is read (GR-83: an input shape, never a subject_unproven reason)
  if (input.activation !== undefined) return { ok: false, reason: 'resolve_input_malformed', detail: 'activation' };
  if (input.at !== undefined && (typeof input.at !== 'number' || !Number.isSafeInteger(input.at) || input.at < 0)) return { ok: false, reason: 'resolve_input_malformed', detail: 'at' };
  const evalAt = input.at === undefined ? Number.MAX_SAFE_INTEGER : (input.at as number);
  /** an entry written after the evaluation time does not exist for the verdict (GR-83); an entry with no readable time is never skipped here, the reads below refuse it */
  const afterEvalTime = (e: unknown): boolean => {
    const t = isPlainObject(e) ? e['entryTime'] : undefined;
    return typeof t === 'number' && Number.isSafeInteger(t) && t >= 0 && t > evalAt;
  };
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
    if (afterEvalTime(e)) continue;
    // GR-89: the online reader reads certen.subject/v2 entries only; a v1 record refuses the read of the account (GR-44)
    const d = decodeEntry({ account: 'subjects', elements: isPlainObject(e) ? e['elements'] : undefined, v2Only: true });
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
  const needsAt: Array<{ time: number; version: number }> = [];
  parts.regs.forEach((r, i) => {
    const registers = i === 0 && r.status === 'active';
    const reactivates = i > 0 && parts.regs[i - 1]!.status === 'suspended' && r.status === 'active';
    if (registers || reactivates) needsAt.push({ time: times[i]!, version: r.version as number });
  });
  const head = parts.regs[parts.regs.length - 1]!;
  const consentNeeded = needsAt.length > 0 || head.status === 'active';
  const accepted: Array<Placed<Acceptance>> = [];
  if (consentNeeded) {
    const load = loadAcceptances();
    if (!load.ok) return load.result;
    const acc = load.value;
    if (acc === undefined || acc === null) return unproven('subject_acceptance_missing');
    if (!isPlainObject(acc) || !isPlainObject(acc['account']) || !Array.isArray(acc['entries'])) return unproven('subject_acceptance_missing', { detail: 'acceptance account unreadable' });
    const a = acc['account'] as { ownerBook?: unknown; authorities?: unknown; history?: unknown; incomplete?: unknown };
    const owner = a.ownerBook;
    // GR-89: the owner of the acceptance account is a key book in the authority set of the subject ADI ITSELF (a book under a sub-ADI is not)
    if (typeof owner !== 'string' || !subjectBooks.includes(owner)) return unproven('acceptance_account_not_subject');
    const ag = checkAccountAuthority({ ownerBook: owner, forbiddenBooks: [], authorities: a.authorities, history: a.history, incomplete: a.incomplete, safeAfter });
    if (!ag.ok) return unproven(ag.reason, ag.index === undefined ? {} : { index: ag.index });
    const aEntries = acc['entries'] as unknown[];
    for (let i = 0; i < aEntries.length; i++) {
      const e = aEntries[i];
      if (afterEvalTime(e)) continue;
      const d = decodeAcceptanceEntry(isPlainObject(e) ? e['elements'] : undefined);
      if (!d.ok) return unproven('account_entry_undecodable', { index: i, cause: d.reason });
      const t = isPlainObject(e) ? e['entryTime'] : undefined;
      if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0) return unproven('account_entry_undecodable', { index: i, cause: 'entry_time_missing' });
      if (d.acceptance.subject !== asserted.adi) return unproven('acceptance_names_another_subject', { index: i });
      accepted.push({ value: d.acceptance, time: t });
    }
  }
  /** GR-55: the action of the latest entry that names this principal and this registry at or before t (a later list position wins a tie) */
  const inForceAt = (t: number): { action: 'accept' | 'revoke'; time: number } | null => {
    let best: Placed<Acceptance> | null = null;
    for (const x of accepted) if (x.value.principal === grantorAdi && x.value.registry === grantorAdi + '/certen-subjects' && x.time <= t && (best === null || x.time >= best.time)) best = x;
    return best === null ? null : { action: best.value.action, time: best.time };
  };

  // 5. the head decides the status, type and submitter (a suspension or a retirement written while an increase still waits is the status in force: the waiting increase never takes effect)
  const decided = headDecision(parts);
  if (!decided.ok) return decided;

  // 6. GR-82, GR-57, GR-83: the head is active, so the increase that put it in force (the latest registering or reactivating version) needs the acceptance in force AT the evaluation time
  // and is in force from the later of its own entry time and the entry time of that acceptance, never before (no retroactive authority)
  const increase = needsAt.length > 0 ? needsAt[needsAt.length - 1]! : { time: times[0]!, version: parts.regs[0]!.version as number };
  const consent = inForceAt(evalAt);
  if (consent === null) return unproven('subject_acceptance_missing', { version: increase.version });
  if (consent.action === 'revoke') return unproven('subject_acceptance_revoked', { version: increase.version });
  return { ...decided, evidence: 'chain_enforced', activeSince: Math.max(increase.time, consent.time) };
}
