/**
 * The ONLINE lineage reader (GRANT.md section 4a: GR-58 to GR-61, GR-22, GR-24, GR-44). Pure: every fact is an input.
 *
 * The online verdict of a Grant lineage is `chain_enforced`: the account's authority facts (checkAccountAuthority), the
 * canonical entries (GR-43), the owner match and the prior-hash chain (GR-22). It reads NO key page and never requires the
 * key that signed an earlier version to be on a page now (GR-59), so a routine key rotation cannot change it. The
 * envelope signatures are OFFLINE evidence (verifyEnvelope, GR-60); online, the head's envelope is checked against the
 * CURRENT snapshot only when one is given, and the result is the advisory `headEnvelopeCurrent`, never a refusal.
 */
import { isPlainObject } from './bytes.js';
import { checkAccountAuthority, SAFE_AFTER } from './account.js';
import { decodeEntry, verifyGrantEnvelope, type Envelope } from './envelope.js';
import { evaluateLineage, type GrantStatus } from './grant.js';
import type { Grant } from './grant-profile.js';

export interface OnlineAccount {
  /** the key book that must own the account: the grantor's book */
  ownerBook: unknown;
  authorities: unknown;
  history: unknown;
  incomplete?: unknown;
  safeAfter?: unknown;
}

export interface LineageOnlineInput {
  account: OnlineAccount;
  entries: unknown;
  now: unknown;
  /** keep only the entries of this grantId (the account holds many lineages); absent: all entries are one lineage */
  grantId?: unknown;
  /** the key-page snapshot NOW, for the advisory head check only */
  chain?: unknown;
  /** books of the subject, read from its authority set now (the forbidden books of the account rule) */
  subjectBooks?: unknown;
}

export interface LineageOnlineEntry { index: number; version: number; hash: string; entryTime?: number }
export type LineageOnlineResult =
  | {
      ok: true;
      head: { version: number; hash: string };
      status: GrantStatus;
      evidence: 'chain_enforced';
      entries: LineageOnlineEntry[];
      /** present when a current key-page snapshot was given; information, NEVER a refusal (GR-60) */
      advisory?: { headEnvelopeCurrent: boolean; headEnvelopeReason: string | null };
    }
  | { ok: false; reason: string; detail?: string; index?: number; cause?: string };

/** entry refusals that leave the grant attributable: the lineage fails as a whole (GR-24), not as an unreadable account */
const VERSION_REFUSALS = ['entry_not_canonical', 'payload_tag_mismatch', 'grant_hash_mismatch'];

export function readLineageOnline(input: LineageOnlineInput): LineageOnlineResult {
  const acct = input.account;
  if (!isPlainObject(acct)) return { ok: false, reason: 'account_authority_unreadable' };
  const entries = input.entries;
  if (!Array.isArray(entries)) return { ok: false, reason: 'lineage_unreadable' };

  type Decoded = { index: number; grant: Grant; envelope: Envelope; hash: string; entryTime?: number };
  const decoded: Decoded[] = [];
  let decodeFailure: LineageOnlineResult | null = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const d = decodeEntry({ account: 'grants', elements: isPlainObject(e) ? e['elements'] : undefined });
    if (!d.ok) {
      if (decodeFailure === null) decodeFailure = VERSION_REFUSALS.includes(d.reason) ? { ok: false, reason: 'lineage_unverified_version', detail: d.reason, index: i } : { ok: false, reason: 'account_entry_undecodable', index: i, cause: d.reason };
      continue;
    }
    if (d.account !== 'grants') continue;
    const t = isPlainObject(e) ? e['entryTime'] : undefined;
    decoded.push({ index: i, grant: d.grant, envelope: d.envelope, hash: d.hash, ...(typeof t === 'number' ? { entryTime: t } : {}) });
  }

  // the account authority rule is the one online gate (GR-58); the subject's books come from the caller and from the Grants themselves
  const forbidden = Array.isArray(input.subjectBooks) ? (input.subjectBooks as unknown[]).filter((b): b is string => typeof b === 'string') : [];
  const subjectAdi = decoded[0]?.grant.subject.adi;
  const gate = checkAccountAuthority({
    ownerBook: acct.ownerBook,
    forbiddenBooks: forbidden,
    ...(subjectAdi === undefined ? {} : { subjectAdi }),
    authorities: acct.authorities,
    history: acct.history,
    incomplete: acct.incomplete,
    safeAfter: acct.safeAfter === undefined ? SAFE_AFTER : acct.safeAfter,
  });
  if (!gate.ok) return gate.index === undefined ? { ok: false, reason: gate.reason } : { ok: false, reason: gate.reason, index: gate.index };
  if (decodeFailure !== null) return decodeFailure;

  const mine = input.grantId === undefined ? decoded : decoded.filter((d) => d.grant.grantId === input.grantId);
  for (const d of mine) if (d.grant.grantor.keyBook !== acct.ownerBook) return { ok: false, reason: 'account_owner_mismatch', index: d.index };

  const lineage = evaluateLineage({ entries: mine.map((d) => ({ grant: d.grant, envelopeVerdict: 'ok' })), now: input.now });
  if (!lineage.ok) return lineage;

  const out: LineageOnlineResult = {
    ok: true,
    head: lineage.head,
    status: lineage.status,
    evidence: 'chain_enforced',
    entries: mine.map((d) => ({ index: d.index, version: d.grant.version, hash: d.hash, ...(d.entryTime === undefined ? {} : { entryTime: d.entryTime }) })),
  };
  if (input.chain !== undefined && input.chain !== null) {
    const head = mine[mine.length - 1]!;
    const v = verifyGrantEnvelope({ grant: head.grant, envelope: head.envelope, chain: input.chain, subjectBooks: Array.isArray(input.subjectBooks) ? input.subjectBooks : [] });
    out.advisory = { headEnvelopeCurrent: v.ok, headEnvelopeReason: v.ok ? null : v.reason };
  }
  return out;
}
