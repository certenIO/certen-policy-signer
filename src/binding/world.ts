/**
 * What the signer must know about the WORLD to bind a decision (DECISION.md section 4): the head of the Grant lineage and the
 * subject a transaction resolves to. Both are read from Accumulate at decision time and are never taken from the producer's
 * claim (GR-34, GR-37). The signer only compares them: the comparison is the core's `bindDecision`.
 *
 * An implementation answers `{ ok: false, detail }` for anything it could not establish (unreadable account, unverifiable
 * lineage, a Grant not in force, an unproven subject): the core then refuses by name (`grant_unverified`,
 * `subject_unproven`), never allows. Production: src/binding/chain-world.ts over the core's `readGrantLineage` and
 * `readSubjectRegistry`.
 */
import type { SubjectType } from '../core/grant-profile.js';

export interface ResolvedSubject { adi: string; type: SubjectType }
export interface GrantHead { hash: string; subject: ResolvedSubject }
export type WorldAnswer<T> = { ok: true; value: T } | { ok: false; detail: string };

export interface BindingWorld {
  /** the head of the lineage `grantId` written by `grantorAdi`, when it is verified and in force */
  grantHead(q: { grantorAdi: string; grantId: string }): Promise<WorldAnswer<GrantHead>>;
  /** the registry-resolved subject of an asserted subject, reading the registries of `principals` */
  resolveSubject(q: { principals: string[]; asserted: { adi: string; assertedBy: string } }): Promise<WorldAnswer<ResolvedSubject>>;
}
