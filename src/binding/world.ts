/**
 * What the signer must know about the WORLD to bind a decision (DECISION.md section 4): the head of the Grant lineage and the
 * subject a transaction resolves to. Both are read from Accumulate at decision time and are never taken from the producer's
 * claim (GR-34, GR-37). The signer only compares them: the comparison is the core's `bindDecision`.
 *
 * One call, `establish`, answers both from ONE evaluation (one cache view, one set of counters): the Grant head from the
 * grantor's own data account, then the subject through the registry of the GRANTOR and the subject's acceptance
 * (READER-MODEL-V2). An implementation answers `{ ok: false, detail }` for anything it could not establish (unreadable account,
 * an account that fails the authority rule, a Grant not in force, an unproven subject): the core then refuses by name
 * (`grant_unverified`, `subject_unproven`), never allows. Production: src/binding/chain-world.ts.
 */
import type { SubjectType } from '../core/grant-profile.js';
import type { EvaluationStats } from './read-cache.js';

export interface ResolvedSubject { adi: string; type: SubjectType }
/** `grant` is the head Grant object as the lineage verified it, handed back to the subject resolution and never trusted from anywhere else */
export interface GrantHead { hash: string; subject: ResolvedSubject; grant: unknown }
export type WorldAnswer<T> = { ok: true; value: T } | { ok: false; detail: string };

export interface WorldFacts {
  head: WorldAnswer<GrantHead>;
  /** null when it was not attempted (no head, or the transaction asserts no subject) */
  subject: WorldAnswer<ResolvedSubject> | null;
  /** what the evaluation cost and how old the facts it used were */
  stats?: EvaluationStats;
}

export interface BindingWorld {
  establish(q: {
    grantorAdi: string;
    /** the key book that must own the grantor's accounts */
    grantorBook: string;
    grantId: string;
    /** the intent's asserted subject, or null */
    asserted: { adi: string; assertedBy: string } | null;
  }): Promise<WorldFacts>;
}
