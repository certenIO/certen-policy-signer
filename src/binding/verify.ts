/**
 * The signer's check of a decision record (certen.decision/v1) BEFORE any signature: the glue between the policy reply, the
 * transaction about to be signed, the world and the core's `bindDecision` (DECISION.md section 4, DE-01 to DE-09, DE-54, DE-61).
 *
 * What it does, in order:
 *   1. builds the request FROM THE TRANSACTION (src/binding/request.ts): a transaction that cannot be bound is refused
 *      `presented_malformed` with the reason in `detail`;
 *   2. reads the reply's `record` member: an absent record (a legacy reply) on a seat that requires binding is
 *      `decision_malformed` (detail `record_absent`); a reply whose `decision` member disagrees with the record is
 *      `decision_malformed` (detail `verb_mismatch`);
 *   3. when the transaction names a Grant, reads the head and the resolved subject from the world in ONE evaluation (before the
 *      lock: network reads never hold the journal); the counters and the age of the facts go into the consumed entry;
 *   4. calls the core inside the nonce store's exclusive step; an accepted decision has its nonce consumed (durable) before this
 *      function returns, which is before any signature. A refusal changes nothing: no consumption, no vote, no cancel.
 * A failure to read the world or to write the journal is a refusal, never an allow.
 */
import { bindDecision, type BindingState } from '../core/decision-binding.js';
import { JournalError } from './journal.js';
import { NonceStore } from './nonces.js';
import { buildPresentedRequest } from './request.js';
import type { ResolvedTx } from '../types.js';
import type { BindingWorld, ResolvedSubject } from './world.js';
import type { EvaluationStats } from './read-cache.js';

/** the member of the policy reply that carries the certen.decision/v1 record (INTERFACE-1 of DESIGN.md) */
export const DECISION_RECORD_MEMBER = 'record';

export interface BindingRules {
  /** the seat id of this scope */
  seat: string;
  /** identities (key or ADI) this seat authorises to decide */
  authorizedApprovers: string[];
  /** the cap on expiresAt - issuedAt, in seconds */
  maxWindowSeconds: number;
  /** the policy hash this seat pins; null records the hash and does not compare it (OQ-DAX2-1) */
  policyHash: string | null;
  requireGrant: boolean;
  /** whose Grants this seat takes, and the key book that must own the grantor's accounts (both or neither) */
  grantorAdi?: string;
  grantorBook?: string;
}

export interface BindingRuntime {
  nonces: NonceStore;
  /** absent: a transaction that names a Grant cannot be verified and is refused `grant_unverified` */
  world?: BindingWorld;
  nowSeconds: () => number;
}

export interface BoundDecision {
  ok: true;
  verb: 'approve' | 'deny';
  requestHash: string;
  decisionHash: string;
  nonce: string;
  grantHash: string | null;
  policyHash: string;
  /** false when the seat pins no policy: the hash is recorded, not compared */
  policyPinned: boolean;
  approver: string;
  seat: string;
  /** the subject the world resolved, or null when no Grant was in play */
  subject: ResolvedSubject | null;
  /** what the evaluation of the world cost and how old its facts were; null when no Grant was in play */
  facts: EvaluationStats | null;
}
export type BindingOutcome = BoundDecision | { ok: false; reason: string; detail?: string; requestHash?: string; nonce?: string };

const refuse = (reason: string, detail?: string): BindingOutcome => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export async function verifyBinding(a: {
  reply: Record<string, unknown>;
  tx: Pick<ResolvedTx, 'txHash' | 'rawTransaction' | 'summary'>;
  rules: BindingRules;
  runtime: BindingRuntime;
  /**
   * Called after the world is read and BEFORE the nonce is consumed, with the resolved subject (or null): a reason it returns
   * stops the check without consuming anything. The pause gate uses it, so a decision is never spent while the seat or the
   * subject is paused and is still valid after a resume.
   */
  gate?: (subject: ResolvedSubject | null) => string | undefined;
}): Promise<BindingOutcome> {
  const { reply, tx, rules, runtime } = a;
  const now = runtime.nowSeconds();

  // 1. the request, from the transaction about to be signed
  const built = buildPresentedRequest(tx);
  if (!built.ok) return refuse('presented_malformed', built.detail);
  const { request, grantRef, grantRefHash, assertedSubject } = built.value;
  // DE-76: a legCount other than 1 is refused by the core (multi_leg_unsupported) after the presented transaction is read, so a
  // multi-leg intent never reaches the world: the refusal is the first thing it gets

  // 2. the record
  // (a multi-leg intent is refused by the core BEFORE it reads the decision, DE-76: the record is not looked at for it)
  const rec = reply[DECISION_RECORD_MEMBER];
  if (built.value.legCount === 1) {
    if (rec === undefined || rec === null) return refuse('decision_malformed', 'record_absent');
    if (isObj(rec) && typeof rec['decision'] === 'string' && rec['decision'] !== reply['decision']) return refuse('decision_malformed', 'verb_mismatch');
  }

  // 3. the world, only when the transaction names a Grant (a seat without a Grant requirement and a transaction without one
  //    need no head and no subject: DE-61); the core compares the claim with the head, never the other way round
  let head: { hash: string; subject: ResolvedSubject; grant: unknown } | null = null;
  let facts: EvaluationStats | null = null;
  let headDetail: string | undefined;
  let subject: ResolvedSubject | null = null;
  let subjectDetail: string | undefined;
  if (grantRef !== null) {
    if (runtime.world === undefined || rules.grantorAdi === undefined || rules.grantorBook === undefined) {
      headDetail = rules.grantorAdi === undefined || rules.grantorBook === undefined ? 'no_grantor_configured' : 'no_world_configured';
    } else {
      try {
        const w = await runtime.world.establish({ grantorAdi: rules.grantorAdi, grantorBook: rules.grantorBook, grantId: grantRef.grantId, asserted: assertedSubject });
        facts = w.stats ?? null;
        if (w.head.ok) head = w.head.value;
        else headDetail = w.head.detail;
        if (head !== null) {
          if (w.subject === null) subjectDetail = 'no_asserted_subject';
          else if (w.subject.ok) subject = w.subject.value;
          else subjectDetail = w.subject.detail;
        }
      } catch (e) {
        headDetail = `world_error:${(e as Error).message}`;
      }
    }
  }

  const base: Omit<BindingState, 'consumed'> = {
    requireGrant: rules.requireGrant,
    grantHeadHash: head === null ? null : head.hash,
    grantHeadSubject: head === null ? null : { ...head.subject },
    expectedPolicyHash: rules.policyHash,
    authorizedApprovers: [...rules.authorizedApprovers],
    maxWindowSeconds: rules.maxWindowSeconds,
  };
  const presented = { request, legCount: built.value.legCount, grantRefHash, seat: rules.seat, subject: subject === null ? null : { ...subject } };

  const stop = a.gate?.(subject);
  if (stop !== undefined) return refuse(stop);

  // 4. the core, with the nonce consumed (durable) inside the same exclusive step
  try {
    return await runtime.nonces.consumeWith<BindingOutcome>((consumed) => {
      const r = bindDecision({ state: { ...base, consumed }, now, decision: rec, presented });
      if (!r.ok) {
        const detail = r.detail ?? (r.reason === 'grant_unverified' ? headDetail : r.reason === 'subject_unproven' ? subjectDetail : undefined);
        return { result: refuse(r.reason, detail) };
      }
      return {
        result: {
          ok: true, verb: r.verb, requestHash: r.requestHash, decisionHash: r.decisionHash, nonce: r.nonce, grantHash: r.grantHash,
          policyHash: r.policyHash, policyPinned: r.policyPinned, approver: r.approver, seat: r.seat, subject, facts,
        },
        consume: { requestHash: r.requestHash, nonce: r.nonce, ...(facts === null ? {} : { extra: { facts: factsRecord(facts) } }) },
      };
    });
  } catch (e) {
    if (e instanceof JournalError) return refuse(e.reason === 'decision_replayed' ? 'decision_replayed' : 'decision_not_recorded', e.reason === 'decision_replayed' ? undefined : `${e.reason}${e.detail ? ' ' + e.detail : ''}`);
    throw e;
  }
}

/** The age and cost of the facts a decision was bound on, as the journal records them (integers only): the bound a reader can state. */
export function factsRecord(f: EvaluationStats): Record<string, number> {
  return { queries: f.queries, hits: f.cacheHits, misses: f.cacheMisses, maxFactAgeMs: Math.round(f.maxFactAgeMs), ttlMs: f.ttlMs };
}
