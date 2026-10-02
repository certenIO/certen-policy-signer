/** The pipeline: trigger → resolve → decide → sign → submit, with idempotency + retries. */
import { randomUUID } from 'node:crypto';
import { AccumulateClient } from './accumulate/client.js';
import { sha256Hex } from './accumulate/signing.js';
import { Keyring } from './signer/keyring.js';
import { PolicyClient } from './policy/policy.js';
import { Store } from './store/store.js';
import { Resolver } from './resolver.js';
import { Logger } from './logger.js';
import { VoteBackend, VoteResult, DirectVoteBackend } from './vote/backend.js';
import { Notifier, NotifyEvent, NULL_NOTIFIER } from './notify.js';
import { PendingRef, PolicyRequest, Receipt, ResolvedTx, SigningRequest } from './types.js';
import { headerDeadlinePassed } from './accumulate/header.js';
import { withDisplay } from './display.js';
import type { PageState } from './ops/rotate.js';
import { checkKeyPageChange, KeyPageRefusal } from './ops/keypage-guard.js';
import { finaliseHold, recordHold } from './store/pending-hold.js';
import { humanRecordId } from './store/store.js';
import { advanceAwaitingHuman } from './officer/landed.js';

export interface OrchestratorOptions {
  submitRejectVote?: boolean;   // default false: deny => withhold signature (tx expires)
  maxBadVersionRetries?: number; // default 3
  policyTtlSeconds?: number;    // default 900
  /** SR4 local guard. Receives EVERY leg amount (`values`), not just the representative one, plus the
   *  count of legs whose amount could not be read at all. */
  guard?: (tx: { account: string; summary: string; value?: string; values?: string[]; unpricedLegs?: number }) => boolean;
  isPaused?: () => boolean;     // SR8 emergency kill switch
  delegators?: string[];        // delegate attachment model: user page(s) delegating to our book
}

/**
 * The rules one key page runs under, when they differ from the process defaults.
 *
 * A fleet rarely shares one rulebook: a trading agent and a treasury page belong on different engines,
 * under different ceilings. Overrides are keyed by page because that is what the poller already carries —
 * `PendingRef.signerUrl` IS the page the work was discovered for, so no extra plumbing is needed to know
 * whose rules apply.
 *
 * Every field is optional and falls back to the process default; a scope states only what differs.
 */
export interface ScopeRules {
  policy?: PolicyClient;
  guard?: OrchestratorOptions['guard'];
  submitRejectVote?: boolean;
}

export interface OrchestratorDeps {
  accumulate: AccumulateClient;
  /** The default policy client. Used for any page without an override. */
  policy: PolicyClient;
  keyring: Keyring;
  store: Store;
  resolver: Resolver;
  logger: Logger;
  /** How the vote reaches the chain. Defaults to DIRECT (submit to Accumulate ourselves). */
  votes?: VoteBackend;
  /** Outbound notifications. Best-effort and non-blocking by contract — see notify.ts. */
  notifier?: Notifier;
  /** Label carried on every notification so a receiver watching several signers can tell them apart. */
  orgId?: string;
  /** Per-page rule overrides, keyed by the page URL LOWERCASED. Absent pages use the defaults. */
  scopeRules?: Map<string, ScopeRules>;
  /**
   * `sha256:` + hex of this signer's effective config (secrets removed), computed at startup. Stamped on
   * every PolicyRequest and Receipt so a decision names the signer configuration it was taken under (A6).
   */
  configVersion?: string;
  /** `decoders.labels`, shown beside addresses in the Phase 7 display (`PolicyRequest.display`). */
  displayLabels?: Record<string, string>;
  /**
   * G-65: read a key page off the chain at decision time. Before this signer approves an `updateKeyPage`
   * transaction it applies the body's operations to what this returns and refuses a change that would
   * leave the page unsatisfiable. Absent (or failing) => an `updateKeyPage` is never approved: the page
   * cannot be read, and the guard never assumes a page state.
   */
  readPage?: (page: string) => Promise<PageState>;
  /**
   * G-69: pages that are HUMAN-ONLY seats (`wallet.human_scopes`). Work found for them is resolved, stored
   * and decided like any other, but this signer never signs for them -- approve or reject: a decision that
   * needs a signature is recorded as `awaiting_human`, and a person signs through officer intake.
   */
  humanOnlyPages?: string[];
  options?: OrchestratorOptions;
  now?: () => number; // injectable clock (ms) for tests
}

export class Orchestrator {
  private readonly opt: Required<Pick<OrchestratorOptions, 'maxBadVersionRetries' | 'policyTtlSeconds' | 'submitRejectVote'>> & OrchestratorOptions;
  private readonly now: () => number;
  private readonly votes: VoteBackend;
  private readonly notifier: Notifier;
  private readonly humanOnly: Set<string>;

  constructor(private readonly d: OrchestratorDeps) {
    this.humanOnly = new Set((d.humanOnlyPages ?? []).map((p) => p.toLowerCase().replace(/\/+$/, '')));
    this.opt = {
      submitRejectVote: d.options?.submitRejectVote ?? false,
      maxBadVersionRetries: d.options?.maxBadVersionRetries ?? 3,
      policyTtlSeconds: d.options?.policyTtlSeconds ?? 900,
      guard: d.options?.guard,
      isPaused: d.options?.isPaused,
      delegators: d.options?.delegators,
    };
    this.now = d.now ?? Date.now;
    this.notifier = d.notifier ?? NULL_NOTIFIER;
    this.votes = d.votes ?? new DirectVoteBackend(d.accumulate, d.keyring, d.logger, {
      maxBadVersionRetries: this.opt.maxBadVersionRetries,
      delegators: this.opt.delegators,
      now: this.now,
    });
  }

  /**
   * The policy engine, local guard, and reject-vote behavior for the page this work belongs to.
   *
   * Falls back field by field rather than all-or-nothing: a scope that overrides only its ceiling keeps
   * the default engine. Matching is case-insensitive because an Accumulate URL is, and a scope written
   * `acc://Agent.acme/book/1` in config must still match the `acc://agent.acme/book/1` the node reports —
   * a miss here would silently run that page under the DEFAULT rules, which is the exact failure the
   * feature exists to prevent.
   */
  private rulesFor(signerUrl: string): Required<Pick<ScopeRules, 'policy' | 'submitRejectVote'>> & Pick<ScopeRules, 'guard'> {
    const o = this.d.scopeRules?.get(signerUrl.toLowerCase());
    return {
      policy: o?.policy ?? this.d.policy,
      guard: o?.guard !== undefined ? o.guard : this.opt.guard,
      submitRejectVote: o?.submitRejectVote ?? this.opt.submitRejectVote,
    };
  }

  /** Every receipt carries the signer-config version (A6), and is filed under its request's record key. */
  private saveReceipt(page: string, r: Receipt): Promise<void> {
    const recordId = this.isHumanOnly(page) ? humanRecordId(r.txHash, page) : undefined;
    return this.d.store.saveReceipt({ ...r, ...(recordId ? { recordId } : {}), ...(this.d.configVersion ? { configVersion: this.d.configVersion } : {}) });
  }

  /**
   * The record key for this transaction ON THIS PAGE (review #1). A keyed seat keeps the tx hash (every
   * existing record); a human-only seat gets its own `<txHash>@<page>` record, so its handling of a
   * transaction can never pre-empt (or freeze) a keyed seat that must vote on the same transaction.
   */
  private rid(r: { txHash: string; signerUrl: string }): string {
    return this.isHumanOnly(r.signerUrl) ? humanRecordId(r.txHash, r.signerUrl) : r.txHash;
  }

  /**
   * Fire an outbound notification. Never throws and never awaited — a notification is a courtesy to the
   * operator's systems, not a step in the decision. See notify.ts for why this is the one place in the
   * codebase that does NOT fail closed.
   */
  private notify(event: NotifyEvent, tx: ResolvedTx | undefined, extra?: { reason?: string; error?: string; txHash?: string }): void {
    try {
      this.notifier.emit({
        event,
        at: new Date(this.now()).toISOString(),
        orgId: this.d.orgId ?? '',
        txHash: tx?.txHash ?? extra?.txHash,
        operationId: tx?.operationId,
        account: tx?.account,
        actionSummary: tx?.summary.action,
        chain: tx?.summary.chain,
        target: tx?.summary.target,
        values: tx?.summary.values,
        reason: extra?.reason,
        error: extra?.error,
      });
    } catch (e) {
      this.d.logger.warn({ event, err: (e as Error).message }, 'notifier threw (ignored)');
    }
  }

  /** Handle one pending-tx reference. Idempotent + single-flight per txHash. */
  async handle(ref: PendingRef): Promise<SigningRequest> {
    const { store, logger } = this.d;
    const existing = await store.get(this.rid(ref));
    if (existing && ['signed', 'rejected', 'expired'].includes(existing.status)) {
      logger.debug({ tx: ref.txHash, status: existing.status }, 'idempotent skip');
      return existing;
    }
    if (!store.tryLock(this.rid(ref))) {
      logger.debug({ tx: ref.txHash }, 'already in-flight');
      return existing ?? (await this.ensure(ref));
    }
    try {
      return await this.run(ref);
    } finally {
      store.unlock(this.rid(ref));
    }
  }

  private async ensure(ref: PendingRef): Promise<SigningRequest> {
    const s = await this.d.store.get(this.rid(ref));
    if (s) return s;
    const req: SigningRequest = {
      txHash: ref.txHash, ...(this.isHumanOnly(ref.signerUrl) ? { recordId: this.rid(ref) } : {}), signerUrl: ref.signerUrl, status: 'discovered',
      attempts: 0, createdAt: this.now(), updatedAt: this.now(),
    };
    try {
      await this.d.store.create(req);
      return req;
    } catch {
      // lost a create race — return the row the winner created
      return (await this.d.store.get(this.rid(ref)))!;
    }
  }

  private async run(ref: PendingRef): Promise<SigningRequest> {
    const { store, resolver, logger } = this.d;
    // Which page this work belongs to decides which engine answers for it and under which ceiling.
    const rules = this.rulesFor(ref.signerUrl);
    const priorStatus = (await store.get(this.rid(ref)))?.status; // was this tx already known? (gates the discovery log)
    await this.ensure(ref);

    // 1. Resolve
    const r = await resolver.resolve(ref);
    // Could not read it. Record nothing terminal about a transaction we failed to look at — leave the row
    // retryable so the next poll asks again once the node is back.
    if (r.kind === 'unavailable') {
      logger.warn({ tx: ref.txHash, err: r.error }, 'could not resolve pending tx; leaving it for the next poll');
      return store.update(this.rid(ref), { lastError: `resolve: ${r.error}` });
    }
    if (r.kind === 'gone') {
      const status = r.reason === 'executed' ? 'signed' : 'expired';
      logger.info({ tx: ref.txHash, reason: r.reason }, 'tx gone before signing');
      // G-64: a hold that ends because the transaction went away is still kept, with that as its outcome.
      return store.update(this.rid(ref), { status, ...finaliseHold(await store.get(this.rid(ref)), `gone:${r.reason}`, this.now()) });
    }
    const tx = r.tx;
    // G-69: the engine has already decided and a person owes the signature. Asking again on every poll
    // would rewrite the decision under them; the request ends when their signature lands (officer intake)
    // or when the transaction goes away (handled just above).
    if (priorStatus === 'awaiting_human') {
      // ...but the chain is read on every poll (review #3): the people's signatures are counted against the
      // page's thresholds, so a signature that landed after officer intake stopped watching still ends it.
      logger.debug({ tx: ref.txHash }, 'awaiting a human signature through officer intake; reading the chain');
      const getTxSignatures = this.d.accumulate.getTxSignatures?.bind(this.d.accumulate);
      return (await advanceAwaitingHuman({ store, readPage: this.d.readPage, ...(getTxSignatures ? { getTxSignatures } : {}), logger, now: this.now }, ref.txHash, ref.signerUrl))
        ?? (await store.get(this.rid(ref)))!;
    }
    await store.update(this.rid(ref), {
      status: 'awaiting_policy', account: tx.account, signerVersion: tx.signerVersion,
      actionSummary: tx.summary.action, operationId: tx.operationId,
    });
    // Discovery: a pending tx that names our book as a required authority. Logged once (first sighting),
    // not on every retry, so an operator can see WHAT was found and on WHICH account.
    if (!priorStatus || priorStatus === 'discovered') {
      logger.info(
        { tx: tx.txHash, account: tx.account, authority: ref.signerUrl, action: tx.summary.action },
        'discovered pending intent; our book is a required authority',
      );
      // Fired once, on first sighting, for the same reason the log line is: a notification on every poll
      // would text the operator every 20 seconds for the life of the transaction.
      this.notify('pending.discovered', tx);
    }

    // Decision 0031: never sign a transaction whose on-chain deadline has passed, nor one whose deadline
    // cannot be read. Checked before the engine is asked (there is nothing left to decide) and again
    // right before signing (the engine may have taken a while).
    const dead = this.deadlineRefusal(tx);
    if (dead) return this.refuseDeadline(tx, dead);

    // 2. Decide
    const policyReq: PolicyRequest = withDisplay({
      requestId: randomUUID(),
      txHash: tx.txHash,
      operationId: tx.operationId,
      // Which of our pages is asking. The wallet has always known -- it is how the poller found this
      // transaction -- and until F5 simply never passed it on.
      signerUrl: tx.signerUrl,
      // WHO the transaction is about, when the payload named someone. Spread rather than assigned: an
      // intent that named nobody must produce a request with NO `subject` key at all, because "absent"
      // and "unknown" are the same state and the signer has no business inventing the difference.
      ...(tx.summary.subject ? { subject: tx.summary.subject } : {}),
      account: tx.account,
      chain: tx.summary.chain,
      actionSummary: tx.summary.action,
      target: tx.summary.target,
      value: tx.summary.value,
      values: tx.summary.values,
      // Tells the engine whether `values` is the WHOLE picture. Without it, a partial list of amounts is
      // indistinguishable from a complete one, and the engine's own ceiling has the same blind spot ours had.
      unpricedLegs: tx.summary.unpricedLegs,
      calldataDecoded: tx.summary.calldataDecoded,
      // What the call GRANTS, beside what it moves. An engine gating only on `values` auto-approves an
      // unlimited spending authority, because an approve moves nothing at all. T18/T21.
      grant: tx.summary.grant,
      // The transaction's own header, read from Accumulate for every body type (task 2.5, F23): the
      // principal, the additional authorities Accumulate will enforce (the submitter chose them — a
      // required-party rule must check this list, A2), the ON-CHAIN deadline and the memo.
      header: tx.header,
      // Phase 6 seat contract §1. Spread so an absent fact is an absent key, never `undefined`.
      bodyType: tx.bodyType,
      ...(this.d.configVersion ? { configVersion: this.d.configVersion } : {}),
      ...(tx.summary.assets ? { assets: tx.summary.assets } : {}),
      // A body that provably carries no contract call (an acceptance, a governance body, or any non-WriteData body)
      // has selfCall=false and targetKnown=true. An undecoded WriteData leaves both absent, so rules stay indeterminate.
      ...(tx.summary.selfCall !== undefined ? { selfCall: tx.summary.selfCall } : noContractCall(tx) ? { selfCall: false } : {}),
      ...(tx.summary.targetKnown !== undefined ? { targetKnown: tx.summary.targetKnown } : noContractCall(tx) ? { targetKnown: true } : {}),
      ...(tx.governance ? { governance: tx.governance } : {}),
      ...(tx.acceptance ? { acceptance: tx.acceptance } : {}),
      // Policy TTL for THIS request. Not the on-chain deadline, which is `header.expiresAt`.
      expiresAt: new Date(this.now() + this.opt.policyTtlSeconds * 1000).toISOString(),
    }, { labels: this.d.displayLabels });
    await store.update(this.rid(ref), { policyRequestId: policyReq.requestId });
    // Kept so a decision service can read back exactly what it was asked (`/relay/pending/:hash`, 6.4).
    await store.savePolicyRequest(policyReq, this.rid(ref));

    // The decision request, carried off chain to the operator's own policy engine. It holds the decoded
    // action plus every gate-relevant amount; the reply drives accept / reject / withhold.
    logger.info({ tx: tx.txHash, policyRequestId: policyReq.requestId, action: tx.summary.action }, 'requesting decision from policy engine');
    let decision;
    try {
      decision = await rules.policy.decide(policyReq);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      logger.warn({ tx: ref.txHash, err: msg }, 'policy decision failed');
      return store.update(this.rid(ref), {
        status: 'awaiting_policy', lastError: `policy: ${msg}`,
        attempts: (await store.get(this.rid(ref)))!.attempts + 1,
      });
    }

    // The engine has not decided yet (out-of-band approval, step-up challenge, review queue). Withhold:
    // sign nothing, leave the tx pending on chain, ask again next poll. This is NOT an error — recording
    // it as one would bury a genuine engine fault under a stream of ordinary waiting, and would make a
    // slow human approval look identical to an outage on /healthz. Attempts are left alone for the same
    // reason: waiting is not a failed attempt.
    if (decision.decision === 'pending') {
      logger.info(
        { tx: ref.txHash, reason: decision.reason },
        'policy engine has not decided yet; withholding signature and will retry',
      );
      // G-64: keep WHY, and under which versions, on the record -- updated on every re-evaluation.
      const pending = recordHold(await store.get(this.rid(ref)), decision, this.now());
      return store.update(this.rid(ref), { status: 'awaiting_policy', lastError: undefined, pending });
    }

    // G-64: the engine has decided; the hold (if there was one) ends here and is kept as history.
    {
      const fin = finaliseHold(await store.get(this.rid(ref)), decision.decision, this.now());
      if (fin.pendingFinal) await store.update(this.rid(ref), fin);
    }

    // SR8 emergency pause — checked BEFORE the deny branch, because a Reject vote is still a SIGNATURE.
    // With `submit_reject_vote: true` (what every shipped config sets), leaving this check further down
    // meant a "paused" wallet went on signing and submitting rejections. Pause means sign NOTHING.
    if (this.opt.isPaused?.()) {
      logger.warn({ tx: ref.txHash, decision: decision.decision }, 'signing paused; withholding signature');
      return store.update(this.rid(ref), { status: 'awaiting_policy', lastError: 'paused' });
    }

    if (decision.decision === 'deny') {
      logger.info({ tx: ref.txHash, reason: decision.reason }, 'policy denied');
      await store.update(this.rid(ref), { status: 'denied', decision: 'deny' });
      // A reject vote that could not be submitted is a FAILURE, exactly as an approve vote is — the
      // result was being discarded here. That mattered: `rejected` is terminal, so the tx was never
      // retried, while the receipt below recorded `vote: reject` for a vote that never reached the
      // chain. The transaction stayed pending on-chain until expiry with the audit trail claiming it
      // had been actively killed. Leave it retryable and write no receipt, as the approve path does.
      let rejectVote: VoteResult | undefined;
      if (rules.submitRejectVote) {
        const lateReject = this.deadlineRefusal(tx);
        if (lateReject) return this.refuseDeadline(tx, lateReject, decision);
        // G-69: a human-only seat holds no key; the reject the engine asked for is a person's to cast.
        if (this.isHumanOnly(tx.signerUrl)) return this.awaitHuman(tx, 'reject', decision);
        const res = await this.signAndSubmit(tx, 'reject');
        if (!res.ok) {
          logger.error({ tx: ref.txHash, err: res.error }, 'reject vote submission failed');
          this.notify('signature.failed', tx, { reason: decision.reason, error: res.error });
          return store.update(this.rid(ref), { status: 'error', lastError: res.error });
        }
        rejectVote = res;
      }
      const final = await store.update(this.rid(ref), { status: 'rejected' });
      await this.saveReceipt(tx.signerUrl, {
        txHash: tx.txHash, operationId: tx.operationId, decision: 'deny',
        vote: rules.submitRejectVote ? 'reject' : undefined,
        reason: decision.reason,
        // Whose re-authentication this was about. The receipts are the audit trail, and a year later
        // that is the question being asked of them.
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: decision.evidence,
        // A reject is a signature too, and the record should say which key cast it. A deployment that
        // withholds rejects rather than casting them has nothing to attribute, and gets nothing.
        ...(rejectVote?.signedBy ? { signedBy: rejectVote.signedBy } : {}),
      });
      this.notify('decision.denied', tx, { reason: decision.reason });
      return final;
    }

    // SR4 local guard (defense-in-depth even if policy approved)
    if (rules.guard && !rules.guard({
      account: tx.account, summary: tx.summary.action,
      value: tx.summary.value, values: tx.summary.values, unpricedLegs: tx.summary.unpricedLegs,
    })) {
      logger.warn({ tx: ref.txHash, values: tx.summary.values, unpricedLegs: tx.summary.unpricedLegs }, 'local guard blocked an approved tx');
      // Keep the engine's reason and evidence on the record: the receipt must show that the engine
      // approved and WE refused, not merely that something was blocked.
      await this.saveReceipt(tx.signerUrl, {
        txHash: tx.txHash, operationId: tx.operationId, decision: 'approve',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'local_guard', values: tx.summary.values },
      });
      return store.update(this.rid(ref), { status: 'rejected', lastError: 'local_guard_block' });
    }

    // G-65: never approve an updateKeyPage that would brick the page it changes (see keyPageRefusal).
    const brick = await this.keyPageRefusal(tx);
    if (brick) return this.refuseKeyPage(tx, brick, decision);

    // 3. Sign + submit (approve). The deadline is re-read against the clock now: an approval that arrived
    // after the transaction died must not become a late signature (0031).
    const lateApprove = this.deadlineRefusal(tx);
    if (lateApprove) return this.refuseDeadline(tx, lateApprove, decision);

    // G-69: a human-only seat holds no key. Every check above (pause, SR4 ceiling, G-65 key-page guard,
    // deadline) has run exactly as for a keyed seat; the approve signature is a person's to make.
    if (this.isHumanOnly(tx.signerUrl)) return this.awaitHuman(tx, 'approve', decision);

    await store.update(this.rid(ref), { status: 'approved', decision: 'approve', assertionRef: decision.assertion ? sha256Hex(decision.assertion) : undefined });
    // Whose key signs. T29: when the policy engine names the approver, THEIR key signs — so the
    // signature on chain is the person's rather than the organisation's cast in their name. Absent,
    // the organisation signs as itself, exactly as before.
    const res = await this.castForApprovers(tx, 'approve', approverKeyRefs(decision.evidence));
    if (res.ok) {
      await this.saveReceipt(tx.signerUrl, {
        txHash: tx.txHash, operationId: tx.operationId, decision: 'approve', vote: 'approve',
        signatureHash: res.signatureHash, submittedAt: this.now(), accumulateResult: 'ok',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: decision.evidence,
        // What satisfied it, carried through rather than re-derived. F4.
        ...(res.signedBy ? { signedBy: res.signedBy } : {}),
      });
      this.notify('decision.approved', tx, { reason: decision.reason });
      return store.update(this.rid(ref), { status: 'signed', timestampMicros: res.timestamp });
    }
    // A vote we decided to cast but could not is a real failure — say so. It used to be recorded in the
    // store and nowhere else, so an operator watching the logs saw the policy decision and then silence.
    logger.error({ tx: ref.txHash, err: res.error }, 'vote submission failed');
    this.notify('signature.failed', tx, { reason: decision.reason, error: res.error });
    return store.update(this.rid(ref), { status: 'error', lastError: res.error });
  }

  /**
   * Why this transaction must not be signed on account of its header deadline, or undefined if it may.
   * Decision 0031, fail closed: a passed deadline and an unreadable one are both refusals.
   */
  private deadlineRefusal(tx: ResolvedTx): { lastError: string; reason: string } | undefined {
    if (tx.headerExpiryUnreadable) {
      return {
        lastError: 'header_expiry_unreadable',
        reason: `refusing to sign: the transaction header has an expiry that cannot be read (${tx.headerExpiryUnreadable})`,
      };
    }
    if (headerDeadlinePassed(tx.header, this.now())) {
      return {
        lastError: 'header_deadline_passed',
        reason: `refusing to sign: the transaction's on-chain deadline ${tx.header.expiresAt} has passed (now ${new Date(this.now()).toISOString()})`,
      };
    }
    return undefined;
  }

  /**
   * Record a deadline refusal. No signature of any kind is made. A passed deadline is terminal
   * (`expired`): Accumulate rejects any signature after it (S7), so there is nothing to retry. An
   * unreadable one is `rejected` with the reason, as a local-guard block is.
   */
  private async refuseDeadline(
    tx: ResolvedTx,
    refusal: { lastError: string; reason: string },
    decision?: { decision: string; reason?: string; evidence?: Record<string, unknown> },
  ): Promise<SigningRequest> {
    this.d.logger.warn(
      { tx: tx.txHash, headerExpiresAt: tx.header.expiresAt, decision: decision?.decision, err: refusal.lastError },
      refusal.reason,
    );
    await this.saveReceipt(tx.signerUrl, {
      txHash: tx.txHash, operationId: tx.operationId,
      ...(decision && (decision.decision === 'approve' || decision.decision === 'deny') ? { decision: decision.decision } : {}),
      reason: refusal.reason,
      ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
      policyEvidence: {
        ...(decision?.evidence ?? {}),
        ...(decision?.reason ? { engineReason: decision.reason } : {}),
        blockedBy: refusal.lastError,
        ...(tx.header.expiresAt ? { headerExpiresAt: tx.header.expiresAt } : {}),
      },
    });
    const status = refusal.lastError === 'header_deadline_passed' ? 'expired' : 'rejected';
    return this.d.store.update(this.rid(tx), {
      status, lastError: refusal.lastError,
      // G-64: a refusal before any decision ends the hold too (after a decision it has already ended).
      ...finaliseHold(await this.d.store.get(this.rid(tx)), refusal.lastError, this.now()),
    });
  }

  /** G-69: is `page` a human-only seat (no key here, ever)? */
  private isHumanOnly(page: string): boolean {
    return this.humanOnly.has(page.toLowerCase().replace(/\/+$/, ''));
  }

  /**
   * G-69: record a decision that needs a signature this signer cannot make, because the seat's page holds
   * no key. No signature of any kind is cast. The PolicyRequest (display, summaryHash, header, facts) is
   * already stored, so a person on the page signs through officer intake against it; the receipt keeps the
   * engine's decision, reason and evidence, and says whose signature is owed and which vote.
   */
  private async awaitHuman(
    tx: ResolvedTx,
    vote: 'approve' | 'reject',
    decision: { decision: string; reason?: string; evidence?: Record<string, unknown> },
  ): Promise<SigningRequest> {
    this.d.logger.info({ tx: tx.txHash, page: tx.signerUrl, decision: decision.decision, vote }, 'human-only seat: decision recorded; a person on the page signs through officer intake');
    await this.saveReceipt(tx.signerUrl, {
      txHash: tx.txHash, operationId: tx.operationId,
      ...(decision.decision === 'approve' || decision.decision === 'deny' ? { decision: decision.decision } : {}),
      reason: decision.reason,
      ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
      policyEvidence: { ...(decision.evidence ?? {}), awaitingHumanSignature: { page: tx.signerUrl, vote } },
    });
    return this.d.store.update(this.rid(tx), {
      status: 'awaiting_human',
      ...(decision.decision === 'approve' || decision.decision === 'deny' ? { decision: decision.decision } : {}),
      lastError: undefined,
    });
  }

  /**
   * G-65: why an approve vote on this transaction must be withheld because it would brick a key page, or
   * undefined when it may proceed.
   *
   * Only an `updateKeyPage` body changes a page's entries or thresholds, and its principal IS the page it
   * changes. The operations are the resolver's decoding of the on-chain body (`tx.governance`); the page
   * is read NOW. A body whose operations could not be decoded, and a page that cannot be read, are both
   * refusals -- never an assumed page state.
   */
  private async keyPageRefusal(tx: ResolvedTx): Promise<KeyPageRefusal | undefined> {
    if (tx.bodyType !== 'updateKeyPage') return undefined;
    const ops = tx.governance?.kind === 'updateKeyPage' ? tx.governance.operations : [{ type: 'unknown', unrecognized: true }];
    const v = await checkKeyPageChange(this.d.readPage, tx.account, ops);
    return v.ok ? undefined : v.refusal;
  }

  /**
   * Withhold the approve vote the engine asked for. No signature of any kind is cast.
   *
   * WHY WITHHOLD, NOT REJECT. Both are fail-closed (neither can carry the change towards execution). The
   * engine -- the party's own policy (P1) -- decided `approve`; this guard is the signer's safety
   * interlock, not a second policy, so it refuses to sign rather than inventing a reject vote the policy
   * never chose. That is the same posture as the SR4 local guard above. A party that wants the change
   * actively killed still has its policy's `deny` (which casts a reject when configured) and its humans.
   *
   *   - The change would brick the page: terminal `rejected`, with a receipt that records the engine's
   *     approve, `blockedBy: keypage_guard` and the structured refusal (reason, threshold, entries).
   *   - The page could not be read: NOT terminal. Nothing is known about the change, so the request stays
   *     `awaiting_policy` and is asked again next poll; still nothing is signed.
   */
  private async refuseKeyPage(
    tx: ResolvedTx,
    refusal: KeyPageRefusal,
    decision: { decision: string; reason?: string; evidence?: Record<string, unknown> },
  ): Promise<SigningRequest> {
    const lastError = `keypage_guard: ${refusal.reason}`;
    if (refusal.reason === 'page_unreadable') {
      this.d.logger.warn({ tx: tx.txHash, page: tx.account, refusal }, 'key page unreadable; withholding the approve vote and will retry');
      return this.d.store.update(this.rid(tx), { status: 'awaiting_policy', lastError });
    }
    this.d.logger.warn({ tx: tx.txHash, page: tx.account, refusal }, 'REFUSING to approve an updateKeyPage that would brick the page; no signature cast');
    await this.saveReceipt(tx.signerUrl, {
      txHash: tx.txHash, operationId: tx.operationId, decision: 'approve',
      reason: decision.reason,
      ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
      policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'keypage_guard', keyPageRefusal: refusal },
    });
    return this.d.store.update(this.rid(tx), { status: 'rejected', lastError });
  }

  /**
   * Cast the vote through whichever backend is configured — DIRECT (we submit the envelope to Accumulate)
   * or GATEWAY (the Certen api-gateway hands us the bytes; we sign; we hand the signature back). The
   * decision above this line is identical either way: the policy engine gates both.
   */
  private async signAndSubmit(tx: ResolvedTx, vote: 'approve' | 'reject', keyRef?: string): Promise<VoteResult> {
    // G-69 defence in depth: nothing above reaches here for a human-only seat, and if anything ever did,
    // the answer is no signature -- never a key found for the page by some other route.
    if (this.isHumanOnly(tx.signerUrl)) return { ok: false, error: 'human-only scope: this signer holds no key for this page' };
    await this.d.store.update(this.rid(tx), { status: 'signing', signerVersion: tx.signerVersion });
    return this.votes.cast(tx, vote, keyRef === undefined ? {} : { keyRef });
  }

  /**
   * Cast one vote per named approver. Runbook F, T29-d.
   *
   * A key page counts signatures itself, so two approvers means two signatures — one from each of
   * their keys. Votes are cast in sequence rather than together, deliberately: each consumes the
   * page's `lastUsedOn` and moves its version, and two concurrent votes would race into a
   * bad-version retry that looks like a fault.
   *
   * ── PARTIAL SUCCESS IS THE NORMAL CASE, NOT A FAULT ────────────────────────────────────────────
   *
   * A half-enrolled organisation is the ordinary state of a rollout: one approver's key is held here
   * and another's is not. The one that can sign SHOULD, and the transaction is then correctly short
   * of its threshold and left pending — the protocol's own answer, and not something to report as a
   * failure. So this succeeds if ANY vote landed, records the first that did, and says in the log
   * which refs could not be signed for and why.
   *
   * Only when nothing at all could be signed is it a failure, and then the first error is the one
   * worth reporting: it is the reason the transaction has no signature.
   */
  private async castForApprovers(
    tx: ResolvedTx,
    vote: 'approve' | 'reject',
    refs: string[],
  ): Promise<VoteResult> {
    if (this.isHumanOnly(tx.signerUrl)) return { ok: false, error: 'human-only scope: this signer holds no key for this page' };
    // Nobody named: one vote, the organisation's own key, exactly as before T29.
    if (refs.length === 0) return this.signAndSubmit(tx, vote);

    // From one ref upward the loop below handles it, so a named approver this wallet cannot sign for
    // is RECORDED as a failed vote rather than thrown out of the pipeline. One ref and two refs
    // failing the same way is the point: a misconfigured ref is an operational fact about one
    // transaction, not an exception for the poll loop to cope with.

    await this.d.store.update(this.rid(tx), { status: 'signing', signerVersion: tx.signerVersion });
    let first: VoteResult | undefined;
    let firstError: string | undefined;

    for (const ref of refs) {
      let res: VoteResult;
      try {
        res = await this.votes.cast(tx, vote, { keyRef: ref });
      } catch (e) {
        // A ref this wallet holds no key for throws rather than substituting the organisation's key.
        // That is the T29 refusal working; it is not a reason to abandon the approvers it CAN sign for.
        res = { ok: false, error: (e as Error).message };
      }
      if (res.ok) {
        this.d.logger.info({ tx: tx.txHash, keyRef: ref }, 'signed as the named approver');
        first ??= res;
      } else {
        this.d.logger.warn({ tx: tx.txHash, keyRef: ref, err: res.error }, 'could not sign as the named approver');
        firstError ??= res.error;
      }
    }

    if (first) return first;
    return { ok: false, ...(firstError ? { error: firstError } : {}) };
  }
}

/**
 * The approver's key ref, as the policy engine named it. Runbook F, T29.
 *
 * `evidence` is a free-form record on the decision — part of the frozen contract, so naming the
 * approver needs no contract change (invariant F-9). What arrives here came from the policy engine
 * over the MAC channel, which authenticates it but says nothing about whether the value is one this
 * process holds a key for: that is checked in the keyring, which refuses an unknown ref rather than
 * substituting the organisation's key.
 *
 * Read strictly. A non-string, an empty string, or an over-long value is treated as ABSENT rather than
 * passed on, so a malformed decision falls back to the organisation signing as itself — the behaviour
 * every deployment had before this existed — instead of failing the vote. The one thing it must never
 * do is turn a garbled ref into a DIFFERENT valid ref, and returning undefined cannot.
 */
export function approverKeyRef(evidence: Record<string, unknown> | undefined): string | undefined {
  const raw = evidence?.['approverKeyRef'];
  if (typeof raw !== 'string') return undefined;
  const ref = raw.trim();
  if (!ref || ref.length > 256) return undefined;
  return ref;
}

/**
 * EVERY approver whose key should sign. Runbook F, T29-d.
 *
 * A key page counts signatures against its own threshold, so a 2-of-N page needs two signatures and
 * each approver makes their own with the key they control — measured on Kermit, not assumed. One vote
 * per transaction would leave such a page one signature short and the transaction pending until it
 * expired, which is what this exists to prevent.
 *
 * Reads `approverKeyRefs` (a list), falling back to the single `approverKeyRef` so a console that has
 * not been updated keeps working exactly as it did. Duplicates are collapsed: two votes with the same
 * key are one signature to the page and a wasted round trip to find that out.
 *
 * An empty result means nobody was named, and the caller signs once as the organisation — the
 * behaviour of every deployment before T29.
 */
export function approverKeyRefs(evidence: Record<string, unknown> | undefined): string[] {
  const raw = evidence?.['approverKeyRefs'];
  const list = Array.isArray(raw) ? raw : [];
  const refs: string[] = [];
  for (const item of list) {
    if (typeof item !== 'string') continue;      // a malformed entry is skipped, not fatal
    const ref = item.trim();
    if (!ref || ref.length > 256) continue;
    if (!refs.includes(ref)) refs.push(ref);
  }
  if (refs.length) return refs;
  const single = approverKeyRef(evidence);
  return single ? [single] : [];
}

/** True when the transaction provably carries no contract call: acceptance and governance facts, or a non-WriteData body. */
function noContractCall(tx: { bodyType?: string; acceptance?: unknown; governance?: unknown }): boolean {
  return Boolean(tx.acceptance || tx.governance || (tx.bodyType && tx.bodyType !== 'writeData'));
}
