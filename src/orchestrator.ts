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
import { PendingRef, PolicyRequest, ResolvedTx, SigningRequest } from './types.js';

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
  options?: OrchestratorOptions;
  now?: () => number; // injectable clock (ms) for tests
}

export class Orchestrator {
  private readonly opt: Required<Pick<OrchestratorOptions, 'maxBadVersionRetries' | 'policyTtlSeconds' | 'submitRejectVote'>> & OrchestratorOptions;
  private readonly now: () => number;
  private readonly votes: VoteBackend;
  private readonly notifier: Notifier;

  constructor(private readonly d: OrchestratorDeps) {
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
    const existing = await store.get(ref.txHash);
    if (existing && ['signed', 'rejected', 'expired'].includes(existing.status)) {
      logger.debug({ tx: ref.txHash, status: existing.status }, 'idempotent skip');
      return existing;
    }
    if (!store.tryLock(ref.txHash)) {
      logger.debug({ tx: ref.txHash }, 'already in-flight');
      return existing ?? (await this.ensure(ref));
    }
    try {
      return await this.run(ref);
    } finally {
      store.unlock(ref.txHash);
    }
  }

  private async ensure(ref: PendingRef): Promise<SigningRequest> {
    const s = await this.d.store.get(ref.txHash);
    if (s) return s;
    const req: SigningRequest = {
      txHash: ref.txHash, signerUrl: ref.signerUrl, status: 'discovered',
      attempts: 0, createdAt: this.now(), updatedAt: this.now(),
    };
    try {
      await this.d.store.create(req);
      return req;
    } catch {
      // lost a create race — return the row the winner created
      return (await this.d.store.get(ref.txHash))!;
    }
  }

  private async run(ref: PendingRef): Promise<SigningRequest> {
    const { store, resolver, logger } = this.d;
    // Which page this work belongs to decides which engine answers for it and under which ceiling.
    const rules = this.rulesFor(ref.signerUrl);
    const priorStatus = (await store.get(ref.txHash))?.status; // was this tx already known? (gates the discovery log)
    await this.ensure(ref);

    // 1. Resolve
    const r = await resolver.resolve(ref);
    // Could not read it. Record nothing terminal about a transaction we failed to look at — leave the row
    // retryable so the next poll asks again once the node is back.
    if (r.kind === 'unavailable') {
      logger.warn({ tx: ref.txHash, err: r.error }, 'could not resolve pending tx; leaving it for the next poll');
      return store.update(ref.txHash, { lastError: `resolve: ${r.error}` });
    }
    if (r.kind === 'gone') {
      const status = r.reason === 'executed' ? 'signed' : 'expired';
      logger.info({ tx: ref.txHash, reason: r.reason }, 'tx gone before signing');
      return store.update(ref.txHash, { status });
    }
    const tx = r.tx;
    await store.update(ref.txHash, {
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

    // 2. Decide
    const policyReq: PolicyRequest = {
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
      expiresAt: new Date(this.now() + this.opt.policyTtlSeconds * 1000).toISOString(),
    };
    await store.update(ref.txHash, { policyRequestId: policyReq.requestId });

    // The decision request, carried off chain to the operator's own policy engine. It holds the decoded
    // action plus every gate-relevant amount; the reply drives accept / reject / withhold.
    logger.info({ tx: tx.txHash, policyRequestId: policyReq.requestId, action: tx.summary.action }, 'requesting decision from policy engine');
    let decision;
    try {
      decision = await rules.policy.decide(policyReq);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      logger.warn({ tx: ref.txHash, err: msg }, 'policy decision failed');
      return store.update(ref.txHash, {
        status: 'awaiting_policy', lastError: `policy: ${msg}`,
        attempts: (await store.get(ref.txHash))!.attempts + 1,
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
      return store.update(ref.txHash, { status: 'awaiting_policy', lastError: undefined });
    }

    // SR8 emergency pause — checked BEFORE the deny branch, because a Reject vote is still a SIGNATURE.
    // With `submit_reject_vote: true` (what every shipped config sets), leaving this check further down
    // meant a "paused" wallet went on signing and submitting rejections. Pause means sign NOTHING.
    if (this.opt.isPaused?.()) {
      logger.warn({ tx: ref.txHash, decision: decision.decision }, 'signing paused; withholding signature');
      return store.update(ref.txHash, { status: 'awaiting_policy', lastError: 'paused' });
    }

    if (decision.decision === 'deny') {
      logger.info({ tx: ref.txHash, reason: decision.reason }, 'policy denied');
      await store.update(ref.txHash, { status: 'denied', decision: 'deny' });
      // A reject vote that could not be submitted is a FAILURE, exactly as an approve vote is — the
      // result was being discarded here. That mattered: `rejected` is terminal, so the tx was never
      // retried, while the receipt below recorded `vote: reject` for a vote that never reached the
      // chain. The transaction stayed pending on-chain until expiry with the audit trail claiming it
      // had been actively killed. Leave it retryable and write no receipt, as the approve path does.
      let rejectVote: VoteResult | undefined;
      if (rules.submitRejectVote) {
        const res = await this.signAndSubmit(tx, 'reject');
        if (!res.ok) {
          logger.error({ tx: ref.txHash, err: res.error }, 'reject vote submission failed');
          this.notify('signature.failed', tx, { reason: decision.reason, error: res.error });
          return store.update(ref.txHash, { status: 'error', lastError: res.error });
        }
        rejectVote = res;
      }
      const final = await store.update(ref.txHash, { status: 'rejected' });
      await store.saveReceipt({
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
      await store.saveReceipt({
        txHash: tx.txHash, operationId: tx.operationId, decision: 'approve',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'local_guard', values: tx.summary.values },
      });
      return store.update(ref.txHash, { status: 'rejected', lastError: 'local_guard_block' });
    }

    // 3. Sign + submit (approve)
    await store.update(ref.txHash, { status: 'approved', decision: 'approve', assertionRef: decision.assertion ? sha256Hex(decision.assertion) : undefined });
    // Whose key signs. T29: when the policy engine names the approver, THEIR key signs — so the
    // signature on chain is the person's rather than the organisation's cast in their name. Absent,
    // the organisation signs as itself, exactly as before.
    const res = await this.castForApprovers(tx, 'approve', approverKeyRefs(decision.evidence));
    if (res.ok) {
      await store.saveReceipt({
        txHash: tx.txHash, operationId: tx.operationId, decision: 'approve', vote: 'approve',
        signatureHash: res.signatureHash, submittedAt: this.now(), accumulateResult: 'ok',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: decision.evidence,
        // What satisfied it, carried through rather than re-derived. F4.
        ...(res.signedBy ? { signedBy: res.signedBy } : {}),
      });
      this.notify('decision.approved', tx, { reason: decision.reason });
      return store.update(ref.txHash, { status: 'signed', timestampMicros: res.timestamp });
    }
    // A vote we decided to cast but could not is a real failure — say so. It used to be recorded in the
    // store and nowhere else, so an operator watching the logs saw the policy decision and then silence.
    logger.error({ tx: ref.txHash, err: res.error }, 'vote submission failed');
    this.notify('signature.failed', tx, { reason: decision.reason, error: res.error });
    return store.update(ref.txHash, { status: 'error', lastError: res.error });
  }

  /**
   * Cast the vote through whichever backend is configured — DIRECT (we submit the envelope to Accumulate)
   * or GATEWAY (the Certen api-gateway hands us the bytes; we sign; we hand the signature back). The
   * decision above this line is identical either way: the policy engine gates both.
   */
  private async signAndSubmit(tx: ResolvedTx, vote: 'approve' | 'reject', keyRef?: string): Promise<VoteResult> {
    await this.d.store.update(tx.txHash, { status: 'signing', signerVersion: tx.signerVersion });
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
    // Nobody named: one vote, the organisation's own key, exactly as before T29.
    if (refs.length === 0) return this.signAndSubmit(tx, vote);

    // From one ref upward the loop below handles it, so a named approver this wallet cannot sign for
    // is RECORDED as a failed vote rather than thrown out of the pipeline. One ref and two refs
    // failing the same way is the point: a misconfigured ref is an operational fact about one
    // transaction, not an exception for the poll loop to cope with.

    await this.d.store.update(tx.txHash, { status: 'signing', signerVersion: tx.signerVersion });
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
