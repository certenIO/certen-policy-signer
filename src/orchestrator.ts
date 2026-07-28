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
import { PendingRef, PolicyRequest, ResolvedTx, SigningRequest } from './types.js';

export interface OrchestratorOptions {
  submitRejectVote?: boolean;   // default false: deny => withhold signature (tx expires)
  maxBadVersionRetries?: number; // default 3
  policyTtlSeconds?: number;    // default 900
  /** SR4 local guard. Receives EVERY leg amount (`values`), not just the representative one. */
  guard?: (tx: { account: string; summary: string; value?: string; values?: string[] }) => boolean;
  isPaused?: () => boolean;     // SR8 emergency kill switch
  delegators?: string[];        // delegate attachment model: user page(s) delegating to our book
}

export interface OrchestratorDeps {
  accumulate: AccumulateClient;
  keyring: Keyring;
  policy: PolicyClient;
  store: Store;
  resolver: Resolver;
  logger: Logger;
  /** How the vote reaches the chain. Defaults to DIRECT (submit to Accumulate ourselves). */
  votes?: VoteBackend;
  options?: OrchestratorOptions;
  now?: () => number; // injectable clock (ms) for tests
}

export class Orchestrator {
  private readonly opt: Required<Pick<OrchestratorOptions, 'maxBadVersionRetries' | 'policyTtlSeconds' | 'submitRejectVote'>> & OrchestratorOptions;
  private readonly now: () => number;
  private readonly votes: VoteBackend;

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
    this.votes = d.votes ?? new DirectVoteBackend(d.accumulate, d.keyring, d.logger, {
      maxBadVersionRetries: this.opt.maxBadVersionRetries,
      delegators: this.opt.delegators,
      now: this.now,
    });
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
    const { store, resolver, policy, logger } = this.d;
    const priorStatus = (await store.get(ref.txHash))?.status; // was this tx already known? (gates the discovery log)
    await this.ensure(ref);

    // 1. Resolve
    const r = await resolver.resolve(ref);
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
    }

    // 2. Decide
    const policyReq: PolicyRequest = {
      requestId: randomUUID(),
      txHash: tx.txHash,
      operationId: tx.operationId,
      account: tx.account,
      chain: tx.summary.chain,
      actionSummary: tx.summary.action,
      target: tx.summary.target,
      value: tx.summary.value,
      values: tx.summary.values,
      calldataDecoded: tx.summary.calldataDecoded,
      expiresAt: new Date(this.now() + this.opt.policyTtlSeconds * 1000).toISOString(),
    };
    await store.update(ref.txHash, { policyRequestId: policyReq.requestId });

    // The decision request, carried off chain to the operator's own policy engine. It holds the decoded
    // action plus every gate-relevant amount; the reply drives accept / reject / withhold.
    logger.info({ tx: tx.txHash, policyRequestId: policyReq.requestId, action: tx.summary.action }, 'requesting decision from policy engine');
    let decision;
    try {
      decision = await policy.decide(policyReq);
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
      if (this.opt.submitRejectVote) {
        // A reject vote that could not be submitted is a FAILURE, exactly as an approve vote is — the
        // result was being discarded here. That mattered: `rejected` is terminal, so the tx was never
        // retried, while the receipt below recorded `vote: reject` for a vote that never reached the
        // chain. The transaction stayed pending on-chain until expiry with the audit trail claiming it
        // had been actively killed. Leave it retryable and write no receipt, as the approve path does.
        const res = await this.signAndSubmit(tx, 'reject');
        if (!res.ok) {
          logger.error({ tx: ref.txHash, err: res.error }, 'reject vote submission failed');
          return store.update(ref.txHash, { status: 'error', lastError: res.error });
        }
      }
      const final = await store.update(ref.txHash, { status: 'rejected' });
      await store.saveReceipt({
        txHash: tx.txHash, operationId: tx.operationId, decision: 'deny',
        vote: this.opt.submitRejectVote ? 'reject' : undefined,
        reason: decision.reason,
        policyEvidence: decision.evidence,
      });
      return final;
    }

    // SR4 local guard (defense-in-depth even if policy approved)
    if (this.opt.guard && !this.opt.guard({ account: tx.account, summary: tx.summary.action, value: tx.summary.value, values: tx.summary.values })) {
      logger.warn({ tx: ref.txHash, values: tx.summary.values }, 'local guard blocked an approved tx');
      // Keep the engine's reason and evidence on the record: the receipt must show that the engine
      // approved and WE refused, not merely that something was blocked.
      await store.saveReceipt({
        txHash: tx.txHash, operationId: tx.operationId, decision: 'approve',
        reason: decision.reason,
        policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'local_guard', values: tx.summary.values },
      });
      return store.update(ref.txHash, { status: 'rejected', lastError: 'local_guard_block' });
    }

    // 3. Sign + submit (approve)
    await store.update(ref.txHash, { status: 'approved', decision: 'approve', assertionRef: decision.assertion ? sha256Hex(decision.assertion) : undefined });
    const res = await this.signAndSubmit(tx, 'approve');
    if (res.ok) {
      await store.saveReceipt({
        txHash: tx.txHash, operationId: tx.operationId, decision: 'approve', vote: 'approve',
        signatureHash: res.signatureHash, submittedAt: this.now(), accumulateResult: 'ok',
        reason: decision.reason,
        policyEvidence: decision.evidence,
      });
      return store.update(ref.txHash, { status: 'signed', timestampMicros: res.timestamp });
    }
    // A vote we decided to cast but could not is a real failure — say so. It used to be recorded in the
    // store and nowhere else, so an operator watching the logs saw the policy decision and then silence.
    logger.error({ tx: ref.txHash, err: res.error }, 'vote submission failed');
    return store.update(ref.txHash, { status: 'error', lastError: res.error });
  }

  /**
   * Cast the vote through whichever backend is configured — DIRECT (we submit the envelope to Accumulate)
   * or GATEWAY (the Certen api-gateway hands us the bytes; we sign; we hand the signature back). The
   * decision above this line is identical either way: the policy engine gates both.
   */
  private async signAndSubmit(tx: ResolvedTx, vote: 'approve' | 'reject'): Promise<VoteResult> {
    await this.d.store.update(tx.txHash, { status: 'signing', signerVersion: tx.signerVersion });
    return this.votes.cast(tx, vote);
  }
}
