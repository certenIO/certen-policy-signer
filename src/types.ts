/** Shared domain types for the signing wallet. */

export type Vote = 'approve' | 'reject' | 'abstain';

export const VOTE_CODE: Record<Vote, number> = { approve: 0, reject: 1, abstain: 2 };

/** A pointer to a pending transaction that may need our signature. Advisory only. */
export interface PendingRef {
  txHash: string;      // hex, 64 chars
  signerUrl: string;   // acc://<org>.acme/book/1
}

/** Human-readable + structured description of what the tx does, for the policy engine. */
export interface ActionSummary {
  action: string;                 // "Transfer 5,000 ACME" / "Contract call ping(bytes32)"
  chain?: string;
  target?: string;
  value?: string;                 // representative amount (leg 0) — display / back-compat
  values?: string[];              // ALL gate-relevant amounts (one per intent leg); all-or-nothing gate
  /**
   * Legs that move value but whose amount could NOT be read.
   *
   * `values` holds only amounts a decoder could actually parse, so a leg it could not price simply is not
   * in the list — and a gate that walks `values` would pass it without ever looking at it. Counting those
   * legs here is what lets both the local ceiling and your policy engine tell "every amount is under the
   * limit" apart from "every amount I could read is under the limit". Absent or 0 means all legs priced.
   */
  unpricedLegs?: number;
  calldataDecoded?: string;
  raw?: Record<string, unknown>;  // fallback / extra fields
}

/** Fully resolved pending transaction, ready to sign. */
export interface ResolvedTx {
  txHash: string;
  account: string;                // principal
  signerUrl: string;
  signerVersion: number;
  bodyType: string;
  operationId?: string;
  summary: ActionSummary;
  rawTransaction: unknown;        // opaque tx object to re-submit in the envelope
  lastUsedOn: number;             // micros, for timestamp derivation
}

/** Request sent to the org's policy engine. */
export interface PolicyRequest {
  requestId: string;
  txHash: string;
  operationId?: string;
  account: string;
  chain?: string;
  actionSummary: string;
  target?: string;
  value?: string;                 // representative amount (leg 0)
  values?: string[];              // ALL leg amounts — policy engine gates all-or-nothing across these
  /** Value-moving legs whose amount could not be read; if > 0, `values` is INCOMPLETE. Deny unless you
   *  have another way to bound them — the signer's own ceiling refuses to sign in this case. */
  unpricedLegs?: number;
  calldataDecoded?: string;
  /** How long THIS DECISION REQUEST is valid (policy TTL, default 15 min) — NOT the tx's on-chain deadline. */
  expiresAt: string;              // ISO
}

/**
 * Decision returned by the policy engine.
 *
 * `pending` means "I have not decided yet" — the engine is waiting on something out-of-band (a human
 * approval, a step-up auth challenge, a review queue). The signer withholds: it signs NOTHING, leaves the
 * transaction pending on chain, and asks again on the next poll.
 *
 * It exists as its own value because the alternatives are both wrong. Answering `deny` to mean "not yet"
 * casts a real reject vote that kills a transaction the engine might have approved a minute later. Stalling
 * the HTTP response until a human answers ties up the request until it times out, and a timeout is
 * indistinguishable from an outage. `pending` says "ask me again" without spending a signature.
 *
 * An engine using `pending` MUST key its own state on `txHash`, which is stable across polls, and not on
 * `requestId`, which the signer regenerates every time — otherwise it re-opens a new challenge on each poll.
 */
export interface Decision {
  decision: 'approve' | 'deny' | 'pending';
  reason?: string;
  evidence?: Record<string, unknown>;
  assertion?: string;            // optional signed JWS
}

export type RequestStatus =
  | 'discovered'
  | 'awaiting_policy'
  | 'approved'
  | 'denied'
  | 'signing'
  | 'signed'
  | 'rejected'
  | 'expired'
  | 'error';

export interface SigningRequest {
  txHash: string;
  operationId?: string;
  account?: string;
  signerUrl: string;
  signerVersion?: number;
  actionSummary?: string;
  policyRequestId?: string;
  status: RequestStatus;
  decision?: 'approve' | 'deny';
  assertionRef?: string;
  timestampMicros?: number;
  attempts: number;
  lastError?: string;
  createdAt: number;
  updatedAt: number;
}

export interface Receipt {
  txHash: string;
  operationId?: string;
  decision?: 'approve' | 'deny';
  vote?: Vote;
  /** The policy engine's stated reason. Persisted: the audit trail must say WHY, not just what. */
  reason?: string;
  signatureHash?: string;        // hash of the submitted signature (audit; not the sig itself)
  submittedAt?: number;
  accumulateResult?: string;
  policyEvidence?: Record<string, unknown>;
}
