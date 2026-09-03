/** Shared domain types for the signing wallet. */

export type Vote = 'approve' | 'reject' | 'abstain';

export const VOTE_CODE: Record<Vote, number> = { approve: 0, reject: 1, abstain: 2 };

/** A pointer to a pending transaction that may need our signature. Advisory only. */
export interface PendingRef {
  txHash: string;      // hex, 64 chars
  signerUrl: string;   // acc://<org>.acme/book/1
}

/**
 * WHO A TRANSACTION IS ABOUT — the end user whose policy decision gates it.
 *
 * `subject` is not `initiator` and not `account`. The initiator is whoever asked for the transaction;
 * `account` is the on-chain principal it acts on; the subject is the person it is *about*. They coincide
 * when a user submits their own gated transaction and diverge whenever an organisation acts on a user's
 * behalf — which is the case this field exists for.
 *
 * ── IT IS AN ASSERTION, NOT A PROOF ───────────────────────────────────────────────────────────────
 *
 * The subject is an assertion by whoever wrote the intent, not a proof by the user it names. Nothing on
 * chain binds it: Accumulate verified only that the submitter could sign for the transaction's principal,
 * and the subject is not the principal. An engine that acts on `subject.adi` is therefore trusting the
 * intent producer to name the right person; a compromised producer can name any enrolled identity it
 * likes and ask the engine to re-authenticate the wrong human. The subject is an input to a decision,
 * never an authorization.
 *
 * The one field on a request that CANNOT be forged is `account`, the on-chain principal. So pin it:
 * accept a subject claim only when `account` is an account belonging to a customer you already have a
 * relationship with. That is one line of engine config and it is the difference between trusting anyone
 * who can reach your endpoint and trusting claims written under an account you agreed to trust.
 *
 * Absent means absent. Old intents, third-party producers and non-intent payloads carry no subject, and
 * the signer never invents one. An engine that REQUIRES a subject and does not get one must return
 * `{"decision":"deny"}` — throwing merely withholds, and leaves the transaction alive until it expires.
 */
export interface IntentSubject {
  /** The Accumulate ADI — `acc://alice.acme`. The identity, and what enrollment bound. Key on THIS. */
  adi: string;
  /**
   * A hint, never the identity. A book can live under an ADI without governing it, and an ADI can be
   * governed by several. Keying on the book makes every key rotation a re-enrollment; read the ADI's
   * authority set at verification time instead.
   */
  keyBook?: string;
  /** The producer's own opaque reference for this person, when it sent one. */
  id?: string;
  /** Who is making the claim — the identity that wrote the intent. */
  assertedBy?: string;
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
  /** WHO the transaction is about, when the payload named someone. See `IntentSubject`. */
  subject?: IntentSubject;
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
  /**
   * WHO this transaction is about, when the payload named someone. May be absent — see `IntentSubject`
   * for what it is worth and for what to do when it is not there.
   */
  subject?: IntentSubject;
  /**
   * WHICH KEY PAGE IS ASKING. Runbook F Phase F5.
   *
   * The page, not the book: a book is the authority and a page is the seat, and a wallet holding a
   * treasury seat and a risk seat holds two pages. Answering "the book" would merge exactly the two
   * questions this field exists to separate.
   *
   * Without it, one policy endpoint serving a multi-page signer cannot tell a treasury seat's question
   * from a risk seat's -- it sees two identical requests about one transaction and answers the same
   * thing twice. A deployment can work around that today by giving each scope its own `policy.url`,
   * which is a legitimate shape rather than a hack, and this is the tidy version.
   *
   * Optional on the wire so an engine that predates it is unaffected, and so a wallet that has not
   * been upgraded does not become unanswerable.
   */
  signerUrl?: string;
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

/** Every status a request can hold. Exported as a value so the HTTP layer can validate a caller's filter
 *  against it rather than keeping a second copy that drifts. */
export const REQUEST_STATUSES = [
  'discovered',
  'awaiting_policy',
  'approved',
  'denied',
  'signing',
  'signed',
  'rejected',
  'expired',
  'error',
] as const;

export type RequestStatus = (typeof REQUEST_STATUSES)[number];

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
  /**
   * The subject's ADI at decision time. The receipts ARE the audit trail, and an auditor reading one a
   * year later is asking whose re-authentication approved this signature. Absent when the intent named
   * nobody.
   */
  subject?: string;
  vote?: Vote;
  /** The policy engine's stated reason. Persisted: the audit trail must say WHY, not just what. */
  reason?: string;
  signatureHash?: string;        // hash of the submitted signature (audit; not the sig itself)
  submittedAt?: number;
  accumulateResult?: string;
  policyEvidence?: Record<string, unknown>;
  /**
   * What actually satisfied the vote. Runbook F Phase F4.
   *
   * Which key page the signature was made on, with which algorithm, and the hash of the key -- the
   * three facts any honest answer to "did a PERSON approve this, or did the organisation approve it in
   * their name" rests on. For a delegated vote `page` is the INNER signer, whose key it was, and
   * `delegators` names the seats it satisfied.
   *
   * Facts and no verdict, deliberately. A classification computed at signing time would be this
   * process's opinion, frozen, and impossible to check against the chain afterwards; these can be
   * compared to the key page entry they claim to be. Absent on a vote that was never accepted, and on
   * every receipt written before this field existed.
   */
  signedBy?: {
    page: string;
    signatureType: string;
    publicKeyHash: string;
    delegators: string[];
    /**
     * Whose behalf the key was held on, when the deployment declared that it is somebody's.
     *
     * Present means THE ORGANISATION SIGNED IN A PERSON'S NAME. That is legitimate for rotating an
     * expired certificate and for retiring a leaver, and it is never legitimate on an approval -- so
     * it is the one thing on this record that is worth alarming on rather than merely displaying.
     *
     * Absent is the ordinary case and says nothing about a person either way. It does NOT mean a
     * person signed: nothing on a key page distinguishes a certificate from a software key, so no
     * record can establish that from the chain alone.
     */
    onBehalfOf?: string;
  };
}
