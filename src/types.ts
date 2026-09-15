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
   * governed by several, so a stored book URL is one authority among N.
   *
   * What makes it stale is authority-set membership, not keys: `UpdateAccountAuth` can remove a book
   * from the set or disable it in place without any of its keys changing. Key rotation does the
   * reverse — `UpdateKeyPage`/`UpdateKey` change entries on a PAGE and leave the book URL untouched.
   * Read the ADI's authority set at verification time; that is the part that moves.
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
  /**
   * The decoded calldata. A CERTEN intent carries one `LegCall` per contract-call leg (Phase 6.1); a plain
   * data write may still state a free-text description, which is passed through as a string.
   */
  calldataDecoded?: string | LegCall[];
  /** Assets moved or referenced by legs whose target is pinned with an `asset` (Phase 6.1). */
  assets?: LegAsset[];
  /** True when any leg's call target equals the leg's `from` (a V7 account calling itself). */
  selfCall?: boolean;
  /** True only when every contract-call leg's (chainId, target) is pinned in `decoders.evm_abi`. */
  targetKnown?: boolean;
  /** WHO the transaction is about, when the payload named someone. See `IntentSubject`. */
  subject?: IntentSubject;
  /** WHAT AUTHORITY the call grants, when it grants one. See `IntentGrant`. */
  grant?: IntentGrant;
  raw?: Record<string, unknown>;  // fallback / extra fields
}

/**
 * One contract-call leg's calldata, decoded. Phase 6 seat contract §1.
 *
 * `abi` names the pinned ABI (e.g. `FDBUSD`); it is empty when the target is not pinned and the selector
 * was read generically (ERC-20) or not at all. `function` is empty when the calldata could not be decoded.
 * Integers are decimal strings; bytes32 and addresses are lowercase 0x hex.
 */
export interface LegCall {
  legIndex: number;
  chainId?: number;
  target: string;
  abi: string;
  function: string;
  signature: string;
  args: Record<string, string>;
}

/** An asset a decoded leg moves or references, from the pinned ABI entry's `asset`. */
export interface LegAsset {
  legIndex: number;
  chain: string;
  chainId?: number;
  token: string;
  symbol: string;
  decimals: number;
}

/** Typed operations of a governance body (`updateKeyPage` / `updateAccountAuth`). Phase 6.2. */
export interface GovernanceFact {
  kind: 'updateKeyPage' | 'updateAccountAuth';
  principal: string;
  operations: Array<{ type: string; [k: string]: unknown }>;
}

/**
 * A firm's acceptance (decision 0028 / 0038 §4): a WriteData on `acc://…/acceptances` whose single data
 * element is exactly the canonical JSON `{"amount":N,"category":S,"firm":S,"instructionHash":64hex}`.
 */
export interface AcceptanceFact {
  instructionHash: string;
  category: string;
  amount: number;
  firm: string;
}

/**
 * What a call GRANTS, as opposed to what it moves.
 *
 * ── WHY THIS EXISTS, WHICH IS THE WHOLE POINT ────────────────────────────────────────────────────
 *
 * Every other number on this contract answers "how much moves". An ERC-20 `approve` moves **nothing**
 * and hands somebody standing authority to move a balance later, without asking again. So a gate
 * reading `values[]` sees `0`, and a policy rule meaning "small enough to approve automatically"
 * matches an UNLIMITED spending approval. That is not hypothetical: it was found in this product's own
 * demo data by an unbriefed reviewer in under four minutes.
 *
 * The risk of such a call is not in its amount, and nothing on the wire carried the fact that could
 * bound it.
 *
 * ── WHY FIELDS RATHER THAN THE DECODED TEXT ──────────────────────────────────────────────────────
 *
 * `calldataDecoded` already reads `approve(spender = 0x…, amount = …)`, and an engine could parse it.
 * It must not. That string is prose assembled for a human, and letting a gate read it would let
 * whoever submits a transaction choose the wording that governs them. A decision rests on fields a
 * decoder took out of the bytes, never on a label the payload supplied.
 */
export interface IntentGrant {
  /** Who may spend, as an address string. Absent when the call names nobody. */
  spender?: string;
  /**
   * The allowance in the token's BASE UNITS, as a decimal string — the same form as `values[]`.
   *
   * Deliberately unscaled: scaling needs the token's decimals, and a decoder that guessed them would
   * be inventing the number a control is measured against. An engine that cannot scale can still act
   * on the case that matters most, because an unlimited approval is `2^256 − 1` whatever the decimals.
   */
  allowance?: string;
  /**
   * What is being granted, when the payload named it.
   *
   * Both fields are PASSED THROUGH from the payload, never inferred. `decimals` is present only when
   * the intent stated it and stated it sanely, because a guessed precision is a wrong bound rather
   * than a missing one — an engine that cannot scale should refuse to match rather than assume, which
   * is what the approval console's `maxAllowance` does. The case that matters most needs neither
   * field: an unlimited approval is 2^256 − 1 at every precision.
   */
  asset?: { symbol?: string; decimals?: number };
}

/**
 * THE PENDING TRANSACTION'S OWN HEADER, as Accumulate recorded it. Runbook Phase 2 task 2.5 (F23).
 *
 * Read from the transaction record the node returns (`message.transaction.header`) for EVERY body type
 * — a CERTEN intent, a plain WriteData acceptance transaction (decision 0028), a token send — by the
 * resolver, not by any payload decoder. Nothing here comes from the payload a producer wrote.
 *
 * ── WHAT `authorities` IS, AND WHAT IT IS NOT ────────────────────────────────────────────────────
 *
 * `authorities` is exactly the list of additional authorities Accumulate will enforce on this
 * transaction, on top of the principal account's own authorities. The SUBMITTER composes it. So it
 * says who Accumulate will wait for, never who SHOULD have been listed: a submitter that leaves a
 * required party out produces a transaction that Accumulate completes without that party. A seat whose
 * rules require a party for a class of payment must therefore check this list and deny when the party
 * is missing (runbook decision A2). See `checkRequiredParties` in examples/policy-engine.mjs.
 *
 * ── TWO DIFFERENT EXPIRIES ───────────────────────────────────────────────────────────────────────
 *
 * `header.expiresAt` is the transaction's ON-CHAIN deadline (`header.expire.atTime`). After it no
 * signature can complete the transaction, and this signer refuses to sign it at all (decision 0031).
 * `PolicyRequest.expiresAt` is unrelated: it is how long one decision REQUEST is valid (policy TTL).
 */
export interface TransactionHeaderInfo {
  /** The account the transaction acts on (`header.principal`). Always present. */
  principal: string;
  /**
   * Additional authorities named in the header (`header.authorities`), exactly as recorded. Absent when
   * the header names none. The submitter composed this list — see above.
   */
  authorities?: string[];
  /** The on-chain deadline (`header.expire.atTime`) as ISO-8601 UTC. Absent when the header sets none. */
  expiresAt?: string;
  /** The header memo, when set. Submitter-written free text: display only, never a basis for a decision. */
  memo?: string;
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
  /** Typed governance operations, when the body is `updateKeyPage` / `updateAccountAuth`. */
  governance?: GovernanceFact;
  /** The acceptance content, when the body is a canonical acceptance WriteData. */
  acceptance?: AcceptanceFact;
  /** The transaction header as recorded on chain. See `TransactionHeaderInfo`. */
  header: TransactionHeaderInfo;
  /**
   * Set when the header HAS an expiry that could not be read. Internal only (never sent to an engine):
   * a deadline this process cannot read is a deadline it cannot prove has not passed, so the
   * orchestrator refuses to sign rather than treat it as "no deadline".
   */
  headerExpiryUnreadable?: string;
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
  /** Per contract-call leg for a CERTEN intent (`LegCall[]`); a stated string for a plain data write. */
  calldataDecoded?: string | LegCall[];
  /** Accumulate body type of the transaction (`writeData`, `updateKeyPage`, `updateAccountAuth`, …). */
  bodyType?: string;
  /** `sha256:` + hex of the canonical JSON of this signer's effective config, secrets removed. */
  configVersion?: string;
  /** Assets moved or referenced by decoded legs. See `LegAsset`. */
  assets?: LegAsset[];
  /** True when any leg's target equals its `from` (the V7 calling itself). */
  selfCall?: boolean;
  /** True only when every contract-call leg's (chainId, target) is pinned. */
  targetKnown?: boolean;
  /** Typed operations for governance bodies. See `GovernanceFact`. */
  governance?: GovernanceFact;
  /** Present for a canonical acceptance WriteData. See `AcceptanceFact`. */
  acceptance?: AcceptanceFact;
  /**
   * WHAT AUTHORITY this call grants, when it grants one. See `IntentGrant`.
   *
   * Gate on this as well as on `values[]`, and understand why both are needed: `values[]` bounds what
   * MOVES, and an `approve` moves nothing while handing over the right to move a balance later. A rule
   * set that only bounds amounts will auto-approve an unlimited spending authority and read as though
   * it did something careful.
   *
   * Absent means the call grants nothing nameable — the ordinary case for a transfer. It does NOT mean
   * "grants nothing": a call this decoder could not read has no grant field either, which is why
   * `calldataDecoded` being present with no `grant` is worth a rule of its own.
   */
  grant?: IntentGrant;
  /**
   * The pending transaction's own header, read from Accumulate: principal, the additional authorities
   * Accumulate will enforce, the on-chain deadline, and the memo. See `TransactionHeaderInfo`.
   *
   * Optional on the wire so an engine or wallet that predates it is unaffected; this signer populates it
   * on every request it sends. An engine enforcing a required-party rule (A2) must treat an ABSENT
   * `header` as "cannot verify the parties" and deny, never as "no parties required".
   */
  header?: TransactionHeaderInfo;
  /**
   * How long THIS DECISION REQUEST is valid (policy TTL, default 15 min) — NOT the tx's on-chain
   * deadline. The on-chain deadline is `header.expiresAt`.
   */
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
  /** The signer-config version the decision was taken under (`sha256:…`). Decision A6. */
  configVersion?: string;
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
