/** Accumulate client interface + an in-memory mock for tests. */
import { ExtractedHeader, extractTxHeader } from './header.js';

export interface PendingTxResult {
  found: boolean;
  /**
   * We could not ASK — the node was unreachable, timed out, or answered with something that is not a
   * definitive "no such record". Deliberately distinct from `found: false`, which is the chain telling
   * us the transaction is gone. Collapsing the two marks a live pending tx `expired`, and `expired` is
   * terminal, so a single flaky query would retire a transaction the signer still owes a vote on.
   */
  unavailable?: boolean;
  rawTransaction?: unknown;
  body?: { type: string; [k: string]: unknown };
  principal?: string;
  /**
   * The transaction header as recorded (`message.transaction.header`), read by `extractTxHeader`.
   * Optional so a client that predates it stays valid; the resolver derives it from `rawTransaction`
   * when a client does not supply it.
   */
  header?: ExtractedHeader;
  executed?: boolean;
  expired?: boolean;
}

export interface SignerInfo {
  version: number;
  lastUsedOn: number; // micros
  creditBalance?: number;
}

export interface SubmitResult {
  ok: boolean;
  code?: 'badSignerVersion' | 'insufficientCredits' | 'alreadySigned' | 'expired' | 'error';
  error?: string;
  result?: unknown;
}

/**
 * One signature the chain records against a transaction. Runbook F Phase F4, T32.
 *
 * FACTS, AND NO VERDICT — every field is something the network said. Nothing here is an opinion about
 * whose signature it is; see `TxSignatures` for why that matters.
 */
export interface ChainSignature {
  /** `ed25519`, `ecdsaSha256`, `rsaSha256` … as the protocol names it. */
  type: string;
  /**
   * `sha256(publicKey)` — the same value a key page holds as its entry, so the two can be compared.
   *
   * Computed HERE, in the signer, because this is the component allowed to know how a key page entry
   * is derived. The approval console must never compute one: `scripts/check-no-chain-code.mjs` refuses
   * a `sha256` in its authority module precisely because hashing a key to compare it with a page is a
   * two-line change nobody would think of as adopting chain code, and it is.
   */
  publicKeyHash: string;
  /** The authorities a delegated signature passed through, outermost first. Empty when direct. */
  delegators: string[];
  /** The key page the signature was made on, when the record names one. */
  signer?: string;
}

/**
 * What the chain says about a transaction, and who signed it.
 *
 * ── WHAT THIS ESTABLISHES, AND WHAT IT CANNOT ────────────────────────────────────────────────────
 *
 * It can say: this transaction is delivered or still pending, N signatures satisfied it, and each was
 * of this algorithm, made by the key with this hash, through these delegators.
 *
 * It CANNOT say whose key that was. A key page entry is `sha256(publicKey)` for every key type alike,
 * so nothing on the chain distinguishes an employee's certificate from a piece of software. Binding a
 * key hash to a person is a claim the ROSTER makes — two people proposed it and agreed it — and a
 * reader has to be told which half is which. The signer reports the chain half and stops there.
 *
 * That asymmetry is the whole of T32: the console could already say *the organisation signed in her
 * name*, because our own signer produced that signature and knew which of its keys it used. It could
 * not say *she signed*, because her certificate signs on chain and nothing read it back. This is the
 * reading. The attribution stays a declaration, and stays labelled as one.
 */
export interface TxSignatures {
  /** As the network reports it: `delivered`, `pending`, … Empty when it did not say. */
  status: string;
  /** True only when the network positively said so. Absent evidence is not evidence of absence. */
  delivered: boolean;
  signatures: ChainSignature[];
  /**
   * Set when the transaction could not be read at all.
   *
   * Distinct from an empty `signatures`, for the same reason `PendingTxResult.unavailable` is distinct
   * from `found: false`: a caller must never read "we could not ask" as "nobody signed".
   */
  unavailable?: string;
}

export interface AccumulateClient {
  getPendingTx(txHash: string, signerUrl: string): Promise<PendingTxResult>;
  getSignerInfo(signerUrl: string): Promise<SignerInfo>;
  /** Phase 1/2 discovery: txs in the signer page's on-chain Pending() index (principal/delegated authorities). */
  listPendingForSigner(signerUrl: string): Promise<string[]>;
  /**
   * Phase 3 discovery: scan a key BOOK's signature chain for `signatureRequest` messages and
   * return the hashes of still-pending produced txs. Catches txs where this book is an ADDITIONAL
   * (transaction-header) authority — which under Baikonur are NOT written to any Pending() index.
   */
  listPendingViaSignatureChain(bookUrl: string): Promise<string[]>;
  submit(envelope: unknown): Promise<SubmitResult>;
  /**
   * What the chain says about a transaction and the signatures on it. T32.
   *
   * Optional on the interface so a client that predates it — and the mock below, when a test does not
   * care — is still a valid `AccumulateClient`. A caller must handle its absence.
   */
  getTxSignatures?(txHash: string, principal: string): Promise<TxSignatures>;
}

/* ------------------------------------------------------------------ */
/* Mock client — deterministic, for unit/integration tests.            */
/* ------------------------------------------------------------------ */

export interface MockPending {
  rawTransaction?: unknown;
  body: { type: string; [k: string]: unknown };
  principal: string;
  executed?: boolean;
  expired?: boolean;
}

export class MockAccumulateClient implements AccumulateClient {
  pending = new Map<string, MockPending>();
  signer: SignerInfo = { version: 1, lastUsedOn: 0, creditBalance: 100 };
  submissions: unknown[] = [];
  /** queue of submit results; when empty defaults to ok. */
  submitQueue: SubmitResult[] = [];
  /** When true, getPendingTx reports that the node could not be queried (not that the tx is gone). */
  unavailable = false;

  addPending(txHash: string, p: MockPending) { this.pending.set(txHash, p); }

  async getPendingTx(txHash: string): Promise<PendingTxResult> {
    if (this.unavailable) return { found: false, unavailable: true };
    const p = this.pending.get(txHash);
    if (!p) return { found: false };
    const rawTransaction = p.rawTransaction ?? { header: { principal: p.principal }, body: p.body };
    return {
      found: true,
      rawTransaction,
      body: p.body,
      principal: p.principal,
      header: extractTxHeader(rawTransaction, p.principal),
      executed: p.executed,
      expired: p.expired,
    };
  }
  async getSignerInfo(): Promise<SignerInfo> { return { ...this.signer }; }
  async listPendingForSigner(): Promise<string[]> {
    return [...this.pending.entries()].filter(([, p]) => !p.executed && !p.expired).map(([h]) => h);
  }
  /** Mock has no signature chain; discovery is exercised via listPendingForSigner. */
  async listPendingViaSignatureChain(): Promise<string[]> { return []; }
  async submit(envelope: unknown): Promise<SubmitResult> {
    this.submissions.push(envelope);
    const next = this.submitQueue.shift();
    if (next) {
      // On a version bump, advance the mock signer so a retry succeeds.
      if (next.code === 'badSignerVersion') this.signer.version += 1;
      return next;
    }
    return { ok: true, result: { status: 'delivered' } };
  }
}
