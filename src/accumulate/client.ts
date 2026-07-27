/** Accumulate client interface + an in-memory mock for tests. */

export interface PendingTxResult {
  found: boolean;
  rawTransaction?: unknown;
  body?: { type: string; [k: string]: unknown };
  principal?: string;
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

  addPending(txHash: string, p: MockPending) { this.pending.set(txHash, p); }

  async getPendingTx(txHash: string): Promise<PendingTxResult> {
    const p = this.pending.get(txHash);
    if (!p) return { found: false };
    return {
      found: true,
      rawTransaction: p.rawTransaction ?? { header: { principal: p.principal }, body: p.body },
      body: p.body,
      principal: p.principal,
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
