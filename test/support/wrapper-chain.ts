/**
 * A mock chain for the wrapper model. Shared by the wrapper suites.
 *
 * It models where things are RECORDED, because that is what the wrapper design turns on:
 *  - a person's key signature is recorded with whatever delegators it claims (`keySigns`), and is what
 *    `getTxSignatures` lists — wrapper mode must never act on it;
 *  - when a person's page reaches its threshold through a wrapper, their book's AUTHORITY signature is
 *    recorded at the wrapper book's partition (`approvesThrough`), and that is what
 *    `getAuthoritySignatures(tx, wrapperBook)` lists.
 * A vote this signer submits through `[W, …]` is recorded the same way, as our book's authority signature
 * at W's book, so a test sees our vote on chain after we cast it, as a live node would show it.
 */
import { createHash } from 'node:crypto';
import { AuthorityVote, AuthorityVotes, ChainSignature, MockAccumulateClient, PendingTxResult, TxSignatures } from '../../src/accumulate/client.js';
import { bookOf } from '../../src/delegation/path.js';

const k = (txHash: string, account: string) => `${txHash}|${account.toLowerCase()}`;

export class WrapperChain extends MockAccumulateClient {
  /** Key signatures per tx hash (what `getTxSignatures` reports). */
  sigs = new Map<string, ChainSignature[]>();
  /** Authority votes per (tx hash, account) — what `getAuthoritySignatures` reports at that account. */
  votesAt = new Map<string, AuthorityVote[]>();
  /** Accounts whose authority-signature read fails. */
  unreadable = new Set<string>();
  /** Every (txHash, address) a transaction was read at, and every account votes were read at. */
  reads: Array<{ txHash: string; at: string }> = [];
  voteReads: string[] = [];
  /** Pending txIDs per account, as the v3 `pending` query lists them. Our own page and book stay empty. */
  pendingAt = new Map<string, Array<{ txHash: string; principal: string }>>();
  /** Accounts whose pending query fails. */
  failingPending = new Set<string>();
  /** Every chain read a poll cycle made, by kind, for the capacity numbers. */
  calls = { pendingForAccount: 0, pendingForSigner: 0, signatureChain: 0 };
  /** False = our submitted votes never show up on chain (isolates the store's own idempotency). */
  recordOurVotes = true;

  /** A key signature claiming `hops` (hop order). The network records it before checking any hop. */
  keySigns(txHash: string, signer: string, hops: string[]) {
    const list = this.sigs.get(txHash) ?? [];
    list.push({ type: 'ed25519', publicKeyHash: createHash('sha256').update(signer).digest('hex'), delegators: [...hops].reverse(), hops: [...hops], signer });
    this.sigs.set(txHash, list);
  }

  /** A person's page reached its threshold through `path`: their book's vote lands at `path[0]`'s book. */
  approvesThrough(txHash: string, personPage: string, path: string[], over: Partial<AuthorityVote> = {}) {
    const at = k(txHash, bookOf(path[0]!));
    const list = this.votesAt.get(at) ?? [];
    list.push({ origin: personPage, authority: bookOf(personPage), delegators: [...path], vote: 'accept', historical: false, ...over });
    this.votesAt.set(at, list);
  }

  /** A transaction waiting on `account`'s pending list (a wrapper book, when its page is short of threshold). */
  pendingOn(account: string, txHash: string, principal: string) {
    const list = this.pendingAt.get(account.toLowerCase()) ?? [];
    list.push({ txHash, principal });
    this.pendingAt.set(account.toLowerCase(), list);
  }

  override async listPendingForAccount(url: string): Promise<Array<{ txHash: string; principal: string }>> {
    this.calls.pendingForAccount++;
    if (this.failingPending.has(url.toLowerCase())) throw new Error(`pending query failed for ${url}`);
    return [...(this.pendingAt.get(url.toLowerCase()) ?? [])];
  }
  /** A delegate's own page: always empty, as on the real network. */
  override async listPendingForSigner(url: string): Promise<string[]> {
    this.calls.pendingForSigner++;
    return (this.pendingAt.get(url.toLowerCase()) ?? []).map((p) => p.txHash);
  }
  override async listPendingViaSignatureChain(): Promise<string[]> {
    this.calls.signatureChain++;
    return [];
  }

  override async getPendingTx(txHash: string, at?: string): Promise<PendingTxResult> {
    this.reads.push({ txHash, at: String(at) });
    return super.getPendingTx(txHash);
  }

  async getTxSignatures(txHash: string): Promise<TxSignatures> {
    const p = this.pending.get(txHash);
    return { status: p?.executed ? 'delivered' : 'pending', delivered: !!p?.executed, signatures: [...(this.sigs.get(txHash) ?? [])] };
  }

  async getAuthoritySignatures(txHash: string, account: string): Promise<AuthorityVotes> {
    this.voteReads.push(account);
    if (this.unreadable.has(account.toLowerCase())) return { delivered: false, votes: [], unavailable: 'node down' };
    const p = this.pending.get(txHash);
    return { delivered: !!p?.executed, votes: [...(this.votesAt.get(k(txHash, account)) ?? [])] };
  }

  override async submit(envelope: unknown) {
    const res = await super.submit(envelope);
    if (res.ok) {
      let s = (envelope as { signatures: any[] }).signatures[0];
      const outerFirst: string[] = [];
      while (s.type === 'delegated') { outerFirst.push(String(s.delegator)); s = s.signature; }
      const hops = outerFirst.reverse();
      if (hops.length && this.recordOurVotes) this.approvesThrough(String(s.transactionHash), String(s.signer), hops);
    }
    return res;
  }
}

/** Unwrap a submitted envelope's signature to its hops (hop order), inner signer and data. */
export function submittedVote(envelope: unknown): { hops: string[]; signer: string; data?: string; vote?: string } {
  let s = (envelope as { signatures: any[] }).signatures[0];
  const outerFirst: string[] = [];
  while (s.type === 'delegated') { outerFirst.push(String(s.delegator)); s = s.signature; }
  return { hops: outerFirst.reverse(), signer: String(s.signer), ...(s.data ? { data: String(s.data) } : {}), ...(s.vote ? { vote: String(s.vote) } : {}) };
}
