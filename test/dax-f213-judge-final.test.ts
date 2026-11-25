/**
 * DAX-F213 (rehearsal 5b, 2026-11-25): every seat judges EVERY transaction its book is an authority for, including one another authority
 * made final before this seat could vote, and records that decision through the normal decision layer. A vote that cannot be submitted is
 * recorded as such, by name (`voteNotSubmitted`: the transaction was final, rejected by <authority> / executed), never as `expired` or silence.
 * A seat never records an approval as if it counted, and never submits to a final transaction.
 *
 * Discovery: Accumulate records each signature request on the AUTHORITY's signature chain (accumulate v1.4.x
 * internal/core/execute/v2/block/msg_signature_request.go:136-142 -> internal/database/signatures.go:87-99), whatever the transaction's state,
 * and the chain is append-only, so the entry outlives the transaction being final. The poller reads that chain forward from a persisted cursor.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { MockAccumulateClient, type TxSignatures } from '../src/accumulate/client.js';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Poller, openRequestsOf } from '../src/poller.js';
import { NO_PAUSES } from './support/no-pauses.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const TX2 = 'cd'.repeat(32);
const SEAT_PAGE = 'acc://fdb-risk.acme/book/1';
const SEAT_BOOK = 'acc://fdb-risk.acme/book';
const PAYER_BOOK = 'acc://harbor-mfg.acme/book';
const PRINCIPAL = 'acc://harbor-mfg.acme/data';
const MISMATCH = 'declaration_mismatch: the leg pays a beneficiary no declared instruction carries';

/** A mock chain that also answers who signed (the payer's book rejected it, threshold 1). */
class Chain extends MockAccumulateClient {
  sigs = new Map<string, TxSignatures>();
  /** book -> signature-chain entries (signatureRequest only; the index is the position) */
  sigChain = new Map<string, Array<{ txHash: string; principal: string }>>();
  async getTxSignatures(txHash: string): Promise<TxSignatures> {
    return this.sigs.get(txHash) ?? { status: '', delivered: false, signatures: [] };
  }
  async listSignatureRequests(book: string, since?: number) {
    const all = this.sigChain.get(book) ?? [];
    if (since === undefined) return { next: all.length, requests: [] };
    return { next: all.length, requests: all.slice(since).map((r, i) => ({ index: since + i, ...r })) };
  }
}

function rejectedByPayer(acc: Chain, tx = TX) {
  acc.addPending(tx, { body: { type: 'sendTokens', to: [{ url: 'acc://orchid.acme/tokens', amount: '850000' }] }, principal: PRINCIPAL, failed: true, status: 'rejected' } as never);
  acc.sigs.set(tx, {
    status: 'rejected', delivered: false,
    signatures: [
      { type: 'ed25519', publicKeyHash: '11'.repeat(32), delegators: [], hops: [], signer: `${PAYER_BOOK}/2`, vote: 'approve' },
      { type: 'ed25519', publicKeyHash: '22'.repeat(32), delegators: [], hops: [], signer: `${PAYER_BOOK}/2`, vote: 'reject' },
    ],
  });
}

function rig(policy: MockPolicyClient, opts: { submitRejectVote?: boolean } = { submitRejectVote: true }) {
  const acc = new Chain();
  const store = new MemoryStore();
  const orch = new Orchestrator({
    pauses: NO_PAUSES, accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9))),
    policy, store, resolver: new Resolver(acc), logger: silent, options: opts,
  });
  return { acc, store, orch, policy };
}

describe('DAX-F213: a seat judges a transaction another authority made final before it could vote', () => {
  it('judges it, records deny with its reason, and records the vote as NOT submitted because the payer book rejected it', async () => {
    const { acc, store, orch, policy } = rig(new MockPolicyClient({ decision: 'deny', reason: MISMATCH }));
    rejectedByPayer(acc);
    const r = await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL });
    expect(policy.calls.length).toBe(1);                       // judged, through the normal decision layer
    expect(r.status).toBe('final');                             // not `expired`
    expect(r.decision).toBe('deny');
    expect(acc.submissions.length).toBe(0);                     // never submits to a final transaction
    const rc = await store.getReceipt(TX);
    expect(rc).toMatchObject({ decision: 'deny', reason: MISMATCH, voteNotSubmitted: { reason: 'transaction_final', chainStatus: 'rejected', finalBy: [PAYER_BOOK] } });
    expect(rc?.vote).toBeUndefined();
    expect(rc?.signatureHash).toBeUndefined();
    // the policy request the decision was asked on is the normal one
    expect(policy.calls[0]!.txHash).toBe(TX);
  });

  it('an approval of an executed transaction is recorded as an approval whose vote was not submitted, never as signed', async () => {
    const { acc, store, orch } = rig(new MockPolicyClient({ decision: 'approve', reason: 'within limits' }));
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://orchid.acme/tokens', amount: '5' }] }, principal: PRINCIPAL, executed: true });
    const r = await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL });
    expect(r.status).toBe('final');
    expect(acc.submissions.length).toBe(0);
    const rc = await store.getReceipt(TX);
    expect(rc).toMatchObject({ decision: 'approve', voteNotSubmitted: { chainStatus: 'executed', finalBy: [] } });
    expect(rc?.vote).toBeUndefined();
    expect(rc?.accumulateResult).toBeUndefined();
  });

  it('a held decision on a transaction that then ends rejected is closed as final with its hold, without asking the engine again', async () => {
    const { acc, store, orch, policy } = rig(new MockPolicyClient({ decision: 'pending', reason: 'awaiting a person' }));
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://orchid.acme/tokens', amount: '5' }] }, principal: PRINCIPAL });
    expect((await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL })).status).toBe('awaiting_policy');
    rejectedByPayer(acc);
    const r = await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL });
    expect(policy.calls.length).toBe(1);
    expect(r.status).toBe('final');
    expect(r.pendingFinal?.reason).toBe('awaiting a person');
    const rc = await store.getReceipt(TX);
    expect(rc).toMatchObject({ reason: 'awaiting a person', voteNotSubmitted: { chainStatus: 'rejected', finalBy: [PAYER_BOOK] } });
    expect(rc?.decision).toBeUndefined();
  });

  it('a decided seat whose reject vote could not be submitted before the transaction became final records the decision and the vote not submitted', async () => {
    const { acc, store, orch, policy } = rig(new MockPolicyClient({ decision: 'deny', reason: MISMATCH }));
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://orchid.acme/tokens', amount: '5' }] }, principal: PRINCIPAL });
    acc.submitQueue = [{ ok: false, code: 'error', error: 'transaction has been rejected' }];
    expect((await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL })).status).toBe('error');
    rejectedByPayer(acc);
    const r = await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL });
    expect(policy.calls.length).toBe(1);                       // the decision stands; not asked again
    expect(r.status).toBe('final');
    expect(acc.submissions.length).toBe(1);                     // the one failed attempt, nothing after final
    expect(await store.getReceipt(TX)).toMatchObject({ decision: 'deny', reason: MISMATCH, voteNotSubmitted: { chainStatus: 'rejected', finalBy: [PAYER_BOOK] } });
  });

  it('once judged, later polls are an idempotent skip', async () => {
    const { acc, orch, policy } = rig(new MockPolicyClient({ decision: 'deny', reason: MISMATCH }));
    rejectedByPayer(acc);
    await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL });
    await orch.handle({ txHash: TX, signerUrl: SEAT_PAGE, principal: PRINCIPAL });
    expect(policy.calls.length).toBe(1);
  });

  it('a transaction the chain has no record of is still not judged (nothing to read)', async () => {
    const { orch, policy } = rig(new MockPolicyClient({ decision: 'deny' }));
    const r = await orch.handle({ txHash: TX2, signerUrl: SEAT_PAGE });
    expect(r.status).toBe('expired');
    expect(policy.calls.length).toBe(0);
  });
});

describe('DAX-F213: discovery from the book\'s signature-request history, from a persisted cursor', () => {
  const tick = (p: Poller) => (p as unknown as { tick(): Promise<void> }).tick();
  const poller = (r: ReturnType<typeof rig>) => new Poller(r.acc, r.orch, SEAT_PAGE, 1000, silent, Date.now, undefined, SEAT_BOOK, undefined,
    { cursors: r.store, revisit: openRequestsOf(r.store) });

  it('first sighting of a book starts at its head (history is not judged), then judges a request that arrives already final', async () => {
    const r = rig(new MockPolicyClient({ decision: 'deny', reason: MISMATCH }));
    rejectedByPayer(r.acc, TX2);
    r.acc.sigChain.set(SEAT_BOOK, [{ txHash: TX2, principal: PRINCIPAL }]); // history before this signer first ran
    const p = poller(r);
    await tick(p);
    expect(r.policy.calls.length).toBe(0);
    expect(await r.store.getCursor(`signature-requests:${SEAT_BOOK}`)).toBe(1);

    // the D-05 shape: the request is recorded on our book, and the payer's book rejected the transaction before we polled
    rejectedByPayer(r.acc, TX);
    r.acc.sigChain.get(SEAT_BOOK)!.push({ txHash: TX, principal: PRINCIPAL });
    await tick(p);
    expect(r.policy.calls.length).toBe(1);
    expect((await r.store.get(TX))?.status).toBe('final');
    expect(await r.store.getReceipt(TX)).toMatchObject({ decision: 'deny', reason: MISMATCH, voteNotSubmitted: { finalBy: [PAYER_BOOK] } });
    expect(await r.store.getCursor(`signature-requests:${SEAT_BOOK}`)).toBe(2);
    expect(r.acc.submissions.length).toBe(0);

    await tick(p);
    expect(r.policy.calls.length).toBe(1);
  });

  it('a request whose transaction cannot be read yet is revisited from the store until it is judged', async () => {
    const r = rig(new MockPolicyClient({ decision: 'deny', reason: MISMATCH }));
    const p = poller(r);
    await tick(p); // cursor at head (0)
    rejectedByPayer(r.acc, TX);
    r.acc.sigChain.set(SEAT_BOOK, [{ txHash: TX, principal: PRINCIPAL }]);
    r.acc.unavailable = true;
    await tick(p);
    expect((await r.store.get(TX))?.status).not.toBe('final');
    r.acc.unavailable = false;
    await tick(p);
    expect((await r.store.get(TX))?.status).toBe('final');
    expect(r.policy.calls.length).toBe(1);
  });

  it('the cursor survives a restart (FileStore)', async () => {
    const { mkdtempSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { FileStore } = await import('../src/store/store.js');
    const dir = mkdtempSync(join(tmpdir(), 'f213-'));
    try {
      const a = new FileStore(join(dir, 's.json'));
      await a.setCursor('signature-requests:acc://x.acme/book', 7);
      expect(await new FileStore(join(dir, 's.json')).getCursor('signature-requests:acc://x.acme/book')).toBe(7);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('DAX-F213: RawAccumulateClient.listSignatureRequests reads the book\'s signature chain forward', () => {
  const entry = (index: number, type: string, txID?: string) => ({ recordType: 'chainEntry', name: 'signature', index, value: { recordType: 'message', message: { type, ...(txID ? { txID, authority: SEAT_BOOK } : {}) } } });

  it('with no cursor answers only the head; with a cursor returns each signatureRequest with its index, hash and principal', async () => {
    const c = new RawAccumulateClient('http://127.0.0.1:1', silent);
    const calls: unknown[] = [];
    (c as unknown as { query: (s: string, q: unknown) => Promise<unknown> }).query = async (_s, q) => {
      calls.push(q);
      const range = (q as { range: { start?: number; count: number; fromEnd?: boolean } }).range;
      if (range.fromEnd) return { recordType: 'range', total: 5, records: [entry(4, 'signature')] };
      const all = [entry(3, 'signatureRequest', `acc://${TX}@harbor-mfg.acme/data`), entry(4, 'signature')];
      return { recordType: 'range', start: range.start, total: 5, records: all.filter((e) => e.index >= (range.start ?? 0)) };
    };
    expect(await c.listSignatureRequests(SEAT_BOOK)).toEqual({ next: 5, requests: [] });
    expect(await c.listSignatureRequests(SEAT_BOOK, 3)).toEqual({ next: 5, requests: [{ index: 3, txHash: TX, principal: 'acc://harbor-mfg.acme/data' }] });
    expect((calls[1] as { name: string }).name).toBe('signature');
  });

  it('throws when the chain cannot be read, so the cursor is not advanced over unread entries', async () => {
    const c = new RawAccumulateClient('http://127.0.0.1:1', silent);
    (c as unknown as { query: () => Promise<unknown> }).query = async () => { throw new Error('ECONNREFUSED'); };
    await expect(c.listSignatureRequests(SEAT_BOOK, 0)).rejects.toThrow(/ECONNREFUSED/);
  });
});
