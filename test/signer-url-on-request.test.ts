/**
 * Which key page is asking. Runbook F Phase F5, task 1.
 *
 * `PolicyRequest` has never carried it, which was verified in the research and is the reason one
 * console endpoint serving a multi-page signer cannot tell a treasury seat's question from a risk
 * seat's. The wallet has always known — `ResolvedTx.signerUrl` is how the poller found the transaction
 * in the first place — and simply never passed it on.
 *
 * ── WHY IT IS THE PAGE AND NOT THE BOOK ───────────────────────────────────────────────────────────
 *
 * A book is the authority; a page is the seat. Runbook F 0.4 gives each ROLE its own book, and the
 * thing that distinguishes one question from another is which of this wallet's pages is being asked —
 * a signer holding a treasury seat and a risk seat holds two pages, and answering "the book" would
 * merge exactly the two questions this field exists to separate.
 *
 * It is also the value the vote is cast against, so a decision and the signature that follows it name
 * the same thing.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import type { PolicyClient } from '../src/policy/policy.js';
import type { PolicyRequest } from '../src/types.js';

const silent = pino({ level: 'silent' });
const TX = 'f5'.repeat(32);
const PAGE = 'acc://bank.acme/roles/treasury/1';

/** A policy engine that records what it was asked, and approves. */
function recordingEngine(): { seen: PolicyRequest[]; client: PolicyClient } {
  const seen: PolicyRequest[] = [];
  return {
    seen,
    client: {
      decide: async (req: PolicyRequest) => {
        seen.push(req);
        return { decision: 'approve' as const, reason: 'recorded' };
      },
    } as unknown as PolicyClient,
  };
}

async function askAbout(page: string): Promise<PolicyRequest> {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] }, principal: 'acc://alice.acme/tokens' });
  const engine = recordingEngine();
  const orchestrator = new Orchestrator({
    accumulate: acc,
    keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(3)), page),
    policy: engine.client,
    store: new MemoryStore(),
    resolver: new Resolver(acc),
    logger: silent,
  });
  await orchestrator.handle({ txHash: TX, signerUrl: page });
  const req = engine.seen[0];
  if (!req) throw new Error('the policy engine was never asked');
  return req;
}

describe('the decision request says which page is asking', () => {
  it('carries the signer page the transaction was discovered for', async () => {
    const req = await askAbout(PAGE);
    expect(req.signerUrl).toBe(PAGE);
  });

  /**
   * The point of the field. Two seats on one wallet ask two questions about the same transaction, and
   * an engine that cannot tell them apart is answering one of them twice.
   */
  it('distinguishes two seats asking about the same transaction', async () => {
    const treasury = await askAbout('acc://bank.acme/roles/treasury/1');
    const risk = await askAbout('acc://bank.acme/roles/risk/1');
    expect(treasury.txHash).toBe(risk.txHash);
    expect(treasury.signerUrl).not.toBe(risk.signerUrl);
  });

  it('leaves every other field exactly as it was', async () => {
    const req = await askAbout(PAGE);
    expect(req.txHash).toBe(TX);
    expect(req.account).toBe('acc://alice.acme/tokens');
    expect(req.actionSummary).toBeTruthy();
    expect(req.expiresAt).toBeTruthy();
  });
});
