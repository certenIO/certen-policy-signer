import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient, PolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator, OrchestratorOptions } from '../src/orchestrator.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);            // 64 hex chars
const SIGNER = 'acc://demo-org.acme/book/1';

function setup() {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, {
    body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] },
    principal: 'acc://alice.acme/tokens',
  });
  const signer = new LocalSigner(new Uint8Array(32).fill(9));
  const store = new MemoryStore();
  const resolver = new Resolver(acc);
  return { acc, signer, store, resolver };
}

function orch(d: ReturnType<typeof setup>, policy: PolicyClient, options?: OrchestratorOptions) {
  return new Orchestrator({
    accumulate: d.acc, keyring: singleKeyring(d.signer), policy, store: d.store, resolver: d.resolver,
    logger: silent, options,
  });
}

describe('orchestrator pipeline', () => {
  it('approve → signed, exactly one submission, well-formed envelope', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }));
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });

    expect(r.status).toBe('signed');
    expect(d.acc.submissions.length).toBe(1);
    const env = d.acc.submissions[0] as any;
    expect(env.transaction).toHaveLength(1);
    expect(env.signatures[0].signature).toHaveLength(128);
    expect(env.signatures[0].publicKey).toHaveLength(64);
    expect(env.signatures[0].signer).toBe(SIGNER);
    expect(env.signatures[0].vote).toBeUndefined(); // approve omits vote
    const receipt = await d.store.getReceipt(TX);
    expect(receipt?.vote).toBe('approve');
  });

  it('deny → rejected, no submission', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'deny', reason: 'risk' }));
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect(d.acc.submissions.length).toBe(0);
  });

  it('deny with submitRejectVote → a reject vote is submitted', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'deny' }), { submitRejectVote: true });
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect(d.acc.submissions.length).toBe(1);
    expect((d.acc.submissions[0] as any).signatures[0].vote).toBe('reject'); // wire form: lowercase enum
  });

  it('badSignerVersion → re-resolves version, resubmits, signs', async () => {
    const d = setup();
    d.acc.submitQueue = [{ ok: false, code: 'badSignerVersion' }]; // first fails, then default ok
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }));
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('signed');
    expect(d.acc.submissions.length).toBe(2);
  });

  it('double trigger → single signature (idempotent)', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }));
    await o.handle({ txHash: TX, signerUrl: SIGNER });
    const r2 = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r2.status).toBe('signed');
    expect(d.acc.submissions.length).toBe(1);
  });

  it('concurrent triggers → single signature (single-flight)', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }));
    const results = await Promise.all([
      o.handle({ txHash: TX, signerUrl: SIGNER }),
      o.handle({ txHash: TX, signerUrl: SIGNER }),
      o.handle({ txHash: TX, signerUrl: SIGNER }),
    ]);
    expect(results.some((r) => r.status === 'signed')).toBe(true);
    expect(d.acc.submissions.length).toBe(1);
  });

  it('tx already executed → marked signed, no submission', async () => {
    const d = setup();
    d.acc.pending.get(TX)!.executed = true;
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }));
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('signed');
    expect(d.acc.submissions.length).toBe(0);
  });

  it('unknown/expired tx → expired, no submission', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }));
    const r = await o.handle({ txHash: 'cd'.repeat(32), signerUrl: SIGNER });
    expect(r.status).toBe('expired');
    expect(d.acc.submissions.length).toBe(0);
  });

  it('chain reports the tx expired → marked expired before policy is even consulted', async () => {
    // Edge case 5: the wallet's expiry HANDLING. (Live-minting an expiring tx is blocked by
    // accumulate.js 0.12 encoding expire.atTime as an unsigned varint vs core's signed varint.)
    const d = setup();
    d.acc.pending.get(TX)!.expired = true;
    const policy = new MockPolicyClient({ decision: 'approve' });
    const r = await orch(d, policy).handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('expired');
    expect(d.acc.submissions.length).toBe(0);
    expect(policy.calls.length).toBe(0); // gone before we ask the engine
  });

  it('policy engine error → stays awaiting_policy (retryable), no submission', async () => {
    const d = setup();
    const failing: PolicyClient = { decide: async () => { throw new Error('policy down'); } };
    const o = orch(d, failing);
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('awaiting_policy');
    expect(r.lastError).toContain('policy');
    expect(d.acc.submissions.length).toBe(0);
  });

  it('local guard blocks an approved tx (defense-in-depth)', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve' }), { guard: () => false });
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect(d.acc.submissions.length).toBe(0);
  });

  it('policy request carries a human-readable summary', async () => {
    const d = setup();
    const policy = new MockPolicyClient({ decision: 'deny' });
    const o = orch(d, policy);
    await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(policy.calls[0].actionSummary).toContain('Transfer 5000');
    expect(policy.calls[0].account).toBe('acc://alice.acme/tokens');
  });
});
