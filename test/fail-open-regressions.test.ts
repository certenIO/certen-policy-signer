/**
 * Regressions for three fail-open defects found in an audit of the published tree.
 *
 * All three share a shape: the signer took an action, or declined to take one, and RECORDED something
 * stronger than what actually happened. That is the failure mode this project exists to rule out, so each
 * one gets a test that would have caught it.
 */
import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { isDefinitiveNotFound } from '../src/accumulate/raw-client.js';
import { loadConfig } from '../src/config.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const SIGNER = 'acc://demo-org.acme/book/1';

function denyPipeline(submitFails: boolean) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, {
    body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] },
    principal: 'acc://alice.acme/tokens',
  });
  if (submitFails) {
    // Permanently: not a badSignerVersion race, a condition retrying inside the backend cannot clear.
    acc.submitQueue = Array.from({ length: 6 }, () => ({ ok: false, code: 'insufficientCredits', error: 'no credits' }));
  }
  const store = new MemoryStore();
  const orch = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9))),
    policy: new MockPolicyClient({ decision: 'deny', reason: 'risk' }),
    store, resolver: new Resolver(acc), logger: silent,
    options: { submitRejectVote: true },
  });
  return { acc, store, orch };
}

describe('a reject vote that cannot be submitted is a failure, not a rejection', () => {
  it('does not claim the tx was rejected, and stays retryable', async () => {
    const { store, orch } = denyPipeline(true);
    const r = await orch.handle({ txHash: TX, signerUrl: SIGNER });

    // 'rejected' is terminal — recording it here would strand the tx forever.
    expect(r.status).toBe('error');
    expect(r.lastError).toBeTruthy();

    // No receipt: claiming `vote: reject` for a vote that never reached the chain is a false audit record.
    expect(await store.getReceipt(TX)).toBeUndefined();
  });

  it('retries on the next trigger rather than skipping as terminal', async () => {
    const { acc, orch } = denyPipeline(true);
    await orch.handle({ txHash: TX, signerUrl: SIGNER });
    const before = acc.submissions.length;
    await orch.handle({ txHash: TX, signerUrl: SIGNER });
    expect(acc.submissions.length).toBeGreaterThan(before);
  });

  it('still records the rejection normally when the vote DOES land', async () => {
    const { store, orch } = denyPipeline(false);
    const r = await orch.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect((await store.getReceipt(TX))?.vote).toBe('reject');
  });
});

describe('an unreachable node is not evidence that a transaction is gone', () => {
  const pipeline = () => {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, {
      body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] },
      principal: 'acc://alice.acme/tokens',
    });
    const store = new MemoryStore();
    const policy = new MockPolicyClient({ decision: 'approve' });
    const orch = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9))),
      policy, store, resolver: new Resolver(acc), logger: silent,
    });
    return { acc, store, policy, orch };
  };

  it('does not mark a tx expired because the query failed', async () => {
    const { acc, orch } = pipeline();
    acc.unavailable = true;
    const r = await orch.handle({ txHash: TX, signerUrl: SIGNER });
    // 'expired' is terminal — it would retire a transaction still awaiting our vote.
    expect(r.status).not.toBe('expired');
    expect(r.lastError).toMatch(/resolve/);
  });

  it('signs it on the next poll once the node comes back', async () => {
    const { acc, orch } = pipeline();
    acc.unavailable = true;
    await orch.handle({ txHash: TX, signerUrl: SIGNER });
    acc.unavailable = false;
    const r = await orch.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('signed');
    expect(acc.submissions.length).toBe(1);
  });

  it('a chain that really says "not found" is still terminal', async () => {
    const { orch } = pipeline();
    const r = await orch.handle({ txHash: 'cd'.repeat(32), signerUrl: SIGNER });
    expect(r.status).toBe('expired');
  });

  it('only a definitive answer counts as gone', async () => {
    for (const m of ['record not found', 'account does not exist', 'no such record', 'unknown transaction x']) {
      expect(isDefinitiveNotFound(m)).toBe(true);
    }
    for (const m of ['timeout of 15000ms exceeded', 'connect ECONNREFUSED 127.0.0.1:16695',
                     'Request failed with status code 502', 'socket hang up', '<html>502 Bad Gateway</html>']) {
      expect(isDefinitiveNotFound(m)).toBe(false);
    }
  });
});

describe('policy.auth must not silently downgrade to unauthenticated', () => {
  const dir = mkdtempSync(join(tmpdir(), 'signer-cfg-'));
  const write = (policy: string) => {
    const p = join(dir, `${Math.random().toString(36).slice(2)}.yaml`);
    writeFileSync(p, [
      'wallet: { org_id: "o", accumulate_endpoints: ["http://127.0.0.1:9/v3"], signer_url: "acc://o.acme/book/1" }',
      'signer: { provider: "local", local: { allow_ephemeral: true } }',
      policy,
    ].join('\n'));
    return p;
  };

  it('rejects auth: hmac when the secret is missing', () => {
    expect(() => loadConfig(write('policy: { url: "http://e/d", auth: "hmac" }')))
      .toThrow(/hmac_secret is empty/);
  });

  it('rejects auth: hmac when the env ref does not resolve — the shipped example\'s shape', () => {
    delete process.env.AUDIT_TEST_UNSET_SECRET;
    expect(() => loadConfig(write('policy: { url: "http://e/d", auth: "hmac", hmac_secret: "env:AUDIT_TEST_UNSET_SECRET" }')))
      .toThrow(/hmac_secret is empty/);
  });

  it('rejects auth: mtls, which is not implemented', () => {
    expect(() => loadConfig(write('policy: { url: "http://e/d", auth: "mtls" }')))
      .toThrow(/not implemented/);
  });

  it('accepts hmac with a real secret, and none without one', () => {
    process.env.AUDIT_TEST_SET_SECRET = 's3cret';
    expect(loadConfig(write('policy: { url: "http://e/d", auth: "hmac", hmac_secret: "env:AUDIT_TEST_SET_SECRET" }')).policy.hmac_secret).toBe('s3cret');
    expect(loadConfig(write('policy: { url: "http://e/d" }')).policy.auth).toBe('none');
  });
});
