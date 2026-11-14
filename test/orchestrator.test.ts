import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient, PolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator, OrchestratorOptions, signatureEvidence } from '../src/orchestrator.js';
import nacl from 'tweetnacl';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildPreimage } from '../src/accumulate/signing.js';
import { GatewayVoteBackend } from '../src/vote/adapters/certen-gateway.js';
import { loadConfig } from '../src/config.js';

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

/**
 * Evidence in the signature, end to end through the pipeline. Wrapper runbook, change 4.
 *
 * The policy engine puts the digest in `evidence.signatureData` (the free-form part of the frozen
 * contract, invariant F-9). The signer reads it strictly and puts it in the key signature's `data`.
 */
describe('signature data from the decision', () => {
  const DIGEST = 'a1'.repeat(32);
  const env = (d: ReturnType<typeof setup>) => d.acc.submissions[0] as any;

  /** Re-derive the preimage from what was submitted and check the signature against it, as the network would. */
  async function verifiesAsSubmitted(sig: any, d: ReturnType<typeof setup>): Promise<boolean> {
    const pk = await d.signer.publicKey();
    const pre = buildPreimage(Buffer.from(TX, 'hex'), {
      publicKey: pk, signerUrl: sig.signer, signerVersion: sig.signerVersion, timestamp: sig.timestamp,
      vote: sig.vote === 'reject' ? 'reject' : 'approve',
      ...(sig.memo ? { memo: sig.memo } : {}),
      ...(sig.data ? { data: new Uint8Array(Buffer.from(sig.data, 'hex')) } : {}),
    });
    return nacl.sign.detached.verify(pre.dataForSignature, Buffer.from(sig.signature, 'hex'), pk);
  }

  it('puts a valid signatureData and signatureMemo into the signature it submits', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve', evidence: { signatureData: DIGEST, signatureMemo: 'live check 42' } }));
    expect((await o.handle({ txHash: TX, signerUrl: SIGNER })).status).toBe('signed');
    const sig = env(d).signatures[0];
    expect(sig.data).toBe(DIGEST);
    expect(sig.memo).toBe('live check 42');
    expect(await verifiesAsSubmitted(sig, d)).toBe(true);
  });

  it('a reject vote carries the evidence too, when one is cast', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'deny', evidence: { signatureData: DIGEST } }), { submitRejectVote: true });
    await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(env(d).signatures[0].vote).toBe('reject');
    expect(env(d).signatures[0].data).toBe(DIGEST);
    expect(await verifiesAsSubmitted(env(d).signatures[0], d)).toBe(true);
  });

  const malformed: Array<[string, unknown]> = [
    ['31 bytes', 'a1'.repeat(31)],
    ['33 bytes', 'a1'.repeat(33)],
    ['not hex', 'zz'.repeat(32)],
    ['a number', 12345],
    ['an array', [1, 2, 3]],
    ['base64 of 32 bytes', Buffer.alloc(32, 1).toString('base64')],
  ];
  for (const [label, bad] of malformed) {
    it(`a malformed signatureData (${label}) is ignored: the signature is built exactly as before`, async () => {
      const d = setup();
      const o = orch(d, new MockPolicyClient({ decision: 'approve', evidence: { signatureData: bad } }));
      expect((await o.handle({ txHash: TX, signerUrl: SIGNER })).status).toBe('signed');
      expect(env(d).signatures[0].data).toBeUndefined();
    });

    it(`a malformed signatureData (${label}) refuses to sign when require_signature_data is on`, async () => {
      const d = setup();
      const o = orch(d, new MockPolicyClient({ decision: 'approve', evidence: { signatureData: bad } }), { requireSignatureData: true });
      const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
      expect(r.status).toBe('rejected');
      expect(r.lastError).toBe('signature_data_missing');
      expect(d.acc.submissions).toHaveLength(0);
    });
  }

  it('require_signature_data: an approval with no evidence at all is refused, with a receipt naming why', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve', reason: 'ok' }), { requireSignatureData: true });
    const r = await o.handle({ txHash: TX, signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect(r.lastError).toBe('signature_data_missing');
    expect(d.acc.submissions).toHaveLength(0);
    const receipt = await d.store.getReceipt(TX);
    expect(receipt?.decision).toBe('approve');
    expect(receipt?.vote).toBeUndefined();
    expect((receipt?.policyEvidence as any)?.blockedBy).toBe('signature_data_missing');
  });

  it('require_signature_data: a valid digest is signed', async () => {
    const d = setup();
    const o = orch(d, new MockPolicyClient({ decision: 'approve', evidence: { signatureData: '0x' + DIGEST } }), { requireSignatureData: true });
    expect((await o.handle({ txHash: TX, signerUrl: SIGNER })).status).toBe('signed');
    expect(env(d).signatures[0].data).toBe(DIGEST);
  });

  it('a memo over 256 characters, or empty, is ignored', () => {
    expect(signatureEvidence({ signatureMemo: 'x'.repeat(257) }).memo).toBeUndefined();
    expect(signatureEvidence({ signatureMemo: '' }).memo).toBeUndefined();
    expect(signatureEvidence({ signatureMemo: 7 }).memo).toBeUndefined();
    expect(signatureEvidence({ signatureMemo: 'x'.repeat(256) }).memo).toHaveLength(256);
    expect(signatureEvidence(undefined)).toEqual({});
  });

  it('the gateway backend refuses to sign when the decision supplied data it cannot carry', async () => {
    let asked = 0;
    const gw = { requestSigningData: async () => { asked++; throw new Error('must not be called'); }, submitSignature: async () => ({ ok: true }) };
    const d = setup();
    const b = new GatewayVoteBackend(gw as any, singleKeyring(d.signer), silent);
    const tx = { txHash: TX, signerUrl: SIGNER, signerVersion: 1, rawTransaction: {}, lastUsedOn: 0, account: 'acc://alice.acme/tokens' };
    const res = await b.cast(tx, 'approve', { data: new Uint8Array(32) });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/cannot carry/);
    expect(asked).toBe(0);
  });

  it('config refuses require_signature_data together with the gateway', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'certen-sigdata-'));
    let n = 0;
    try {
      const write = (extra: string[]) => {
        const p = join(tmp, `c-${n++}.yaml`);
        writeFileSync(p, [
          'wallet: { org_id: "o", accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"], signer_url: "acc://o.acme/book/1" }',
          `signer: { provider: "local", local: { seed_hex: "${'a'.repeat(64)}" } }`,
          'policy: { url: "http://127.0.0.1:9099/decision" }',
          ...extra,
        ].join('\n'));
        return p;
      };
      const gateway = 'gateway: { enabled: true, url: "http://127.0.0.1:8090", api_key: "ck_live_x", identity: "acc://o.acme" }';
      expect(() => loadConfig(write(['behavior: { require_signature_data: true }', gateway]))).toThrow(/require_signature_data/);
      expect(loadConfig(write(['behavior: { require_signature_data: true }'])).behavior.require_signature_data).toBe(true);
      expect(loadConfig(write([])).behavior.require_signature_data).toBe(false);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
