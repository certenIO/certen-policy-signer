/**
 * SP-10: a submit that gets no answer is decided from the chain -- never treated as a refusal.
 *
 * In the SP-10 run a submit timed out after 15 s while the officer's signature landed and the payment was
 * delivered; the record said "refused". These tests pin the rule on every path that submits a signature:
 * the raw client reports "no answer" as `uncertain` (not as a refusal), the machine vote and governance
 * read the chain for their own signature and act on what is there, and the timeout is configurable.
 * (Officer intake is covered in test/phase7-officer-intake.test.ts.) All names FICTIONAL.
 */
import { describe, it, expect, vi } from 'vitest';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { awaitOwnSignature } from '../src/accumulate/submit-outcome.js';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { MockAccumulateClient, type SubmitResult, type TxSignatures } from '../src/accumulate/client.js';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { applyKeyPageOp } from '../src/ops/keypage.js';
import { SubmitOutcomeUnknownError, signAndSubmit } from '../src/ops/rotate.js';
import { loadConfig } from '../src/config.js';

const silent = pino({ level: 'silent' });
const TX = '3c'.repeat(32);
const PAGE = 'acc://fictional-risk-tcl1.acme/book/1';
const SIGNER = new LocalSigner(new Uint8Array(32).fill(8));
const keyHashOf = async (s: LocalSigner) => createHash('sha256').update(await s.publicKey()).digest('hex');
const sigs = (list: Array<{ publicKeyHash: string; delegators?: string[] }>): TxSignatures =>
  ({ status: 'pending', delivered: false, signatures: list.map((s) => ({ type: 'ed25519', publicKeyHash: s.publicKeyHash, delegators: s.delegators ?? [], hops: [...(s.delegators ?? [])].reverse() })) });
const UNREADABLE: TxSignatures = { status: '', delivered: false, signatures: [], unavailable: 'FICTIONAL node down' };

describe('awaitOwnSignature', () => {
  const base = { txHash: TX, principal: PAGE, keyHash: 'aa'.repeat(32), delegators: [] as string[], vote: 'approve' as const, timeoutMs: 40, pollMs: 10 };
  it('landed / absent / unknown', async () => {
    expect(await awaitOwnSignature({ ...base, getTxSignatures: async () => sigs([{ publicKeyHash: 'aa'.repeat(32) }]) })).toBe('landed');
    expect(await awaitOwnSignature({ ...base, getTxSignatures: async () => sigs([{ publicKeyHash: 'bb'.repeat(32) }]) })).toBe('absent');
    expect(await awaitOwnSignature({ ...base, getTxSignatures: async () => UNREADABLE })).toBe('unknown');
    expect(await awaitOwnSignature({ ...base, getTxSignatures: async () => { throw new Error('ECONNRESET'); } })).toBe('unknown');
    expect(await awaitOwnSignature({ ...base })).toBe('unknown');
  });
  it('matches the delegator set, and finds a signature that appears on a later poll', async () => {
    let n = 0;
    const get = async () => sigs(++n < 3 ? [] : [{ publicKeyHash: 'aa'.repeat(32), delegators: ['acc://B.acme/book/1', 'acc://a.acme/book/1'] }]);
    expect(await awaitOwnSignature({ ...base, timeoutMs: 1000, delegators: ['acc://a.acme/book/1', 'acc://b.acme/book/1'], getTxSignatures: get })).toBe('landed');
    expect(await awaitOwnSignature({ ...base, delegators: ['acc://c.acme/book/1'], getTxSignatures: async () => sigs([{ publicKeyHash: 'aa'.repeat(32) }]) })).toBe('absent');
  });
  it('matches the vote: an earlier REJECT by the same key is not this APPROVE (security review 2026-10-02)', async () => {
    const withVote = (vote?: 'approve' | 'reject'): TxSignatures =>
      ({ status: 'pending', delivered: false, signatures: [{ type: 'ed25519', publicKeyHash: 'aa'.repeat(32), delegators: [], hops: [], ...(vote ? { vote } : {}) }] });
    expect(await awaitOwnSignature({ ...base, getTxSignatures: async () => withVote('reject') })).toBe('absent');
    expect(await awaitOwnSignature({ ...base, vote: 'reject', getTxSignatures: async () => withVote('reject') })).toBe('landed');
    // The chain omits an accept vote: an absent vote is an approve.
    expect(await awaitOwnSignature({ ...base, getTxSignatures: async () => withVote() })).toBe('landed');
    expect(await awaitOwnSignature({ ...base, vote: 'reject', getTxSignatures: async () => withVote() })).toBe('absent');
  });
  it('a clock that never advances cannot make it loop forever', async () => {
    const get = vi.fn(async () => sigs([]));
    expect(await awaitOwnSignature({ ...base, timeoutMs: 30, pollMs: 10, now: () => 0, getTxSignatures: get })).toBe('absent');
    expect(get.mock.calls.length).toBeLessThanOrEqual(4);
  });
});

describe('RawAccumulateClient.submit: no answer is "uncertain", an answer is a refusal', () => {
  function server(handler: (res: http.ServerResponse) => void) {
    const srv = http.createServer((req, res) => { req.resume(); req.on('end', () => handler(res)); });
    return new Promise<{ url: string; close: () => void }>((r) => srv.listen(0, '127.0.0.1', () =>
      r({ url: `http://127.0.0.1:${(srv.address() as { port: number }).port}/v3`, close: () => { srv.closeAllConnections?.(); srv.close(); } })));
  }
  it('a timeout (wallet.submit_timeout_ms) is uncertain, not a refusal', async () => {
    const s = await server(() => { /* never answers */ });
    try {
      const c = new RawAccumulateClient(s.url, silent, 5_000, { submitTimeoutMs: 50 });
      const r = await c.submit({});
      expect(r).toMatchObject({ ok: false, uncertain: true });
      expect(r.error).toMatch(/timeout/i);
    } finally { s.close(); }
  });
  it('a JSON-RPC error is the node answering: a refusal, not uncertain', async () => {
    const s = await server((res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -1, message: 'invalid signature' } })); });
    try {
      const r = await new RawAccumulateClient(s.url, silent).submit({});
      expect(r.ok).toBe(false);
      expect(r.uncertain).toBeUndefined();
    } finally { s.close(); }
  });
});

describe('the machine vote: a submit with no answer is decided from the chain', () => {
  const tx = { txHash: TX, signerUrl: PAGE, signerVersion: 1, rawTransaction: {}, lastUsedOn: 0, account: 'acc://fictional-payer-tcl1.acme/tokens' };
  function backend(onChain: () => TxSignatures, result: SubmitResult = { ok: false, uncertain: true, error: 'timeout of 15000ms exceeded' }) {
    const acc = new MockAccumulateClient();
    acc.submitQueue = [result];
    (acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => onChain();
    return { acc, b: new DirectVoteBackend(acc, singleKeyring(SIGNER, PAGE), silent, { submitOutcomeTimeoutMs: 40, submitOutcomePollMs: 10 }) };
  }
  it('landed -> the vote counts as cast', async () => {
    const kh = await keyHashOf(SIGNER);
    const onChain = (vote?: 'reject'): TxSignatures => ({ status: 'pending', delivered: false, signatures: [{ type: 'ed25519', publicKeyHash: kh, delegators: [], hops: [], ...(vote ? { vote } : {}) }] });
    const { b } = backend(() => onChain('reject'));
    const r = await b.cast(tx, 'reject');
    expect(r.ok).toBe(true);
    expect(r.signedBy?.publicKeyHash).toBe(kh);
    // Our key's earlier APPROVE on chain is not this REJECT landing: not cast, retried.
    const { b: b2 } = backend(() => onChain());
    expect(await b2.cast(tx, 'reject')).toMatchObject({ ok: false, error: expect.stringMatching(/not on chain/) });
  });
  it('absent -> a failure to retry, never a refusal', async () => {
    const { b } = backend(() => sigs([]));
    expect(await b.cast(tx, 'approve')).toMatchObject({ ok: false, error: expect.stringMatching(/not on chain/) });
  });
  it('unreadable -> outcome unknown', async () => {
    const { b } = backend(() => UNREADABLE);
    expect(await b.cast(tx, 'approve')).toMatchObject({ ok: false, error: expect.stringMatching(/outcome unknown/) });
  });
  it('a node refusal is unchanged (no chain read)', async () => {
    const read = vi.fn(() => sigs([]));
    const { b } = backend(read, { ok: false, code: 'error', error: 'invalid signature' });
    expect(await b.cast(tx, 'approve')).toMatchObject({ ok: false, error: 'invalid signature' });
    expect(read).not.toHaveBeenCalled();
  });
  it('through the orchestrator: an unknown outcome is a retryable error, not a rejection; landed is signed', async () => {
    const make = (onChain: () => TxSignatures) => {
      const acc = new MockAccumulateClient();
      acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://fictional-payee-tcl1.acme/tokens', amount: '1' }] }, principal: tx.account });
      acc.submitQueue = [{ ok: false, uncertain: true, error: 'timeout of 15000ms exceeded' }];
      (acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => onChain();
      return new Orchestrator({
        accumulate: acc, keyring: singleKeyring(SIGNER, PAGE), policy: new MockPolicyClient({ decision: 'approve' }), store: new MemoryStore(),
        resolver: new Resolver(acc), logger: silent, options: { submitOutcomeTimeoutMs: 40 },
      });
    };
    expect(await make(() => UNREADABLE).handle({ txHash: TX, signerUrl: PAGE })).toMatchObject({ status: 'error', lastError: expect.stringMatching(/outcome unknown/) });
    const kh = await keyHashOf(SIGNER);
    expect((await make(() => sigs([{ publicKeyHash: kh }])).handle({ txHash: TX, signerUrl: PAGE })).status).toBe('signed');
  });
});

describe('governance: a submit with no answer is decided from the chain', () => {
  const OUR = 'acc://fictional-org-tcl1.acme/book/1';
  function acc(onChain: () => TxSignatures) {
    return {
      query: async () => ({ account: { version: 3, acceptThreshold: 2, keys: [{ publicKeyHash: 'a1'.repeat(32) }, { publicKeyHash: 'b1'.repeat(32) }, { publicKeyHash: 'c1'.repeat(32) }] } }),
      getSignerInfo: async () => ({ version: 3, lastUsedOn: 0, creditBalance: 100 }),
      submit: async (): Promise<SubmitResult> => ({ ok: false, uncertain: true, error: 'timeout of 15000ms exceeded' }),
      getTxSignatures: async () => onChain(),
    } as any;
  }
  it('landed -> submitted (the hash is returned)', async () => {
    const kh = await keyHashOf(SIGNER);
    const h = await signAndSubmit({ accumulate: acc(() => sigs([{ publicKeyHash: kh }])), signer: SIGNER, logger: silent, submitOutcomeTimeoutMs: 40, submitOutcomePollMs: 10 }, OUR, { type: 'updateKeyPage', operation: [{ type: 'setThreshold', threshold: 2 }] }, 'updateKeyPage/setThreshold');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
  it('unreadable -> outcome unknown (never "rejected by the network"); the hash stays with what was submitted', async () => {
    await expect(signAndSubmit({ accumulate: acc(() => UNREADABLE), signer: SIGNER, logger: silent, submitOutcomeTimeoutMs: 40, submitOutcomePollMs: 10 }, OUR, { type: 'updateKeyPage', operation: [] }, 'x'))
      .rejects.toBeInstanceOf(SubmitOutcomeUnknownError);
    const r = await applyKeyPageOp({ accumulate: acc(() => UNREADABLE), signer: SIGNER, logger: silent, page: OUR, submitOutcomeTimeoutMs: 40 }, { op: 'set-threshold', threshold: 3 }, 50);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/outcome UNKNOWN, not refused/);
    expect(r.error).not.toMatch(/rejected by the network/);
    expect(r.submitted).toHaveLength(1);
  });
});

describe('config: submit timeouts', () => {
  it('defaults to the raw client’s 15 s submit timeout and a 30 s outcome read; both configurable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sp10-'));
    const write = (extra: string) => {
      const p = join(dir, `c${Math.random().toString(36).slice(2)}.yaml`);
      writeFileSync(p, `wallet:\n  org_id: "x"\n  accumulate_endpoints: ["http://127.0.0.1:1/v3"]\n  signer_url: "acc://fictional-risk-tcl1.acme/book/1"\n${extra}signer: { provider: "local", local: { allow_ephemeral: true } }\npolicy: { url: "http://127.0.0.1:9/decide" }\n`);
      return loadConfig(p);
    };
    expect(write('').wallet).toMatchObject({ submit_timeout_ms: 15_000, submit_outcome_timeout_ms: 30_000 });
    expect(write('  submit_timeout_ms: 45000\n  submit_outcome_timeout_ms: 60000\n').wallet).toMatchObject({ submit_timeout_ms: 45_000, submit_outcome_timeout_ms: 60_000 });
  });
});
