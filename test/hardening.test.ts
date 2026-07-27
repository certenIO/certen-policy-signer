/**
 * Regression tests for the fail-closed behaviours. Each of these guards a hole that was live in the
 * deployable build: an open admin API, an SR6 check that passed by not looking, receipts that died with
 * the process, a value ceiling a multi-leg intent could walk straight past, and a poller that reported
 * healthy while it had never once succeeded.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AddressInfo } from 'node:net';
import http from 'node:http';
import { createServer, PauseController } from '../src/server.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Resolver } from '../src/resolver.js';
import { FileStore, MemoryStore } from '../src/store/store.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { Poller } from '../src/poller.js';
import { makeValueCeilingGuard } from '../src/guard.js';
import { loadConfig } from '../src/config.js';
import { logger } from '../src/logger.js';
import { SigningRequest } from '../src/types.js';

const silent = logger.child({ level: 'silent' });
let tmp: string;
beforeEach(() => { tmp = mkdtempSync(join(tmpdir(), 'certen-hard-')); });
afterEach(() => rmSync(tmp, { recursive: true, force: true }));

function startServer(opts: { adminApiKey?: string; poller?: { healthy(): boolean; lastSuccess(): number }; metricsPublic?: boolean }) {
  const acc = new MockAccumulateClient();
  const store = new MemoryStore();
  const signer = new LocalSigner(new Uint8Array(32).fill(9));
  const pause: PauseController = { paused: false };
  const keyring = singleKeyring(signer);
  const orchestrator = new Orchestrator({
    accumulate: acc, keyring, policy: new MockPolicyClient({ decision: 'approve' }),
    store, resolver: new Resolver(acc), logger: silent,
  });
  const server = createServer({
    orchestrator, store, keyring, accumulate: acc, pause, logger: silent,
    adminApiKey: opts.adminApiKey, poller: opts.poller, metricsPublic: opts.metricsPublic,
  });
  return new Promise<{ server: http.Server; url: string; pause: PauseController }>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, url: `http://127.0.0.1:${port}`, pause });
    });
  });
}

describe('admin API is never open', () => {
  it('refuses admin routes with 403 when no api_key is configured (was: wide open)', async () => {
    const { server, url, pause } = await startServer({});
    const res = await fetch(`${url}/v1/admin/pause`, { method: 'POST' });
    expect(res.status).toBe(403);
    expect(pause.paused).toBe(false);          // the critical part: an anonymous caller could NOT pause signing
    const pk = await fetch(`${url}/v1/admin/pubkey`);
    expect(pk.status).toBe(403);               // nor learn which key we sign with
    server.close();
  });

  it('rejects a wrong api_key and accepts the right one', async () => {
    const { server, url, pause } = await startServer({ adminApiKey: 'correct-horse' });
    expect((await fetch(`${url}/v1/admin/pause`, { method: 'POST', headers: { 'x-api-key': 'wrong' } })).status).toBe(401);
    expect(pause.paused).toBe(false);
    const ok = await fetch(`${url}/v1/admin/pause`, { method: 'POST', headers: { 'x-api-key': 'correct-horse' } });
    expect(ok.status).toBe(200);
    expect(pause.paused).toBe(true);
    server.close();
  });

  it('leaves /healthz public — orchestrators must be able to probe it', async () => {
    const { server, url } = await startServer({});
    expect((await fetch(`${url}/healthz`)).status).toBe(200);
    server.close();
  });
});

describe('/metrics does not leak the org\'s decision counts', () => {
  it('requires the admin key by default', async () => {
    const { server, url } = await startServer({ adminApiKey: 'k' });
    expect((await fetch(`${url}/metrics`)).status).toBe(401);
    expect((await fetch(`${url}/metrics`, { headers: { 'x-api-key': 'k' } })).status).toBe(200);
    server.close();
  });

  it('is disabled (403), not open, when no admin key is configured', async () => {
    const { server, url } = await startServer({});
    expect((await fetch(`${url}/metrics`)).status).toBe(403);
    server.close();
  });

  it('is public only when the operator explicitly declares the port private', async () => {
    const { server, url } = await startServer({ metricsPublic: true });
    expect((await fetch(`${url}/metrics`)).status).toBe(200);
    server.close();
  });
});

describe('/healthz reflects the discovery loop', () => {
  it('reports 503 when the poller is stalled — a wallet that sees no work is not healthy', async () => {
    const stalled = { healthy: () => false, lastSuccess: () => 0 };
    const { server, url } = await startServer({ poller: stalled });
    const res = await fetch(`${url}/healthz`);
    expect(res.status).toBe(503);
    expect((await res.json() as any).reasons).toContain('poller_stalled');
    server.close();
  });

  it('a poller that has NEVER succeeded goes unhealthy after the grace period (was: healthy forever)', () => {
    let clock = 10_000;
    const acc = new MockAccumulateClient();
    const orch = { handle: async () => ({}) } as unknown as Orchestrator;
    const p = new Poller(acc, orch, 'acc://o.acme/book/1', 1000, silent, () => clock);
    expect(p.healthy()).toBe(true);   // inside the boot grace period
    clock += 5000;                    // 5x the interval, still never a successful poll
    expect(p.healthy()).toBe(false);
  });
});

describe('durable store', () => {
  const row = (txHash: string): SigningRequest => ({
    txHash, signerUrl: 'acc://o.acme/book/1', status: 'signed', attempts: 1,
    createdAt: 1, updatedAt: 1,
  });

  it('survives a restart: history and receipts are still there (was: lost with the process)', async () => {
    const path = join(tmp, 'state.json');
    const a = new FileStore(path);
    await a.create(row('aa'.repeat(32)));
    await a.saveReceipt({ txHash: 'aa'.repeat(32), decision: 'approve', vote: 'approve', policyEvidence: { rule: 'even' } });

    const restarted = new FileStore(path);    // fresh process, same volume
    const got = await restarted.get('aa'.repeat(32));
    expect(got?.status).toBe('signed');       // -> the orchestrator idempotently skips it instead of re-voting
    expect((await restarted.getReceipt('aa'.repeat(32)))?.policyEvidence).toEqual({ rule: 'even' });
  });

  it('refuses to start on a corrupt state file rather than silently re-voting everything', () => {
    const path = join(tmp, 'corrupt.json');
    writeFileSync(path, '{ this is not json');
    expect(() => new FileStore(path)).toThrow(/refusing to start with an empty history/);
  });

  it('writes atomically — no .tmp left behind, file is valid JSON', async () => {
    const path = join(tmp, 'atomic.json');
    const s = new FileStore(path);
    for (let i = 0; i < 20; i++) await s.create(row(String(i).padStart(64, '0')));
    expect(() => JSON.parse(readFileSync(path, 'utf8'))).not.toThrow();
    expect(JSON.parse(readFileSync(path, 'utf8')).requests).toHaveLength(20);
  });
});

describe('SR4 value ceiling gates every leg', () => {
  // This exercises the SHIPPED guard (src/guard.ts, wired in index.ts) — not a copy of the expression.
  const guard = makeValueCeilingGuard(1000n);

  it('blocks when a LATER leg exceeds the ceiling even though leg 0 is fine', () => {
    expect(guard({ value: '10', values: ['10', '999999'] })).toBe(false);
  });
  it('allows when every leg is under the ceiling', () => {
    expect(guard({ value: '10', values: ['10', '20', '1000'] })).toBe(true);
  });
  it('blocks an unparseable amount (fail-closed)', () => {
    expect(guard({ values: ['10', 'not-a-number'] })).toBe(false);
  });
  it('does not overflow on amounts beyond Number.MAX_SAFE_INTEGER (wei-scale)', () => {
    // Number('10000000000000000001') === Number('10000000000000000000'), so a float compare would wave
    // this straight past a 1e19 ceiling. BigInt does not.
    const wei = makeValueCeilingGuard(10_000_000_000_000_000_000n);
    expect(wei({ values: ['10000000000000000001'] })).toBe(false);
    expect(wei({ values: ['10000000000000000000'] })).toBe(true);
  });
  it('is actually wired into the orchestrator: an over-ceiling leg is not signed', async () => {
    const acc = new MockAccumulateClient();
    const tx = 'cd'.repeat(32);
    acc.addPending(tx, { body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '999999' }] }, principal: 'acc://x.acme/tokens' });
    const store = new MemoryStore();
    const orch = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(5))),
      policy: new MockPolicyClient({ decision: 'approve' }),   // the ENGINE says yes...
      store, resolver: new Resolver(acc), logger: silent,
      options: { guard: makeValueCeilingGuard(1000n) },        // ...and the local ceiling still refuses
    });
    await orch.handle({ txHash: tx, signerUrl: 'acc://o.acme/book/1' });
    expect(acc.submissions.length).toBe(0);
    expect((await store.get(tx))?.lastError).toBe('local_guard_block');
  });
});

describe('SR8 pause means sign NOTHING', () => {
  // A Reject vote is still a signature. With submit_reject_vote: true (what every shipped config sets),
  // the pause check used to sit AFTER the deny branch — so a "paused" wallet went on signing rejections.
  async function run(decision: 'approve' | 'deny', paused: boolean) {
    const acc = new MockAccumulateClient();
    const tx = 'ab'.repeat(32);
    acc.addPending(tx, { body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '10' }] }, principal: 'acc://x.acme/tokens' });
    const store = new MemoryStore();
    const orch = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(3))),
      policy: new MockPolicyClient({ decision }), store, resolver: new Resolver(acc), logger: silent,
      options: { submitRejectVote: true, isPaused: () => paused },
    });
    await orch.handle({ txHash: tx, signerUrl: 'acc://o.acme/book/1' });
    return { submissions: acc.submissions.length, status: (await store.get(tx))?.status };
  }

  it('withholds the REJECT signature while paused (regression: it used to submit one)', async () => {
    const r = await run('deny', true);
    expect(r.submissions).toBe(0);
    expect(r.status).not.toBe('rejected');   // stays pending; nothing signed
  });

  it('withholds the APPROVE signature while paused', async () => {
    expect((await run('approve', true)).submissions).toBe(0);
  });

  it('still submits both votes when NOT paused', async () => {
    expect((await run('approve', false)).submissions).toBe(1);
    expect((await run('deny', false)).submissions).toBe(1);
  });
});

describe('config rejects what is not implemented', () => {
  it('refuses policy.mode: async instead of silently behaving synchronously', () => {
    const p = join(tmp, 'async.yaml');
    writeFileSync(p, [
      'wallet: { org_id: "o", network: "kermit", accumulate_endpoints: ["https://k.io/v3"],',
      '          signer_url: "acc://o.acme/book/1" }',
      'signer: { provider: "local", local: { allow_ephemeral: true } }',
      'policy: { url: "http://127.0.0.1:9099/decision", mode: "async" }',
    ].join('\n'));
    expect(() => loadConfig(p)).toThrow();
  });
});
