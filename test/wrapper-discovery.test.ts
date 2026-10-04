/**
 * Discovery through the wrapper books' pending lists. Wrapper runbook, change 1 (Phase 4).
 *
 * A delegate receives no signature request, and a delegated vote is routed to `Delegator[0]` — so a
 * transaction waiting on Trust Stamp sits on the WRAPPER book's pending list (`block/sig_common.go:188-196`)
 * and never on ours. Our own page and book being empty is therefore the normal state, not a fault.
 *
 * The poller reads every enrolled wrapper book each cycle, with bounded concurrency, straight from the
 * registry — so a wrapper enrolled while the process runs is polled next cycle with no restart.
 */
import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { AddressInfo } from 'node:net';
import pino from 'pino';
import { Poller } from '../src/poller.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { MemoryWrapperRegistry, WrapperEntry, FileWrapperRegistry, isRegisteredWrapperPage } from '../src/registry/wrappers.js';
import { createServer } from '../src/server.js';
import { metrics } from '../src/metrics.js';
import { PendingRef } from '../src/types.js';
import { WrapperChain, submittedVote } from './support/wrapper-chain.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const TX2 = 'cd'.repeat(32);
const TS_BOOK = 'acc://ts.acme/book';
const TS_PAGE = 'acc://ts.acme/book/1';
const ALICE = 'acc://p.acme/book/1';
const W_ALICE = 'acc://p.acme/id/1';
const ORG = 'acc://o.acme/book/1';
const PRINCIPAL = 'acc://o.acme/tokens';

const entry = (n: string): WrapperEntry => ({ wrapperBook: `acc://${n}.acme/id`, wrapperPage: `acc://${n}.acme/id/1`, subjectId: n, enrolledAt: 1, seats: [] });

/** An orchestrator stand-in that records what discovery handed it. */
function recordingOrch() {
  const refs: PendingRef[] = [];
  return { refs, orch: { handleAll: async (r: PendingRef) => { refs.push(r); return []; } } as unknown as Orchestrator };
}

/** A logger that records warnings, to prove an empty own page/book is not reported as a fault. */
function warnRecorder() {
  const warns: unknown[] = [];
  const l: any = { debug() {}, info() {}, error() {}, warn: (...a: unknown[]) => warns.push(a), child: () => l };
  return { warns, logger: l };
}

const tick = (p: Poller) => (p as unknown as { tick(): Promise<void> }).tick();

describe('wrapper discovery', () => {
  it('a tx pending on an enrolled wrapper book is handed over with its principal and that wrapper as the hint', async () => {
    const acc = new WrapperChain();
    const reg = new MemoryWrapperRegistry();
    await reg.upsert(entry('p'));
    acc.pendingOn('acc://p.acme/id', TX, PRINCIPAL);
    const { refs, orch } = recordingOrch();
    await tick(new Poller(acc, orch, TS_PAGE, 1000, silent, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 8 }));
    expect(refs).toEqual([{ txHash: TX, signerUrl: TS_PAGE, principal: PRINCIPAL, wrapperBook: 'acc://p.acme/id' }]);
  });

  it('end to end: discovered on the wrapper book, voted on the person\'s path', async () => {
    const acc = new WrapperChain();
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '5' }] }, principal: PRINCIPAL });
    acc.pendingOn('acc://p.acme/id', TX, PRINCIPAL);
    acc.approvesThrough(TX, ALICE, [W_ALICE, ORG]);
    const reg = new MemoryWrapperRegistry();
    await reg.upsert(entry('p'));
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), TS_PAGE), policy: new MockPolicyClient({ decision: 'approve' }),
      store: new MemoryStore(), resolver: new Resolver(acc), logger: silent,
      wrapper: { ourBook: TS_BOOK, ourPage: TS_PAGE, isEnrolledWrapperPage: (p) => isRegisteredWrapperPage(reg, p), wrapperBooks: async () => (await reg.list()).map((e) => e.wrapperBook) },
    });
    await tick(new Poller(acc, o, TS_PAGE, 1000, silent, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 8 }));
    expect(acc.submissions).toHaveLength(1);
    expect(submittedVote(acc.submissions[0]).hops).toEqual([W_ALICE, ORG]);
  });

  it('a wrapper added to the registry between cycles is polled on the next cycle, with no restart', async () => {
    const acc = new WrapperChain();
    const reg = new MemoryWrapperRegistry();
    await reg.upsert(entry('p'));
    acc.pendingOn('acc://q.acme/id', TX2, PRINCIPAL);
    const { refs, orch } = recordingOrch();
    const poller = new Poller(acc, orch, TS_PAGE, 1000, silent, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 8 });
    await tick(poller);
    expect(refs).toEqual([]);
    await reg.upsert(entry('q'));
    await tick(poller);
    expect(refs.map((r) => r.txHash)).toEqual([TX2]);
  });

  it('one wrapper\'s failed query does not stop the others, and is counted', async () => {
    const acc = new WrapperChain();
    const reg = new MemoryWrapperRegistry();
    for (const n of ['a', 'b', 'c']) await reg.upsert(entry(n));
    acc.failingPending.add('acc://b.acme/id');
    acc.pendingOn('acc://a.acme/id', TX, PRINCIPAL);
    acc.pendingOn('acc://c.acme/id', TX2, PRINCIPAL);
    const { refs, orch } = recordingOrch();
    const before = metrics.render();
    const poller = new Poller(acc, orch, TS_PAGE, 1000, silent, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 2 });
    await tick(poller);
    expect(refs.map((r) => r.txHash).sort()).toEqual([TX, TX2].sort());
    expect(poller.healthy()).toBe(true);                       // the cycle itself succeeded
    const count = (m: string, text: string) => Number(new RegExp(`^${m} (\\d+)$`, 'm').exec(text)?.[1] ?? 0);
    expect(count('wallet_wrapper_poll_failures_total', metrics.render()) - count('wallet_wrapper_poll_failures_total', before)).toBe(1);
    expect(count('wallet_wrapper_hits_total', metrics.render()) - count('wallet_wrapper_hits_total', before)).toBe(2);
  });

  it('a tx pending on two wrappers (Alice and Bob) is handed over once per wrapper, each with its own hint', async () => {
    const acc = new WrapperChain();
    const reg = new MemoryWrapperRegistry();
    await reg.upsert(entry('p'));
    await reg.upsert(entry('q'));
    acc.pendingOn('acc://p.acme/id', TX, PRINCIPAL);
    acc.pendingOn('acc://q.acme/id', TX, PRINCIPAL);
    const { refs, orch } = recordingOrch();
    await tick(new Poller(acc, orch, TS_PAGE, 1000, silent, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 8 }));
    expect(refs.map((r) => r.wrapperBook).sort()).toEqual(['acc://p.acme/id', 'acc://q.acme/id']);
  });

  it('our own page and book being empty is the normal state: no warning', async () => {
    const acc = new WrapperChain();
    const reg = new MemoryWrapperRegistry();
    await reg.upsert(entry('p'));
    const { warns, logger } = warnRecorder();
    const { orch } = recordingOrch();
    await tick(new Poller(acc, orch, TS_PAGE, 1000, logger, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 8 }));
    expect(acc.calls.pendingForSigner).toBe(1);
    expect(acc.calls.signatureChain).toBe(1);
    expect(warns).toEqual([]);
  });

  it('a registry that cannot be read fails the cycle (the poller backs off) rather than polling nobody quietly', async () => {
    const acc = new WrapperChain();
    const reg = new MemoryWrapperRegistry();
    reg.list = async () => { throw new Error('disk gone'); };
    const { orch } = recordingOrch();
    let clock = 0;
    const poller = new Poller(acc, orch, TS_PAGE, 1000, silent, () => clock, undefined, TS_BOOK, { registry: reg, concurrency: 8 });
    await tick(poller);
    clock = 10_000;
    expect(poller.healthy()).toBe(false);
  });

  it('the file registry survives a restart and refuses to start from an unreadable file', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'certen-reg-'));
    try {
      const path = join(tmp, 'wrappers.json');
      const a = new FileWrapperRegistry(path);
      await a.upsert(entry('p'));
      await a.addSeat('acc://p.acme/id', { orgPage: ORG, attachedTx: TX, attachedAt: 2 });
      const b = new FileWrapperRegistry(path);
      expect((await b.get('ACC://p.acme/id'))?.seats.map((s) => s.orgPage)).toEqual([ORG]);
      await b.removeSeat('acc://p.acme/id', ORG.toUpperCase());
      expect((await new FileWrapperRegistry(path).get('acc://p.acme/id'))?.seats).toEqual([]);
      const { writeFileSync } = await import('node:fs');
      writeFileSync(path, '{not json');
      expect(() => new FileWrapperRegistry(path)).toThrow(/refusing to start/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('capacity: chain reads per idle poll cycle for 1, 100 and 1,000 wrappers', async () => {
    const measured: Record<number, number> = {};
    for (const n of [1, 100, 1000]) {
      const acc = new WrapperChain();
      const reg = new MemoryWrapperRegistry();
      for (let i = 0; i < n; i++) await reg.upsert(entry(`w${i}`));
      let inFlight = 0;
      let peak = 0;
      const orig = acc.listPendingForAccount.bind(acc);
      acc.listPendingForAccount = async (u: string) => {
        inFlight++; peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 0));
        try { return await orig(u); } finally { inFlight--; }
      };
      const { orch } = recordingOrch();
      await tick(new Poller(acc, orch, TS_PAGE, 1000, silent, Date.now, undefined, TS_BOOK, { registry: reg, concurrency: 8 }));
      measured[n] = acc.calls.pendingForAccount + acc.calls.pendingForSigner + acc.calls.signatureChain;
      expect(acc.calls.pendingForAccount).toBe(n);              // exactly one read per wrapper book
      expect(peak).toBeLessThanOrEqual(8);                       // never more than the concurrency bound
    }
    // Two reads of our own (page pending list, book signature chain) plus one per wrapper.
    expect(measured).toEqual({ 1: 3, 100: 102, 1000: 1002 });
  });
});

describe('push with routing hints', () => {
  const HOOK_KEY = 'hook-secret';
  const sign = (raw: string) => {
    const t = String(Date.now());
    return `t=${t},v1=${createHmac('sha256', HOOK_KEY).update(`${t}.${raw}`).digest('hex')}`;
  };
  async function serve() {
    const refs: PendingRef[] = [];
    const orch = { handleAll: async (r: PendingRef) => { refs.push(r); return []; } } as unknown as Orchestrator;
    const server = createServer({ orchestrator: orch, store: new MemoryStore(), keyring: {} as never, accumulate: {} as never, pause: { paused: false }, logger: silent, webhookHmacSecret: HOOK_KEY });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    const post = (body: unknown, sig?: string) => new Promise<number>((resolve, reject) => {
      const raw = JSON.stringify(body);
      const r = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/v1/pending', headers: { 'content-type': 'application/json', ...(sig ? { 'x-certen-signature': sig } : {}) } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode!)); });
      r.on('error', reject); r.end(raw);
    });
    return { server, refs, post };
  }

  it('still requires the HMAC with hints present', async () => {
    const { server, refs, post } = await serve();
    const body = { tx_hash: TX, signer_url: TS_PAGE, principal: PRINCIPAL, wrapper_book: 'acc://p.acme/id' };
    expect(await post(body)).toBe(401);
    expect(await post(body, sign(JSON.stringify({ ...body, tx_hash: TX2 })))).toBe(401);
    expect(refs).toEqual([]);
    server.close();
  });

  it('passes valid hints on as hints, and drops ones that are not acc:// URLs', async () => {
    const { server, refs, post } = await serve();
    const good = { tx_hash: TX, signer_url: TS_PAGE, principal: PRINCIPAL, wrapper_book: 'acc://p.acme/id' };
    expect(await post(good, sign(JSON.stringify(good)))).toBe(202);
    const bad = { tx_hash: TX2, signer_url: TS_PAGE, principal: 'https://evil.example', wrapper_book: 42 };
    expect(await post(bad, sign(JSON.stringify(bad)))).toBe(202);
    await new Promise((r) => setTimeout(r, 10));
    expect(refs).toEqual([
      { txHash: TX, signerUrl: TS_PAGE, principal: PRINCIPAL, wrapperBook: 'acc://p.acme/id' },
      { txHash: TX2, signerUrl: TS_PAGE },
    ]);
    server.close();
  });

  it('a hint never becomes a path: a pushed wrapper with no recorded approval signs nothing', async () => {
    // The orchestrator re-derives from the votes at the hinted book; see wrapper-path.test.ts "a wrong hint".
    const acc = new WrapperChain();
    acc.addPending(TX, { body: { type: 'sendTokens', to: [] }, principal: PRINCIPAL });
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), TS_PAGE), policy: new MockPolicyClient({ decision: 'approve' }),
      store: new MemoryStore(), resolver: new Resolver(acc), logger: silent,
      wrapper: { ourBook: TS_BOOK, ourPage: TS_PAGE, isEnrolledWrapperPage: async () => true, wrapperBooks: async () => [] },
    });
    expect(await o.handleAll({ txHash: TX, signerUrl: TS_PAGE, principal: PRINCIPAL, wrapperBook: 'acc://p.acme/id' })).toEqual([]);
    expect(acc.submissions).toHaveLength(0);
  });
});
