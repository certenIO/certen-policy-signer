/**
 * DAX-4S round 6, the settings and the operator surface: the seat settings `policy_hash` (REQUIRED: the hash the seat loads and the pin
 * step pins), `allow_raw` (DE-91) and `settlement_horizon_seconds` (DE-88: never below the validator one hour, a seat configured with less
 * refuses to start), and the pin step as an admin route (GET and POST /v1/admin/pin). Also: no production call site of the core ledger or of
 * a relaxation switch exists in this repository (the signer has no ledger; DAXCORE2 R2). FICTIONAL data, temp directories only.
 */
import { afterEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { DecisionJournal } from '../src/binding/journal.js';
import { NonceStore } from '../src/binding/nonces.js';
import { PinStore } from '../src/binding/pin-store.js';
import { PauseStore } from '../src/binding/pause-store.js';
import { effectiveSeats, loadConfig } from '../src/config.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { Resolver } from '../src/resolver.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { LocalSigner } from '../src/signer/signer.js';
import { MemoryStore } from '../src/store/store.js';
import { H, KEY } from './support/binding-fixtures.js';

const silent = pino({ level: 'silent' });
const dirs: string[] = [];
const servers: http.Server[] = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-r6-')); dirs.push(d); return d; };
const NL = String.fromCharCode(10);

describe('config: policy_hash, allow_raw, settlement_horizon_seconds', () => {
  const STATE = join(tmpdir(), 'dax4s-r6-cfg', 'store.json').split(String.fromCharCode(92)).join('/');
  const base = (extra: string): string => {
    const f = join(tmp(), 'c.yaml');
    writeFileSync(f, ['wallet: { org_id: "o", accumulate_endpoints: ["https://k.io/v3"], signer_url: "acc://o.acme/book/1" }',
      'signer: { provider: "local", local: { allow_ephemeral: true } }', 'policy: { url: "http://127.0.0.1:9099/decision" }', `store: { path: "${STATE}" }`, extra].join(NL));
    return f;
  };
  const B = (more: string) => `binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400, policy_hash: "${H('policy-v1')}"${more} }`;

  it('REQUIRES policy_hash on a bound seat: the seat loads it and the pin step pins it; a seat with nothing to pin could never decide (DE-93)', () => {
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400 }`))).toThrow(/policy_hash/);
    expect(() => loadConfig(base(B('')))).not.toThrow();
  });

  it('allow_raw defaults to false and is a boolean (DE-91)', () => {
    expect(effectiveSeats(loadConfig(base(B('')))) [0]!.binding).toMatchObject({ allow_raw: false });
    expect(effectiveSeats(loadConfig(base(B(', allow_raw: true'))))[0]!.binding).toMatchObject({ allow_raw: true });
    expect(() => loadConfig(base(B(', allow_raw: "yes"')))).toThrow();
  });

  it('settlement_horizon_seconds defaults to the validator one hour, may be larger, and a seat configured with less REFUSES TO START (DE-88)', () => {
    expect(effectiveSeats(loadConfig(base(B(''))))[0]!.binding).toMatchObject({ settlement_horizon_seconds: 3600 });
    expect(effectiveSeats(loadConfig(base(B(', settlement_horizon_seconds: 7200'))))[0]!.binding).toMatchObject({ settlement_horizon_seconds: 7200 });
    for (const bad of ['3599', '0', '-1', '5400.5', '"3600"']) expect(() => loadConfig(base(B(`, settlement_horizon_seconds: ${bad}`))), bad).toThrow();
    expect(() => loadConfig(base(B(', settlement_horizon_seconds: 3599')))).toThrow(/3600/);
  });
});

describe('POST /v1/admin/pin and GET /v1/admin/pin (DE-94)', () => {
  const ADMIN = 'fic-admin-key-0000';
  const SEAT = 'seat:fic-treasury';
  const BY = 'seat:fic-operator';
  const WHY = 'FICTIONAL: rule set v1 reviewed by two officers';
  async function start(withPins = true) {
    const dir = tmp();
    const journal = new DecisionJournal({ path: join(dir, 'j.jsonl'), logId: 'fic-signer' });
    const pause = new PauseStore({ journal, statePath: join(dir, 'pause-state.json'), seats: [SEAT], nowSeconds: () => 1_800_000_000 });
    const nonces = new NonceStore(journal, () => 1_800_000_000);
    const pins = new PinStore({ journal, seats: [{ seat: SEAT, loadedHash: H('policy-v1') }], nowSeconds: () => 1_800_000_000 });
    const acc = new MockAccumulateClient();
    const keyring = singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)));
    const store = new MemoryStore();
    const { createServer } = await import('../src/server.js');
    const server = createServer({
      orchestrator: new Orchestrator({ accumulate: acc, keyring, policy: new MockPolicyClient({ decision: 'approve' }), store, resolver: new Resolver(acc), logger: silent, pauses: pause }),
      store, keyring, accumulate: acc, pause, nonces, ...(withPins ? { pins } : {}), logger: silent, adminApiKey: ADMIN,
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    servers.push(server);
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const call = async (method: string, path: string, body?: unknown, key: string | null = ADMIN) => {
      const r = await fetch(url + path, { method, headers: { ...(key === null ? {} : { 'x-api-key': key }), ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      return { status: r.status, json: (await r.json()) as any };
    };
    return { call, journal, pins };
  }

  it('GET lists every seat with the hash it loaded, its pin and its phase', async () => {
    const { call } = await start();
    expect((await call('GET', '/v1/admin/pin')).json).toEqual({ seats: [{ seat: SEAT, loaded: H('policy-v1'), pin: null, phase: 'pin_pending' }] });
  });

  it('POST pins the loaded hash: 200, a policy.pinned entry, the gate opens; the same step again is idempotent', async () => {
    const { call, journal, pins } = await start();
    const r = await call('POST', '/v1/admin/pin', { seat: SEAT, hash: H('policy-v1'), by: BY, reason: WHY });
    expect(r).toMatchObject({ status: 200, json: { phase: 'pinned', previous: null } });
    expect(journal.entries().filter((e) => e.kind === 'policy.pinned')).toHaveLength(1);
    expect(pins.gate(SEAT)).toEqual({ ok: true, pin: H('policy-v1') });
    const again = await call('POST', '/v1/admin/pin', { seat: SEAT, hash: H('policy-v1'), by: BY, reason: WHY });
    expect(again).toMatchObject({ status: 200, json: { idempotent: true } });
    expect(journal.entries().filter((e) => e.kind === 'policy.pinned')).toHaveLength(1);
  });

  it('refuses by name with 400: no seat identity, a short reason, a hash the seat did not load, an unknown seat, a body that is not an object', async () => {
    const { call, journal } = await start();
    expect(await call('POST', '/v1/admin/pin', { seat: SEAT, hash: H('policy-v1'), reason: WHY })).toMatchObject({ status: 400, json: { error: 'seat_required' } });
    expect(await call('POST', '/v1/admin/pin', { seat: SEAT, hash: H('policy-v1'), by: BY, reason: 'short' })).toMatchObject({ status: 400, json: { error: 'reason_required' } });
    expect(await call('POST', '/v1/admin/pin', { seat: SEAT, hash: H('policy-v2'), by: BY, reason: WHY })).toMatchObject({ status: 400, json: { error: 'pin_hash_not_loaded' } });
    expect(await call('POST', '/v1/admin/pin', { seat: 'seat:nope', hash: H('policy-v1'), by: BY, reason: WHY })).toMatchObject({ status: 400, json: { error: 'pin_seat_unknown' } });
    expect((await call('POST', '/v1/admin/pin', [] as never)).status).toBe(400);
    expect(journal.entries().filter((e) => e.kind === 'policy.pinned')).toHaveLength(0);
  });

  it('is an ADMIN route: without the key it is 401, and a signer with no pin control answers 404', async () => {
    const { call } = await start();
    expect((await call('GET', '/v1/admin/pin', undefined, null)).status).toBe(401);
    expect((await call('POST', '/v1/admin/pin', {}, null)).status).toBe(401);
    const none = await start(false);
    expect((await none.call('GET', '/v1/admin/pin')).status).toBe(404);
  });
});

describe('no relaxation switch and no ledger call in the production source (DAXCORE2 R2: the signer has no ledger)', () => {
  const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : p.endsWith('.ts') ? [p] : []; });
  const files = walk(new URL('../src', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  it('names no createLedger, replayLedger, requireGrantHash, strict:false or harness switch outside the copied core text', () => {
    expect(files.length).toBeGreaterThan(50);
    const hits: string[] = [];
    for (const f of files) {
      const text = readFileSync(f, 'utf8');
      if (/\b(createLedger|replayLedger|requireGrantHash|harnessUnpinned)\b|\bstrict\s*:\s*false\b/.test(text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, ''))) hits.push(f);
    }
    expect(hits).toEqual([]);
  });
});
