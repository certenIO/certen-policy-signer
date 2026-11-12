/**
 * The admin surface of the persisted pause (POST/GET /v1/admin/pause, POST /v1/admin/resume, POST /v1/admin/decisions/void) and
 * the config of binding and seats. FICTIONAL data, temp directories only.
 */
import { afterEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { DecisionJournal } from '../src/binding/journal.js';
import { NonceStore } from '../src/binding/nonces.js';
import { PauseStore } from '../src/binding/pause-store.js';
import { derivedSeat } from '../src/binding/seats.js';
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
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-a-')); dirs.push(d); return d; };
const ADMIN = 'fic-admin-key-0000';
const SEATS = ['seat:fic-treasury', 'seat:fic-risk'];
const BY = 'seat:fic-operator';
const WHY = 'FICTIONAL: suspected misuse, stopping';

async function start() {
  const dir = tmp();
  const journal = new DecisionJournal({ path: join(dir, 'j.jsonl'), logId: 'fic-signer' });
  const pause = new PauseStore({ journal, statePath: join(dir, 'pause-state.json'), seats: SEATS, nowSeconds: () => 1_800_000_000 });
  const nonces = new NonceStore(journal, () => 1_800_000_000);
  const acc = new MockAccumulateClient();
  const keyring = singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)));
  const store = new MemoryStore();
  const { createServer } = await import('../src/server.js');
  const server = createServer({
    orchestrator: new Orchestrator({ accumulate: acc, keyring, policy: new MockPolicyClient({ decision: 'approve' }), store, resolver: new Resolver(acc), logger: silent, pauses: pause }),
    store, keyring, accumulate: acc, pause, nonces, logger: silent, adminApiKey: ADMIN,
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  servers.push(server);
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const call = async (method: string, path: string, body?: unknown) => {
    const r = await fetch(url + path, { method, headers: { 'x-api-key': ADMIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: r.status, json: (await r.json()) as any };
  };
  return { call, pause, nonces, url };
}

describe('POST /v1/admin/pause and /resume (DE-26, DE-27)', () => {
  it('refuses by name: no seat, a reason that is too short, a resume with no reason, a resume of what is not paused', async () => {
    const { call, pause } = await start();
    expect(await call('POST', '/v1/admin/pause')).toMatchObject({ status: 400, json: { error: 'seat_required' } });
    expect(await call('POST', '/v1/admin/pause', { by: 'alice', reason: WHY })).toMatchObject({ status: 400, json: { error: 'seat_invalid' } });
    expect(await call('POST', '/v1/admin/pause', { by: BY, reason: 'short' })).toMatchObject({ status: 400, json: { error: 'reason_required' } });
    expect(await call('POST', '/v1/admin/pause', { scope: 'planet', id: 'x', by: BY, reason: WHY })).toMatchObject({ status: 400, json: { error: 'pause_scope_invalid' } });
    expect(await call('POST', '/v1/admin/pause', { id: SEATS[0], by: BY, reason: WHY })).toMatchObject({ status: 400, json: { error: 'pause_scope_invalid' } });
    expect(await call('POST', '/v1/admin/resume', { by: BY, reason: WHY })).toMatchObject({ status: 409, json: { error: 'not_paused' } });
    expect(await call('POST', '/v1/admin/resume', { scope: 'seat', id: SEATS[0], by: BY, reason: '' })).toMatchObject({ status: 400, json: { error: 'reason_required' } });
    expect(pause.anyPaused()).toBe(false);
  });

  it('pauses one seat, then a subject; GET shows who and why; the wrong scope is not lifted by a resume; /healthz says paused', async () => {
    const { call, pause, url } = await start();
    expect((await call('POST', '/v1/admin/pause', { scope: 'seat', id: SEATS[0], by: BY, reason: WHY })).json.paused).toBe(true);
    expect(await call('POST', '/v1/admin/pause', { scope: 'seat', id: SEATS[0], by: BY, reason: WHY })).toMatchObject({ status: 409, json: { error: 'already_paused' } });
    await call('POST', '/v1/admin/pause', { scope: 'subject', id: 'acc://agent-one.fic-grantor.acme', by: BY, reason: WHY });
    const got = await call('GET', '/v1/admin/pause');
    expect(got.json.pauses.map((p: any) => [p.scope, p.id, p.by])).toEqual([['seat', SEATS[0], BY], ['subject', 'acc://agent-one.fic-grantor.acme', BY]]);
    expect(got.json.seats).toEqual(SEATS);
    expect((await call('POST', '/v1/admin/resume', { scope: 'subject', id: SEATS[0], by: BY, reason: WHY })).status).toBe(400); // an id of the wrong shape for the scope
    expect((await call('POST', '/v1/admin/resume', { scope: 'seat', id: 'acc://agent-one.fic-grantor.acme', by: BY, reason: WHY })).status).toBe(400);
    expect(pause.snapshot().pauses).toHaveLength(2);
    const health = (await (await fetch(`${url}/healthz`)).json()) as { paused: boolean; reasons: string[] };
    expect(health.paused).toBe(true);
    expect(health.reasons).toContain('paused');
    await call('POST', '/v1/admin/resume', { scope: 'seat', id: SEATS[0], by: BY, reason: WHY });
    expect(pause.snapshot().pauses.map((p) => p.scope)).toEqual(['subject']); // only its own scope was lifted
  });

  it('without a scope it acts on every configured seat and never lifts a subject pause', async () => {
    const { call, pause } = await start();
    await call('POST', '/v1/admin/pause', { scope: 'subject', id: 'acc://agent-one.fic-grantor.acme', by: BY, reason: WHY });
    expect((await call('POST', '/v1/admin/pause', { by: BY, reason: WHY })).status).toBe(200);
    expect(SEATS.map((s) => pause.check({ seat: s, subject: null, vote: 'reject' }).ok)).toEqual([false, false]);
    expect((await call('POST', '/v1/admin/resume', { by: BY, reason: WHY })).json.paused).toBe(true); // the subject is still paused
    expect(SEATS.map((s) => pause.check({ seat: s, subject: null, vote: 'approve' }).ok)).toEqual([true, true]);
  });

  it('needs the admin key like every admin route', async () => {
    const { url } = await start();
    expect((await fetch(`${url}/v1/admin/pause`, { method: 'GET' })).status).toBe(401);
    expect((await fetch(`${url}/v1/admin/decisions/void`, { method: 'POST', body: '{}' })).status).toBe(401);
  });
});

describe('POST /v1/admin/decisions/void', () => {
  it('voids nonces durably and idempotently; a malformed nonce is refused by name', async () => {
    const { call, nonces } = await start();
    expect((await call('POST', '/v1/admin/decisions/void', { nonces: [H('old-1'), H('old-2')], reason: 'policy_changed' })).json.voided).toEqual([H('old-1'), H('old-2')]);
    expect((await call('POST', '/v1/admin/decisions/void', { nonces: [H('old-1')], reason: 'policy_changed' })).json.voided).toEqual([]);
    expect(nonces.has(H('old-2'))).toBe(true);
    expect(await call('POST', '/v1/admin/decisions/void', { nonces: ['nope'], reason: 'x' })).toMatchObject({ status: 400, json: { error: 'nonce_malformed' } });
    expect((await call('POST', '/v1/admin/decisions/void', { nonces: [H('a')] })).status).toBe(400);
  });
});

describe('config: binding and seats', () => {
  const base = (extra: string, wallet = ''): string => {
    const f = join(tmp(), 'c.yaml');
    writeFileSync(f, ['wallet: { org_id: "o", accumulate_endpoints: ["https://k.io/v3"], signer_url: "acc://o.acme/book/1"' + wallet + ' }',
      'signer: { provider: "local", local: { allow_ephemeral: true } }', 'policy: { url: "http://127.0.0.1:9099/decision" }', extra].join('\n'));
    return f;
  };
  const GOOD = `binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400 }`;

  it('derives a valid seat id for every page and keeps a configured one', () => {
    expect(derivedSeat('acc://o.acme/book/1')).toBe('seat:o.acme-book-1');
    expect(derivedSeat('acc://Harbor-Treasury.acme/book/1')).toBe('seat:harbor-treasury.acme-book-1');
    expect(derivedSeat('acc://' + 'x'.repeat(100) + '.acme/book/1')).toMatch(/^seat:x{49}-[0-9a-f]{12}$/);
    const cfg = loadConfig(base(GOOD));
    expect(effectiveSeats(cfg)).toEqual([{ page: 'acc://o.acme/book/1', seat: 'seat:o.acme-book-1', binding: expect.objectContaining({ max_window_seconds: 5400, require_grant: false, registry_principals: [] }) }]);
    const named = loadConfig(base('', ', seat: "seat:fic-treasury"'));
    expect(effectiveSeats(named)[0]).toEqual({ page: 'acc://o.acme/book/1', seat: 'seat:fic-treasury' });
  });

  it('refuses at boot what would leave a seat unbound or ambiguous', () => {
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["Alice Officer"], max_window_seconds: 5400 }`))).toThrow(/never a display name/);
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 86401 }`))).toThrow();
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"] }`))).toThrow(); // no default window
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400, policy_hash: "0xABC" }`))).toThrow();
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400, polcy_hash: "x" }`))).toThrow(); // a typo stops the boot
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}", "${KEY('a')}"], max_window_seconds: 5400 }`))).toThrow(/twice/);
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400, require_grant: true }`))).toThrow(/grantor_adi/);
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400, require_grant: true, grantor_adi: "acc://g.acme", registry_principals: [] }`))).toThrow(/registry_principals/);
    expect(() => loadConfig(base('', ', seat: "Treasury"'))).toThrow(/seat:<name>/);
    expect(() => loadConfig(base(`binding: { authorized_approvers: ["${KEY('a')}"], max_window_seconds: 5400, require_grant: true, grantor_adi: "acc://g.acme", registry_principals: ["acc://p.acme"] }`))).not.toThrow();
  });

  it('a binding block changes the config version (the signer-config version on every receipt names the pin)', () => {
    const a = loadConfig(base('')).configVersion;
    const b = loadConfig(base(GOOD)).configVersion;
    const c = loadConfig(base(GOOD.replace('5400', '3600'))).configVersion;
    expect(new Set([a, b, c]).size).toBe(3);
  });
});
