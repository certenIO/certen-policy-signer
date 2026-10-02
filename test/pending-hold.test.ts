/**
 * G-64: a seat persists WHY it is holding.
 *
 * The decision service's `pending` answer (its reason and the rule-set / provider-config / signer-config
 * versions it stamped) is kept on the request record, updated on each re-evaluation with a bounded history
 * of distinct reasons, exposed on GET /v1/requests/:tx, finalised (kept as history) when the request is
 * decided, and survives a restart of a FileStore-backed signer. Nothing but the reason text and the three
 * version stamps is stored. All parties, providers and versions are FICTIONAL.
 */
import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { HOLD_HISTORY_MAX, HOLD_REASON_MAX, finaliseHold, holdVersions, recordHold, sanitizeReason } from '../src/store/pending-hold.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import type { PolicyClient } from '../src/policy/policy.js';
import { FileStore, MemoryStore, type Store } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { createServer } from '../src/server.js';
import type { Decision } from '../src/types.js';

const silent = pino({ level: 'silent' });
const TX = '6a'.repeat(32);
const PAGE = 'acc://fictional-bank-tcl1.acme/book/2';
const ADMIN = 'fictional-admin-key-000000';
const V1 = { ruleSetVersion: 'fictional-rules-2026-10-01.1', providerConfigVersion: 'sha256:' + '1'.repeat(64), signerConfigVersion: 'sha256:' + '2'.repeat(64) };
const V2 = { ...V1, providerConfigVersion: 'sha256:' + '3'.repeat(64) };
const SECRETISH = 'FICTIONAL-provider-api-key-value-0000';

/** A policy client answering from a script, one decision per call. */
function scripted(decisions: Decision[]): PolicyClient & { calls: number } {
  const c = { calls: 0, decide: async () => decisions[Math.min(c.calls++, decisions.length - 1)] };
  return c as unknown as PolicyClient & { calls: number };
}

function pipeline(store: Store, policy: PolicyClient, clock: { t: number }) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://fictional-payee-tcl1.acme/tokens', amount: '5000' }] }, principal: 'acc://fictional-payer-tcl1.acme/tokens' });
  const orchestrator = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(5)), PAGE), policy, store,
    resolver: new Resolver(acc), logger: silent, now: () => clock.t,
  });
  return { acc, orchestrator, handle: () => orchestrator.handle({ txHash: TX, signerUrl: PAGE }) };
}

const hold = (reason: string, versions: Record<string, unknown> = V1, extra: Record<string, unknown> = {}): Decision =>
  ({ decision: 'pending', reason, evidence: { seat: 'bank-risk', ...versions, providerFacts: { riskScore: { apiKey: SECRETISH, score: null } }, ...extra } });

describe('pending-hold helpers', () => {
  it('keeps only the three version stamps, by name, from the evidence', () => {
    expect(holdVersions({ ...V1, providerFacts: { x: 1 }, seat: 'bank-risk', token: SECRETISH })).toEqual(V1);
    expect(holdVersions({ ruleSetVersion: 7, providerConfigVersion: 'x'.repeat(500), signerConfigVersion: 'bad\nvalue' })).toEqual({});
    expect(holdVersions(undefined)).toEqual({});
  });

  it('sanitises the reason: control characters, length, and anything shaped like a credential', () => {
    expect(sanitizeReason('provider risk-score gave no answer (HTTP 503)')).toBe('provider risk-score gave no answer (HTTP 503)');
    expect(sanitizeReason(undefined)).toBe('(the decision service gave no reason)');
    expect(sanitizeReason('a\nb\u0007c')).toBe('a b c');
    expect(sanitizeReason('x'.repeat(5000))).toHaveLength(HOLD_REASON_MAX);
    const r = sanitizeReason(`upstream said api_key=${SECRETISH}; Authorization: Bearer ${SECRETISH} at https://p.example/v1?token=${SECRETISH}&q=1`);
    expect(r).not.toContain(SECRETISH);
    expect(r).toContain('[redacted]');
  });

  it('records, updates, dedupes and bounds the history of distinct reasons', () => {
    let cur: { pending?: ReturnType<typeof recordHold> } = {};
    cur = { pending: recordHold(cur, hold('reason A'), 1_000) };
    cur = { pending: recordHold(cur, hold('reason A'), 2_000) };
    expect(cur.pending).toMatchObject({ reason: 'reason A', since: new Date(1_000).toISOString(), lastEvaluatedAt: new Date(2_000).toISOString(), evaluations: 2 });
    expect(cur.pending!.history).toEqual([{ reason: 'reason A', versions: V1, firstSeenAt: new Date(1_000).toISOString(), lastSeenAt: new Date(2_000).toISOString(), count: 2 }]);
    // Same text, different versions: a distinct reason.
    cur = { pending: recordHold(cur, hold('reason A', V2), 3_000) };
    expect(cur.pending!.history).toHaveLength(2);
    // Back to the first: moved to the end, not duplicated.
    cur = { pending: recordHold(cur, hold('reason A'), 4_000) };
    expect(cur.pending!.history.map((h) => h.versions.providerConfigVersion)).toEqual([V2.providerConfigVersion, V1.providerConfigVersion]);
    for (let i = 0; i < HOLD_HISTORY_MAX + 5; i++) cur = { pending: recordHold(cur, hold(`reason ${i}`), 5_000 + i) };
    expect(cur.pending!.history).toHaveLength(HOLD_HISTORY_MAX);
    expect(cur.pending!.history.at(-1)!.reason).toBe(`reason ${HOLD_HISTORY_MAX + 4}`);
    expect(cur.pending!.since).toBe(new Date(1_000).toISOString());
  });

  it('finaliseHold clears the hold and keeps it, or does nothing when there was none', () => {
    const pending = recordHold(undefined, hold('reason A'), 1_000);
    expect(finaliseHold({ pending }, 'approve', 9_000)).toEqual({ pending: undefined, pendingFinal: { ...pending, endedAt: new Date(9_000).toISOString(), outcome: 'approve' } });
    expect(finaliseHold({}, 'approve', 9_000)).toEqual({});
  });

  it('a new hold after a finalised one keeps the earlier reasons in its history', () => {
    const first = recordHold(undefined, hold('reason A'), 1_000);
    const { pendingFinal } = finaliseHold({ pending: first }, 'error', 2_000);
    const second = recordHold({ pendingFinal }, hold('reason B'), 3_000);
    expect(second.since).toBe(new Date(3_000).toISOString());
    expect(second.history.map((h) => h.reason)).toEqual(['reason A', 'reason B']);
  });
});

describe('the orchestrator keeps why a seat is holding', () => {
  it('stores the reason and versions, updates them on re-evaluation, and finalises them on the decision', async () => {
    const store = new MemoryStore();
    const clock = { t: Date.parse('2026-10-02T09:00:00Z') };
    const policy = scripted([
      hold('provider risk-score gave no answer (HTTP 503)'),
      hold('provider risk-score gave no answer (HTTP 503)'),
      hold('awaiting a second approver (FICTIONAL rule large-supplier-payment)', V2),
      { decision: 'approve', reason: 'FICTIONAL rule passed', evidence: V2 },
    ]);
    const p = pipeline(store, policy, clock);

    let r = await p.handle();
    expect(r.status).toBe('awaiting_policy');
    expect(r.pending).toMatchObject({ reason: 'provider risk-score gave no answer (HTTP 503)', versions: V1, since: '2026-10-02T09:00:00.000Z', lastEvaluatedAt: '2026-10-02T09:00:00.000Z', evaluations: 1 });

    clock.t += 20_000;
    r = await p.handle();
    expect(r.pending).toMatchObject({ since: '2026-10-02T09:00:00.000Z', lastEvaluatedAt: '2026-10-02T09:00:20.000Z', evaluations: 2 });
    expect(r.pending!.history).toHaveLength(1);
    expect(r.pending!.history[0].count).toBe(2);

    clock.t += 20_000;
    r = await p.handle();
    expect(r.pending).toMatchObject({ reason: 'awaiting a second approver (FICTIONAL rule large-supplier-payment)', versions: V2, evaluations: 3 });
    expect(r.pending!.history.map((h) => h.reason)).toEqual(['provider risk-score gave no answer (HTTP 503)', 'awaiting a second approver (FICTIONAL rule large-supplier-payment)']);

    clock.t += 20_000;
    r = await p.handle();
    expect(r.status).toBe('signed');
    expect(r.pending).toBeUndefined();
    expect(r.pendingFinal).toMatchObject({
      outcome: 'approve', endedAt: '2026-10-02T09:01:00.000Z', since: '2026-10-02T09:00:00.000Z',
      reason: 'awaiting a second approver (FICTIONAL rule large-supplier-payment)',
    });
    expect(r.pendingFinal!.history).toHaveLength(2);
    // Never the decision's evidence: the provider facts (with their secret-shaped value) are not on the record.
    expect(JSON.stringify(await store.get(TX))).not.toContain(SECRETISH);
    expect(JSON.stringify(await store.get(TX))).not.toContain('providerFacts');
  });

  it('a deny ends the hold too, and a request that never held gains no hold fields', async () => {
    const store = new MemoryStore();
    const clock = { t: 1_800_000_000_000 };
    const p = pipeline(store, scripted([hold('waiting on sanctions-screen'), { decision: 'deny', reason: 'FICTIONAL rule failed' }]), clock);
    await p.handle();
    const r = await p.handle();
    expect(r.status).toBe('rejected');
    expect(r).toMatchObject({ pendingFinal: { outcome: 'deny', reason: 'waiting on sanctions-screen' } });
    expect(r.pending).toBeUndefined();

    const store2 = new MemoryStore();
    const r2 = await pipeline(store2, scripted([{ decision: 'approve' }]), clock).handle();
    expect(r2.status).toBe('signed');
    expect('pending' in r2 || 'pendingFinal' in r2).toBe(false);
  });

  it('a transaction that goes away while held keeps the hold with that outcome', async () => {
    const store = new MemoryStore();
    const clock = { t: 1_800_000_000_000 };
    const p = pipeline(store, scripted([hold('waiting on sanctions-screen')]), clock);
    await p.handle();
    p.acc.pending.get(TX)!.expired = true;
    const r = await p.handle();
    expect(r.status).toBe('expired');
    expect(r.pendingFinal).toMatchObject({ outcome: 'gone:expired', reason: 'waiting on sanctions-screen' });
    expect(r.pending).toBeUndefined();
  });
});

function listen(s: http.Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as { port: number }).port)));
}
function get(port: number, path: string) {
  return new Promise<{ status: number; json: any }>((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path, headers: { 'x-api-key': ADMIN } }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => resolve({ status: res.statusCode!, json: JSON.parse(t) }));
    }).on('error', reject);
  });
}

describe('exposed on the admin API, and durable across a restart', () => {
  it('GET /v1/requests/:tx shows pending while holding and pendingFinal once decided; FileStore keeps both', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'g64-'));
    const path = join(dir, 'state.json');
    const clock = { t: Date.parse('2026-10-02T10:00:00Z') };
    const store = new FileStore(path);
    const p = pipeline(store, scripted([hold('provider risk-score gave no answer (HTTP 503)')]), clock);
    await p.handle();

    const serve = async (s: Store) => {
      const server = createServer({ orchestrator: p.orchestrator, store: s, keyring: {} as any, accumulate: {} as any, pause: { paused: false }, logger: silent, adminApiKey: ADMIN });
      return { server, port: await listen(server) };
    };

    let srv = await serve(store);
    try {
      const r = await get(srv.port, `/v1/requests/${TX}`);
      expect(r.status).toBe(200);
      expect(r.json.pending).toMatchObject({ reason: 'provider risk-score gave no answer (HTTP 503)', versions: V1, since: '2026-10-02T10:00:00.000Z', lastEvaluatedAt: '2026-10-02T10:00:00.000Z' });
      expect(r.json.pending.history).toHaveLength(1);
      expect(r.json.request.pending).toEqual(r.json.pending);
      expect(r.json.pendingFinal).toBeNull();
      const list = await get(srv.port, '/v1/requests?status=awaiting_policy');
      expect(list.json.requests[0].request.pending.reason).toBe('provider risk-score gave no answer (HTTP 503)');
    } finally { srv.server.close(); }

    // Restart: a new FileStore on the same file still knows why the seat was holding.
    const reopened = new FileStore(path);
    expect((await reopened.get(TX))?.pending).toMatchObject({ reason: 'provider risk-score gave no answer (HTTP 503)', versions: V1 });

    // Decide after the restart; the hold is kept as history, and that survives a restart too.
    clock.t += 60_000;
    const p2 = pipeline(reopened, scripted([{ decision: 'approve', reason: 'FICTIONAL rule passed' }]), clock);
    expect((await p2.handle()).status).toBe('signed');
    const again = new FileStore(path);
    srv = await serve(again);
    try {
      const r = await get(srv.port, `/v1/requests/${TX}`);
      expect(r.json.pending).toBeNull();
      expect(r.json.pendingFinal).toMatchObject({ outcome: 'approve', since: '2026-10-02T10:00:00.000Z', endedAt: '2026-10-02T10:01:00.000Z', reason: 'provider risk-score gave no answer (HTTP 503)' });
    } finally { srv.server.close(); }

    // No secret value reached the state file: the decision's evidence is never written.
    const raw = readFileSync(path, 'utf8');
    expect(raw).not.toContain(SECRETISH);
    expect(raw).not.toContain('providerFacts');
  });
});
