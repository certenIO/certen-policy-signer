/**
 * Phase 6.3 (configVersion) and 6.4 (decision-service relay on the admin API). FICTIONAL lab.
 *
 * Every credential below is a throwaway test string, not a secret; every party is FICTIONAL.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import http from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { loadConfig, computeConfigVersion } from '../src/config.js';
import { createRelayClientsHandler, RelayClientsDeps } from '../src/relay-clients.js';
import { createServer } from '../src/server.js';
import type { KeyPageOp, KeyPageResult } from '../src/ops/keypage.js';
import type { PolicyRequest } from '../src/types.js';

const silent = pino({ level: 'silent' });
const dir = mkdtempSync(join(tmpdir(), 'p6-config-'));

const baseYaml = (extra = '') => `
wallet:
  org_id: "fictional-bank-tcl1"
  accumulate_endpoints: ["http://127.0.0.1:1/v3"]
  signer_url: "acc://fictional-bank-tcl1.acme/book/2"
signer:
  provider: "local"
  local:
    seed_hex: "env:P6_TEST_SEED"
policy:
  url: "http://127.0.0.1:9099/decision"
  auth: "hmac"
  hmac_secret: "env:P6_TEST_HMAC"
admin:
  api_key: "env:P6_TEST_ADMIN"
  relay_clients:
    - { name: "compliance-decision", key: "env:P6_TEST_RELAY_COMPLIANCE", scopes: [proof, tx, pending] }
decoders:
  evm_abi:
    - { chain_id: 84532, address: "0x2d9e724dE974A81E97ee553B3482cAFA6d5Fe46b", name: FDBUSD, abi_file: "abi/FDBUSD.json", asset: { symbol: FDBUSD, decimals: 2 } }
  labels: { "0xe66e6f40f1d7a1c06abace493f38c03800ac565a": "Delta Equipment (FICTIONAL)" }
${extra}`;

function write(name: string, text: string) {
  const p = join(dir, name);
  writeFileSync(p, text);
  return p;
}

const ENV = { P6_TEST_SEED: '11'.repeat(32), P6_TEST_HMAC: 'hmac-test-value-aaaaaaaa', P6_TEST_ADMIN: 'admin-test-value-aaaaaaa', P6_TEST_RELAY_COMPLIANCE: 'relay-client-test-value-a' };
const saved: Record<string, string | undefined> = {};

beforeAll(() => {
  for (const [k, v] of Object.entries(ENV)) { saved[k] = process.env[k]; process.env[k] = v; }
  mkdirSync(join(dir, 'abi'), { recursive: true });
  write('abi/FDBUSD.json', JSON.stringify([{ type: 'function', name: 'transferWithReference', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'paymentRef', type: 'bytes32' }] }]));
});
afterAll(() => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

describe('configVersion (6.3)', () => {
  it('is sha256: + 64 hex, stable across loads, and inlines the ABI file', () => {
    const a = loadConfig(write('a.yaml', baseYaml()));
    const b = loadConfig(write('b.yaml', baseYaml()));
    expect(a.configVersion).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(a.configVersion).toBe(b.configVersion);
    expect(a.decoders.evm_abi[0].abi).toHaveLength(1);
  });

  it('changes when a non-secret field changes', () => {
    const a = loadConfig(write('c.yaml', baseYaml()));
    const b = loadConfig(write('d.yaml', baseYaml().replace('http://127.0.0.1:9099/decision', 'http://127.0.0.1:9100/decision')));
    expect(b.configVersion).not.toBe(a.configVersion);
    const c = loadConfig(write('e.yaml', baseYaml().replace('decimals: 2', 'decimals: 6')));
    expect(c.configVersion).not.toBe(a.configVersion);
  });

  it('does not change when only a secret changes (env value, env ref name, or literal secret)', () => {
    const a = loadConfig(write('f.yaml', baseYaml()));
    process.env.P6_TEST_HMAC = 'a-different-hmac-value-bbbb';
    try {
      expect(loadConfig(write('g.yaml', baseYaml())).configVersion).toBe(a.configVersion);
    } finally { process.env.P6_TEST_HMAC = ENV.P6_TEST_HMAC; }
    process.env.P6_TEST_HMAC_2 = 'another-hmac-value-cccccc';
    try {
      expect(loadConfig(write('h.yaml', baseYaml().replace('env:P6_TEST_HMAC', 'env:P6_TEST_HMAC_2'))).configVersion).toBe(a.configVersion);
    } finally { delete process.env.P6_TEST_HMAC_2; }
    expect(loadConfig(write('i.yaml', baseYaml().replace('"env:P6_TEST_HMAC"', '"literal-hmac-value-dddddd"'))).configVersion).toBe(a.configVersion);
  });

  it('never hashes a secret value', () => {
    expect(computeConfigVersion({ policy: { hmac_secret: 'x' } })).toBe(computeConfigVersion({ policy: {} }));
    expect(computeConfigVersion({ relay: { evm: [{ chain_id: 1, rpc_url: 'https://k.example/abc' }] } }))
      .toBe(computeConfigVersion({ relay: { evm: [{ chain_id: 1 }] } }));
  });

  it('refuses a relay client key that is short, missing, or reuses the admin key', () => {
    process.env.P6_TEST_RELAY_COMPLIANCE = 'short';
    try { expect(() => loadConfig(write('j.yaml', baseYaml()))).toThrow(/at least 16/); }
    finally { process.env.P6_TEST_RELAY_COMPLIANCE = ENV.P6_TEST_RELAY_COMPLIANCE; }
    process.env.P6_TEST_RELAY_COMPLIANCE = ENV.P6_TEST_ADMIN;
    try { expect(() => loadConfig(write('k.yaml', baseYaml()))).toThrow(/its own secret/); }
    finally { process.env.P6_TEST_RELAY_COMPLIANCE = ENV.P6_TEST_RELAY_COMPLIANCE; }
    expect(() => loadConfig(write('l.yaml', baseYaml().replace('env:P6_TEST_RELAY_COMPLIANCE', 'env:P6_TEST_UNSET_X')))).toThrow(/resolved to nothing/);
    expect(() => loadConfig(write('m.yaml', baseYaml().replace('scopes: [proof, tx, pending]', 'scopes: [everything]')))).toThrow();
  });
});

/* ------------------------------------------------------------------ */
/* 6.4 relay clients                                                   */
/* ------------------------------------------------------------------ */

const TX_RECORD = JSON.parse(readFileSync(new URL('./fixtures/relay-v3-tx-record.json', import.meta.url), 'utf8'));
const HASH = 'c0ffee00'.repeat(8);
const TX_PRINCIPAL = 'acc://fictional-supplier-payments.acme/data';
const UUIDV = '0b9f7f6e-3c1a-4c2b-9a8e-1d2c3b4a5f60';
const OURS = 'acc://fictional-bank-tcl1.acme/book/2';
const COMPLIANCE_KEY = 'compliance-client-test-key';
const TREASURY_KEY = 'treasury-client-test-key-0';
const GOV_KEY = 'governance-test-key-000000';
const GW_KEY = 'gateway-test-key-00000000';

function listen(s: http.Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as { port: number }).port)));
}
function call(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string) {
  return new Promise<{ status: number; json: any }>((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => resolve({ status: res.statusCode!, json: t ? JSON.parse(t) : null }));
    });
    r.on('error', reject);
    if (body !== undefined) r.write(body);
    r.end();
  });
}

const upstreamCalls: string[] = [];
const gw = http.createServer((req, res) => {
  upstreamCalls.push(`gw ${req.url}`);
  if (req.headers['x-api-key'] !== GW_KEY) { res.writeHead(401); return res.end('{}'); }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ path: req.url }));
});
const rpc = http.createServer((req, res) => {
  let t = ''; req.on('data', (c) => (t += c)); req.on('end', () => {
    upstreamCalls.push(`rpc ${t}`);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x' + '0'.repeat(63) + '1' }));
  });
});


const govCalls: Array<{ op: KeyPageOp; page: string }> = [];
let port = 0;
let server: http.Server;
const PENDING: PolicyRequest = { requestId: 'r1', txHash: HASH, account: 'acc://fictional-customer-tcl1.acme/intents', actionSummary: 'FICTIONAL', expiresAt: '2026-09-14T00:00:00Z', bodyType: 'writeData' };

beforeAll(async () => {
  const gwPort = await listen(gw);
  const rpcPort = await listen(rpc);
  const deps: RelayClientsDeps = {
    clients: [
      { name: 'compliance-decision', key: COMPLIANCE_KEY, scopes: ['proof', 'tx', 'pending'] },
      { name: 'treasury-decision', key: TREASURY_KEY, scopes: ['governance'] },
    ],
    reservedKeys: ['admin-test-key-0000000', GOV_KEY],
    query: async (scope) => {
      upstreamCalls.push(`acc ${scope}`);
      if (scope.startsWith(`acc://${HASH}@`)) return TX_RECORD;
      throw new Error('not found');
    },
    gateway: { url: `http://127.0.0.1:${gwPort}`, apiKey: GW_KEY },
    evm: [{ chainId: 84532, rpcUrl: `http://127.0.0.1:${rpcPort}` }],
    getPolicyRequest: async (h) => (h === HASH ? PENDING : undefined),
    governanceKey: GOV_KEY,
    pages: () => [OURS],
    applyKeyPageOp: async (op, page): Promise<KeyPageResult> => {
      govCalls.push({ op, page });
      const st = { version: 1, threshold: 1, keyHashes: [], entries: [] } as unknown as KeyPageResult['before'];
      return { ok: true, op: op.op, submitted: [`acc://${'cc'.repeat(32)}@fictional-bank-tcl1.acme/book/2`], before: st, after: st };
    },
    logger: silent,
  };
  server = createServer({
    relayClients: createRelayClientsHandler(deps), adminApiKey: 'admin-test-key-0000000',
    orchestrator: {} as any, store: {} as any, keyring: {} as any, accumulate: {} as any, pause: { paused: false }, logger: silent,
  });
  port = await listen(server);
});
afterAll(() => { server?.close(); gw.close(); rpc.close(); });
afterEach(() => { upstreamCalls.length = 0; govCalls.length = 0; });

const C = { 'x-relay-client': 'compliance-decision', 'x-api-key': COMPLIANCE_KEY };
const T = { 'x-relay-client': 'treasury-decision', 'x-api-key': TREASURY_KEY };

describe('relay clients: auth and scopes', () => {
  it('401 for unknown client, wrong key, missing headers, or another client\'s key — nothing upstream', async () => {
    for (const h of [{}, { 'x-relay-client': 'nobody', 'x-api-key': COMPLIANCE_KEY }, { 'x-relay-client': 'compliance-decision', 'x-api-key': TREASURY_KEY },
      { 'x-relay-client': 'compliance-decision' }, { 'x-api-key': COMPLIANCE_KEY }, { 'x-relay-client': 'compliance-decision', 'x-api-key': 'admin-test-key-0000000' }]) {
      expect((await call(port, 'GET', `/relay/proof/tx/${HASH}`, h as Record<string, string>)).status).toBe(401);
    }
    expect(upstreamCalls).toEqual([]);
  });

  it('403 when the client lacks the scope', async () => {
    expect((await call(port, 'GET', `/relay/proof/tx/${HASH}`, T)).status).toBe(403);
    expect((await call(port, 'GET', `/relay/pending/${HASH}`, T)).status).toBe(403);
    expect((await call(port, 'POST', '/relay/governance', { ...C, 'x-governance-key': GOV_KEY }, '{}')).status).toBe(403);
    expect(upstreamCalls).toEqual([]);
  });

  it('refuses a client key that is short or equals a reserved credential', () => {
    const base = { reservedKeys: [GOV_KEY], query: async () => ({}), evm: [], getPolicyRequest: async () => undefined, pages: () => [], logger: silent };
    expect(() => createRelayClientsHandler({ ...base, clients: [{ name: 'a', key: 'short', scopes: ['tx'] }] })).toThrow(/16/);
    expect(() => createRelayClientsHandler({ ...base, clients: [{ name: 'a', key: GOV_KEY, scopes: ['tx'] }] })).toThrow(/must not equal/);
  });

  it('the admin key does not open /relay, and a relay client key does not open admin routes', async () => {
    expect((await call(port, 'GET', `/relay/pending/${HASH}`, { 'x-api-key': 'admin-test-key-0000000' })).status).toBe(401);
    expect((await call(port, 'GET', '/v1/config/version', { 'x-api-key': COMPLIANCE_KEY })).status).toBe(401);
  });
});

describe('relay clients: routes', () => {
  it('proxies proof and receipt reads to the exact gateway paths, never returning the gateway key', async () => {
    const p = await call(port, 'GET', `/relay/proof/tx/${HASH.toUpperCase()}`, C);
    expect(p).toMatchObject({ status: 200, json: { path: `/v1/proof/tx/${HASH}` } });
    expect((await call(port, 'GET', `/relay/proof/${UUIDV}/bundle`, C)).json).toEqual({ path: `/v1/proof/${UUIDV}/bundle` });
    expect((await call(port, 'GET', `/relay/tx/${HASH}/receipt`, C)).json).toEqual({ path: `/v1/proof/tx/${HASH}/receipt` });
    expect(JSON.stringify(p.json)).not.toContain(GW_KEY);
  });

  it('validates params: hash, uuid, principal', async () => {
    expect((await call(port, 'GET', '/relay/proof/tx/abc', C)).status).toBe(400);
    expect((await call(port, 'GET', `/relay/proof/tx/${HASH}..`, C)).status).toBe(400);
    expect((await call(port, 'GET', '/relay/proof/not-a-uuid/bundle', C)).status).toBe(400);
    expect((await call(port, 'GET', `/relay/tx/${HASH}/signatures`, C)).status).toBe(400);
    expect((await call(port, 'GET', `/relay/tx/${HASH}/signatures?principal=${encodeURIComponent('acc://x.acme/../y')}`, C)).status).toBe(400);
    expect((await call(port, 'GET', `/relay/tx/${HASH}/signatures?principal=${encodeURIComponent('https://x.example')}`, C)).status).toBe(400);
    expect((await call(port, 'GET', '/relay/pending/zz', C)).status).toBe(400);
    expect(upstreamCalls).toEqual([]);
  });

  it('signatures: txid, status, header, bodyType and signer/book/vote/keyHash/delegators', async () => {
    const r = await call(port, 'GET', `/relay/tx/${HASH}/signatures?principal=${encodeURIComponent(TX_PRINCIPAL)}`, C);
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ txid: TX_RECORD.id, status: 'pending', bodyType: 'writeData', header: { principal: TX_PRINCIPAL, authorities: ['acc://fictional-bank.acme/book', 'acc://fictional-corporate.acme/book'] } });
    expect(r.json.signatures).toEqual([
      { signer: 'acc://fictional-corporate.acme/book/1', book: 'acc://fictional-corporate.acme/book', vote: 'accept', keyHash: expect.stringMatching(/^[0-9a-f]{64}$/), delegators: [] },
      { signer: 'acc://fictional-approver-ada.acme/book/1', book: 'acc://fictional-approver-ada.acme/book', vote: 'reject', keyHash: expect.stringMatching(/^[0-9a-f]{64}$/), delegators: ['acc://fictional-corporate.acme/book/1'] },
      { signer: 'acc://fictional-bank.acme/book/1', book: 'acc://fictional-bank.acme/book', vote: 'abstain', delegators: [] },
    ]);
    expect(upstreamCalls).toEqual([`acc acc://${HASH}@fictional-supplier-payments.acme/data`]);
  });

  it('pending: the stored PolicyRequest, or 404', async () => {
    expect(await call(port, 'GET', `/relay/pending/${HASH}`, C)).toEqual({ status: 200, json: PENDING });
    expect((await call(port, 'GET', `/relay/pending/${'b2'.repeat(32)}`, C)).status).toBe(404);
  });

  it('evm call: eth_call only, validated, unknown chain 404', async () => {
    const to = '0x2d9e724dE974A81E97ee553B3482cAFA6d5Fe46b';
    const r = await call(port, 'POST', '/relay/evm/84532/call', C, JSON.stringify({ to, data: '0x12345678' }));
    expect(r).toEqual({ status: 200, json: { result: '0x' + '0'.repeat(63) + '1' } });
    expect(JSON.parse(upstreamCalls[0].slice(4))).toMatchObject({ method: 'eth_call', params: [{ to, data: '0x12345678' }, 'latest'] });
    expect((await call(port, 'POST', '/relay/evm/1/call', C, JSON.stringify({ to, data: '0x' }))).status).toBe(404);
    expect((await call(port, 'POST', '/relay/evm/84532/call', C, JSON.stringify({ to: 'nope', data: '0x' }))).status).toBe(400);
    expect((await call(port, 'POST', '/relay/evm/84532/call', C, JSON.stringify({ to, data: '0x123' }))).status).toBe(400);
    expect((await call(port, 'GET', '/relay/evm/84532/call', C)).status).toBe(405);
  });
});

describe('relay clients: governance', () => {
  const body = (o: unknown) => JSON.stringify(o);
  const ops = [{ type: 'add-key', keyHash: 'dd'.repeat(32) }, { type: 'set-threshold', threshold: 2 }];

  it('requires the governance key as well as the scope', async () => {
    expect((await call(port, 'POST', '/relay/governance', T, body({ page: OURS, operations: ops }))).status).toBe(401);
    expect((await call(port, 'POST', '/relay/governance', { ...T, 'x-governance-key': 'wrong-governance-key-00' }, body({ page: OURS, operations: ops }))).status).toBe(401);
    expect(govCalls).toEqual([]);
  });

  it('refuses a page this signer does not hold', async () => {
    const r = await call(port, 'POST', '/relay/governance', { ...T, 'x-governance-key': GOV_KEY }, body({ page: 'acc://fictional-firm-tcl1.acme/book/1', operations: ops }));
    expect(r.status).toBe(403);
    expect(govCalls).toEqual([]);
  });

  it('validates operations and refuses unknown types (no rotate-key, no blind ops)', async () => {
    const H = { ...T, 'x-governance-key': GOV_KEY };
    for (const operations of [[], [{ type: 'rotate-key', newKeyHash: 'dd'.repeat(32) }], [{ type: 'add-key', keyHash: 'xyz' }], [{ type: 'set-threshold', threshold: 0 }], [{ type: 'add-delegate', delegate: 'https://x' }], 'nope']) {
      expect((await call(port, 'POST', '/relay/governance', H, body({ page: OURS, operations }))).status).toBe(400);
    }
    expect((await call(port, 'POST', '/relay/governance', H, body({ page: 'not-a-url', operations: ops }))).status).toBe(400);
    expect(govCalls).toEqual([]);
  });

  it('applies typed ops to our own page and returns { txid, status }', async () => {
    const r = await call(port, 'POST', '/relay/governance', { ...T, 'x-governance-key': GOV_KEY }, body({ page: OURS.toUpperCase().replace('ACC://', 'acc://'), operations: ops }));
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ txid: `acc://${'cc'.repeat(32)}@fictional-bank-tcl1.acme/book/2`, status: 'confirmed' });
    expect(govCalls).toEqual([{ op: { op: 'add-key', keyHash: 'dd'.repeat(32) }, page: OURS }, { op: { op: 'set-threshold', threshold: 2 }, page: OURS }]);
  });
});
