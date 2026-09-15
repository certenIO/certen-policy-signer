/**
 * Read-only relay (src/relay.ts). FICTIONAL Business Transaction Controls lab, runbook Phase 5.3, decision P2.
 *
 * Network is mocked the way gateway-seam.test.ts does it: real loopback HTTP servers standing in for the
 * gateway and an EVM RPC, recording exactly what reached them — so "nothing was forwarded" is observed,
 * not assumed. Accumulate is the injected `query` seam. All tokens are obviously fake.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import http from 'node:http';
import crypto from 'node:crypto';
import { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { createRelayHandler, createRelayServer, bearerMatches, checkRpc, EVM_READ_METHODS } from '../src/relay.js';
import { normalizeTxRecord } from '../src/accumulate/raw-client.js';
import { createServer } from '../src/server.js';
import { loadConfig, validateRelay, Config } from '../src/config.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MemoryStore } from '../src/store/store.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';

const silent = pino({ level: 'silent' });
const TOKEN = 'test-relay-token';
const GATEWAY_KEY = 'test-gateway-api-key-not-real';
const AUTH = { authorization: `Bearer ${TOKEN}` };
const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/relay-v3-tx-record.json', import.meta.url), 'utf8'));
const TXID = FIXTURE.id as string;
const HASH = 'ab'.repeat(32);
const UUID = '0b7d3f7e-1c2a-4e5b-9f00-123456789abc';

type Seen = { method: string; url: string; headers: http.IncomingHttpHeaders; body: string };

function stub(handler: (s: Seen, res: http.ServerResponse) => void) {
  const seen: Seen[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const s = { method: req.method!, url: req.url!, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') };
      seen.push(s);
      handler(s, res);
    });
  });
  return { server, seen };
}
const listen = (s: http.Server) => new Promise<number>((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)));

function call(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string; json: any }> {
  return new Promise((resolve, reject) => {
    const h = { ...headers, ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) } : {}) };
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: h }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json: any; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode!, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    if (body !== undefined) r.write(body);
    r.end();
  });
}

const gw = stub((s, res) => {
  if (s.headers['x-api-key'] !== GATEWAY_KEY) { res.writeHead(401, { 'content-type': 'application/json' }); return res.end('{"error":"unauthorized"}'); }
  if (s.url.endsWith('/receipt')) { res.writeHead(404, { 'content-type': 'application/json' }); return res.end('{"error":"receipt not ready"}'); }
  if (s.url.includes('echo-key')) { res.writeHead(200); return res.end(JSON.stringify({ leaked: GATEWAY_KEY })); }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ path: s.url, proof: { requiredLevel: 'L4' } }));
});
const rpc = stub((s, res) => {
  const parsed = JSON.parse(s.body);
  const answer = (r: any) => ({ jsonrpc: '2.0', id: r.id, result: '0x14a34' });
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(Array.isArray(parsed) ? parsed.map(answer) : answer(parsed)));
});

let gwPort = 0, rpcPort = 0, relayPort = 0;
let relayServer: http.Server;
const query = vi.fn();

beforeAll(async () => {
  gwPort = await listen(gw.server);
  rpcPort = await listen(rpc.server);
  const handler = createRelayHandler({
    token: TOKEN, query, logger: silent,
    gateway: { url: `http://127.0.0.1:${gwPort}/`, apiKey: GATEWAY_KEY },
    evm: [{ chainId: 84532, rpcUrl: `http://127.0.0.1:${rpcPort}/v2/test-provider-path` }],
  });
  relayServer = createRelayServer(handler, silent);
  relayPort = await listen(relayServer);
});
afterAll(() => { gw.server.close(); rpc.server.close(); relayServer.close(); });
beforeEach(() => { gw.seen.length = 0; rpc.seen.length = 0; query.mockReset(); });

describe('relay auth', () => {
  it('bearerMatches: exact token only, compared over equal-length digests', () => {
    expect(bearerMatches(`Bearer ${TOKEN}`, TOKEN)).toBe(true);
    expect(bearerMatches(`Bearer ${TOKEN}x`, TOKEN)).toBe(false);
    expect(bearerMatches('Bearer t', TOKEN)).toBe(false);          // different length: still goes through the compare
    expect(bearerMatches(TOKEN, TOKEN)).toBe(false);               // no scheme
    expect(bearerMatches(`bearer  ${TOKEN}`, TOKEN)).toBe(false);
    expect(bearerMatches(undefined, TOKEN)).toBe(false);
    expect(bearerMatches(`Bearer ${TOKEN}`, '')).toBe(false);
  });

  it('every relay route is 401 without the token, and nothing upstream is touched', async () => {
    const paths: Array<[string, string]> = [
      ['GET', `/v1/relay/accumulate/tx?id=${encodeURIComponent(TXID)}`],
      ['GET', '/v1/relay/accumulate/account?url=acc://fictional-bank.acme/book/1'],
      ['GET', `/v1/relay/gateway/proof/tx/${HASH}`],
      ['GET', `/v1/relay/gateway/transaction/${UUID}`],
      ['POST', '/v1/relay/evm/84532'],
    ];
    for (const [m, p] of paths) {
      const variants: Record<string, string>[] = [{}, { authorization: 'Bearer wrong-token-000000' }, { 'x-api-key': TOKEN }];
      for (const h of variants) {
        const r = await call(relayPort, m, p, h, m === 'POST' ? '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' : undefined);
        expect(r.status).toBe(401);
      }
    }
    expect(query).not.toHaveBeenCalled();
    expect(gw.seen).toHaveLength(0);
    expect(rpc.seen).toHaveLength(0);
  });

  it('sends no CORS headers and refuses to build without a token', async () => {
    const r = await call(relayPort, 'OPTIONS', `/v1/relay/gateway/proof/tx/${HASH}`, { origin: 'https://evil.example', ...AUTH });
    expect(Object.keys(r.headers).some((k) => k.startsWith('access-control-'))).toBe(false);
    expect(() => createRelayHandler({ token: '', query, logger: silent, evm: [] })).toThrow(/token/);
  });
});

describe('relay: accumulate', () => {
  it('normalizes signatures from a recorded v3 response', () => {
    const out = normalizeTxRecord(FIXTURE);
    expect(out).toMatchObject({
      txid: TXID, hash: 'c0ffee00'.repeat(8), status: 'pending', statusNo: 202,
      principal: 'acc://fictional-supplier-payments.acme/data',
      header: {
        principal: 'acc://fictional-supplier-payments.acme/data',
        authorities: ['acc://fictional-bank.acme/book', 'acc://fictional-corporate.acme/book'],
        expireAtTime: '2026-10-01T12:00:00Z', memo: 'FICTIONAL supplier payment SP-0001',
      },
      body: { type: 'writeData' },
    });
    const sha = (h: string) => crypto.createHash('sha256').update(Buffer.from(h, 'hex')).digest('hex');
    // Duplicate dropped; partition (no signer) dropped; unreadable vote "maybe" dropped rather than read as accept.
    expect(out.signatures).toEqual([
      { signer: 'acc://fictional-corporate.acme/book/1', book: 'acc://fictional-corporate.acme/book', type: 'ed25519', vote: 'accept', keyHash: sha('11'.repeat(32)), delegators: [], timestamp: 1790000000001 },
      { signer: 'acc://fictional-approver-ada.acme/book/1', book: 'acc://fictional-approver-ada.acme/book', type: 'ecdsaSha256', vote: 'reject', keyHash: sha('22'.repeat(32)), delegators: ['acc://fictional-corporate.acme/book/1'], timestamp: 1790000000002 },
      { signer: 'acc://fictional-bank.acme/book/1', book: 'acc://fictional-bank.acme/book', type: 'authority', vote: 'abstain', delegators: [] },
    ]);
  });

  it('GET /tx queries the txid and returns the normalized record', async () => {
    query.mockResolvedValue(FIXTURE);
    const r = await call(relayPort, 'GET', `/v1/relay/accumulate/tx?id=${encodeURIComponent(TXID)}`, AUTH);
    expect(r.status).toBe(200);
    expect(query).toHaveBeenCalledWith(TXID);
    expect(r.json.signatures).toHaveLength(3);
    expect(r.headers['cache-control']).toBe('no-store');
  });

  it('rejects malformed ids and non-acc URLs with 400, without querying', async () => {
    for (const id of ['', HASH, `acc://${HASH}`, `acc://abc@fictional.acme`, `https://${HASH}@x.acme`, `acc://${HASH}@a b.acme`, `acc://${HASH}@x.acme?q=1`]) {
      expect((await call(relayPort, 'GET', `/v1/relay/accumulate/tx?id=${encodeURIComponent(id)}`, AUTH)).status).toBe(400);
    }
    for (const u of ['', 'fictional-bank.acme', 'https://fictional-bank.acme', 'acc://user@fictional-bank.acme', 'acc://fictional-bank.acme/../x', 'acc://']) {
      expect((await call(relayPort, 'GET', `/v1/relay/accumulate/account?url=${encodeURIComponent(u)}`, AUTH)).status).toBe(400);
    }
    expect(query).not.toHaveBeenCalled();
  });

  it('GET /account returns the account record; not-found is 404, a failure to ask is 502', async () => {
    const account = { type: 'keyPage', url: 'acc://fictional-bank.acme/book/1', keys: [{ publicKeyHash: '44'.repeat(32) }], acceptThreshold: 2, version: 7 };
    query.mockResolvedValueOnce({ recordType: 'account', account });
    let r = await call(relayPort, 'GET', '/v1/relay/accumulate/account?url=acc://fictional-bank.acme/book/1', AUTH);
    expect(r.status).toBe(200);
    expect(r.json).toEqual(account);
    query.mockRejectedValueOnce(new Error('account acc://nope.acme not found'));
    r = await call(relayPort, 'GET', '/v1/relay/accumulate/account?url=acc://nope.acme', AUTH);
    expect(r.status).toBe(404);
    query.mockRejectedValueOnce(new Error('connect ECONNREFUSED 10.0.0.1:26660'));
    r = await call(relayPort, 'GET', '/v1/relay/accumulate/account?url=acc://nope.acme', AUTH);
    expect(r.status).toBe(502);
    expect(r.text).not.toContain('10.0.0.1');
  });
});

describe('relay: gateway proxy', () => {
  it('proxies the allowlisted paths with the configured key, passing status and body through', async () => {
    const cases: Array<[string, string]> = [
      [`/v1/relay/gateway/proof/tx/${HASH}`, `/v1/proof/tx/${HASH}`],
      [`/v1/relay/gateway/proof/${UUID}`, `/v1/proof/${UUID}`],
      [`/v1/relay/gateway/proof/${UUID}/bundle`, `/v1/proof/${UUID}/bundle`],
      [`/v1/relay/gateway/transaction/${UUID}`, `/v1/transaction/${UUID}`],
    ];
    for (const [from, to] of cases) {
      const r = await call(relayPort, 'GET', `${from}?limit=9&api_key=x`, AUTH);
      expect(r.status).toBe(200);
      expect(r.json.path).toBe(to);                                     // query string not forwarded
      expect(r.json.proof.requiredLevel).toBe('L4');                     // passed through untouched (F5: not evidence)
      expect(r.text).not.toContain(GATEWAY_KEY);
    }
    const receipt = await call(relayPort, 'GET', `/v1/relay/gateway/proof/tx/${HASH}/receipt`, AUTH);
    expect(receipt.status).toBe(404);
    expect(receipt.json).toEqual({ error: 'receipt not ready' });
    expect(gw.seen.every((s) => s.headers['x-api-key'] === GATEWAY_KEY && !s.headers['authorization'])).toBe(true);
  });

  it('refuses paths off the allowlist and bad params without calling the gateway', async () => {
    const notFound = ['/v1/relay/gateway/proof/' + UUID + '/custody', '/v1/relay/gateway/sign', '/v1/relay/gateway/transaction/' + UUID + '/signature', '/v1/relay/gateway/'];
    for (const p of notFound) expect((await call(relayPort, 'GET', p, AUTH)).status).toBe(404);
    const bad = ['/v1/relay/gateway/proof/tx/abc', `/v1/relay/gateway/proof/tx/${HASH}zz`, '/v1/relay/gateway/proof/not-a-uuid', '/v1/relay/gateway/transaction/..%2Fsign', '/v1/relay/gateway/proof/echo-key'];
    for (const p of bad) expect((await call(relayPort, 'GET', p, AUTH)).status).toBe(400);
    expect((await call(relayPort, 'POST', `/v1/relay/gateway/proof/tx/${HASH}`, AUTH, '{}')).status).toBe(405);
    expect(gw.seen).toHaveLength(0);
  });

  it('withholds an upstream body that contains the api key', async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({ echoed: GATEWAY_KEY }), { status: 200 })) as typeof fetch;
    const h = createRelayHandler({ token: TOKEN, query, logger: silent, gateway: { url: 'http://gateway.invalid', apiKey: GATEWAY_KEY }, evm: [], fetchImpl });
    const s = createRelayServer(h, silent);
    const p = await listen(s);
    const r = await call(p, 'GET', `/v1/relay/gateway/proof/${UUID}`, AUTH);
    s.close();
    expect(r.status).toBe(502);
    expect(r.text).not.toContain(GATEWAY_KEY);
  });
});

describe('relay: EVM JSON-RPC', () => {
  const post = (body: unknown, chain = '84532') => call(relayPort, 'POST', `/v1/relay/evm/${chain}`, AUTH, typeof body === 'string' ? body : JSON.stringify(body));

  it('forwards allowlisted single and batch requests', async () => {
    let r = await post({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] });
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ jsonrpc: '2.0', id: 1, result: '0x14a34' });
    r = await post([{ jsonrpc: '2.0', id: 1, method: 'eth_chainId' }, { jsonrpc: '2.0', id: 2, method: 'eth_getTransactionReceipt', params: ['0x' + HASH] }]);
    expect(r.json).toHaveLength(2);
    expect(rpc.seen).toHaveLength(2);
    expect(rpc.seen[0].url).toBe('/v2/test-provider-path');
    expect(r.text).not.toContain('test-provider-path');
  });

  it('refuses a forbidden method with -32601 and forwards nothing', async () => {
    for (const method of ['eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'personal_sign', 'eth_accounts', 'debug_traceTransaction']) {
      const r = await post({ jsonrpc: '2.0', id: 7, method, params: [] });
      expect(r.json.error.code).toBe(-32601);
      expect(r.json.id).toBe(7);
    }
    expect(rpc.seen).toHaveLength(0);
  });

  it('refuses a batch mixing allowed and forbidden methods whole — nothing forwarded', async () => {
    const r = await post([
      { jsonrpc: '2.0', id: 1, method: 'eth_chainId' },
      { jsonrpc: '2.0', id: 2, method: 'eth_sendRawTransaction', params: ['0x00'] },
    ]);
    expect(r.json[1].error.code).toBe(-32601);
    expect(r.json[0].error).toBeDefined();
    expect(r.json[0].result).toBeUndefined();
    expect(rpc.seen).toHaveLength(0);
  });

  it('validates chain, method, body and size', async () => {
    expect((await post({ jsonrpc: '2.0', id: 1, method: 'eth_chainId' }, '1')).status).toBe(404);
    expect((await post({ jsonrpc: '2.0', id: 1, method: 'eth_chainId' }, 'base')).status).toBe(400);
    expect((await call(relayPort, 'GET', '/v1/relay/evm/84532', AUTH)).status).toBe(405);
    expect((await post('{nope')).json.error.code).toBe(-32700);
    expect((await post([])).json.error.code).toBe(-32600);
    expect((await post({ id: 1, method: 'eth_chainId' })).json.error.code).toBe(-32600);
    const big = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: ['x'.repeat(1024 * 1024 + 10)] });
    expect((await post(big)).status).toBe(413);
    expect(rpc.seen).toHaveLength(0);
  });

  it('checkRpc forwards only validated fields', () => {
    const c = checkRpc({ jsonrpc: '2.0', id: 3, method: 'eth_getCode', params: ['0x0', 'latest'], extra: 'dropped' });
    expect(c).toEqual({ forward: { jsonrpc: '2.0', id: 3, method: 'eth_getCode', params: ['0x0', 'latest'] } });
    expect(EVM_READ_METHODS.size).toBe(9);
  });
});

describe('relay mounted on the health/admin server', () => {
  function build(relay?: ReturnType<typeof createRelayHandler>) {
    const acc = new MockAccumulateClient();
    return createServer({
      orchestrator: {} as any, store: new MemoryStore(), keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9))),
      accumulate: acc, pause: { paused: false }, logger: silent, adminApiKey: 'test-admin-key-000', relay,
    });
  }
  it('is 404 when not enabled, and the admin key does not open it', async () => {
    const s = build();
    const p = await listen(s);
    expect((await call(p, 'GET', `/v1/relay/gateway/proof/tx/${HASH}`, AUTH)).status).toBe(404);
    s.close();
    const s2 = build(createRelayHandler({ token: TOKEN, query, logger: silent, evm: [] }));
    const p2 = await listen(s2);
    expect((await call(p2, 'GET', '/v1/relay/accumulate/account?url=acc://x.acme', { 'x-api-key': 'test-admin-key-000' })).status).toBe(401);
    query.mockResolvedValueOnce({ account: { type: 'identity', url: 'acc://x.acme' } });
    expect((await call(p2, 'GET', '/v1/relay/accumulate/account?url=acc://x.acme', AUTH)).status).toBe(200);
    // the relay token is not an admin credential either
    expect((await call(p2, 'GET', '/v1/admin/pubkey', { 'x-api-key': TOKEN })).status).toBe(401);
    s2.close();
  });
});

describe('relay config', () => {
  const base = (relay: unknown): Pick<Config, 'relay' | 'admin'> => ({ relay: { enabled: true, only: false, evm: [], timeout_ms: 1000, ...(relay as object) } as Config['relay'], admin: { api_key: 'test-admin-key-000' } });

  it('refuses an enabled relay without a usable token', () => {
    delete process.env.TEST_RELAY_TOKEN_UNSET;
    expect(() => validateRelay(base({}))).toThrow(/relay.token/);
    expect(() => validateRelay(base({ token: '' }))).toThrow(/relay.token/);
    expect(() => validateRelay(base({ token: '   ' }))).toThrow(/relay.token/);
    expect(() => validateRelay(base({ token: 'env:TEST_RELAY_TOKEN_UNSET' }))).toThrow(/relay.token/);
    expect(() => validateRelay(base({ token: 'short' }))).toThrow(/16/);
    expect(() => validateRelay(base({ token: 'test-admin-key-000' }))).toThrow(/own secret/);
    const ok = base({ token: TOKEN });
    expect(() => validateRelay(ok)).not.toThrow();
    const off = { relay: { enabled: false, evm: [], timeout_ms: 1 }, admin: {} } as unknown as Pick<Config, 'relay' | 'admin'>;
    expect(() => validateRelay(off)).not.toThrow();
  });

  it('resolves env refs and checks gateway key, chains and rpc urls', () => {
    process.env.TEST_RELAY_TOKEN = TOKEN;
    process.env.TEST_RELAY_RPC = 'https://rpc.invalid/v2/test-provider-path';
    const c = base({ token: 'env:TEST_RELAY_TOKEN', evm: [{ chain_id: 84532, rpc_url: 'env:TEST_RELAY_RPC' }] });
    validateRelay(c);
    expect(c.relay.token).toBe(TOKEN);
    expect(c.relay.evm[0].rpc_url).toBe('https://rpc.invalid/v2/test-provider-path');
    expect(() => validateRelay(base({ token: TOKEN, gateway: { url: 'http://g.invalid', api_key: 'env:TEST_RELAY_GW_UNSET' } }))).toThrow(/api_key/);
    expect(() => validateRelay(base({ token: TOKEN, evm: [{ chain_id: 1, rpc_url: 'http://a.invalid' }, { chain_id: 1, rpc_url: 'http://b.invalid' }] }))).toThrow(/twice/);
    expect(() => validateRelay(base({ token: TOKEN, evm: [{ chain_id: 1, rpc_url: 'ws://secret-key@a.invalid' }] }))).toThrow(/^(?!.*secret-key).*http\(s\)/);
    delete process.env.TEST_RELAY_TOKEN; delete process.env.TEST_RELAY_RPC;
  });

  describe('through loadConfig', () => {
    let tmp: string;
    beforeEach(() => { tmp = mkdtempSync(join(tmpdir(), 'certen-relay-')); });
    afterAll(() => { try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
    const write = (relay: string) => {
      const p = join(tmp, 'c.yaml');
      writeFileSync(p, [
        'wallet:', '  org_id: "fictional-bank"', '  accumulate_endpoints: ["http://127.0.0.1:26660/v3"]', '  signer_url: "acc://fictional-bank.acme/book/1"',
        'signer:', '  provider: "local"', '  local:', '    allow_ephemeral: true',
        'policy:', '  url: "http://127.0.0.1:9099/decision"', relay,
      ].join('\n'));
      return p;
    };
    it('defaults to disabled, refuses enabled-without-token and unknown keys', () => {
      expect(loadConfig(write('')).relay.enabled).toBe(false);
      expect(() => loadConfig(write('relay:\n  enabled: true'))).toThrow(/relay.token/);
      expect(() => loadConfig(write(`relay:\n  enabled: true\n  token: "${TOKEN}"\n  methods: ["eth_sendRawTransaction"]`))).toThrow();
      const cfg = loadConfig(write(`relay:\n  enabled: true\n  token: "${TOKEN}"\n  bind: "127.0.0.1:8090"\n  evm:\n    - chain_id: 84532\n      rpc_url: "https://sepolia.base.invalid"`));
      expect(cfg.relay).toMatchObject({ enabled: true, bind: '127.0.0.1:8090', evm: [{ chain_id: 84532 }] });
    });
    it('relay.only boots without any signing scope, and refuses a signer or a missing bind', () => {
      const bare = (relay: string) => {
        const p = join(tmp, 'only.yaml');
        writeFileSync(p, ['wallet:', '  org_id: "fictional-bank-relay"', '  accumulate_endpoints: ["http://127.0.0.1:26660/v3"]',
          'policy:', '  url: "http://127.0.0.1:9/unused"', relay].join('\n'));
        return p;
      };
      const ok = loadConfig(bare(`relay:
  enabled: true
  only: true
  token: "${TOKEN}"
  bind: "127.0.0.1:8090"`));
      expect(ok.relay).toMatchObject({ enabled: true, only: true });
      expect(() => loadConfig(bare(`relay:
  enabled: true
  only: true
  token: "${TOKEN}"`))).toThrow(/relay.only requires/);
      expect(() => loadConfig(write(`relay:
  enabled: true
  only: true
  token: "${TOKEN}"
  bind: "127.0.0.1:8090"`))).toThrow(/relay.only must not/);
      expect(() => loadConfig(bare(''))).toThrow(/signer_url/);
    });
  });
});
