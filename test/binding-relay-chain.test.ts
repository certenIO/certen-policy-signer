/**
 * The relay routes the Console's reader needs (DAX4C-F5), scope `chain` of the decision-service relay: GET only, read-only, v3 only,
 * strictly validated, served through the SAME read cache as the signer's decision binding. FICTIONAL accounts, a fake node.
 */
import { afterEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import pino from 'pino';
import { createChainWorld } from '../src/binding/chain-world.js';
import { ReadCache } from '../src/binding/read-cache.js';
import { createRelayClientsHandler } from '../src/relay-clients.js';
import { FakeNode } from './support/fake-node.js';

const silent = pino({ level: 'silent' });
const GRANTOR = 'acc://fic-grantor.acme';
const GRANTS = `${GRANTOR}/certen-grants`;
const KEY = 'console-client-key-0123456789';
const NOKEY = 'proof-only-client-key-0123456789';
const servers: http.Server[] = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });

function serve(handler: ReturnType<typeof createRelayClientsHandler>): Promise<string> {
  const server = http.createServer((req, res) => { void handler(req, res, new URL(req.url ?? '/', 'http://localhost')); });
  servers.push(server);
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}
const baseDeps = { reservedKeys: [], query: async () => ({}), evm: [], getPolicyRequest: async () => undefined, pages: () => [], logger: silent };

async function start() {
  const node = new FakeNode();
  node.dataAccount(GRANTS, [`${GRANTOR}/book`]);
  node.write(GRANTS, [new Uint8Array([1, 2, 3]), new Uint8Array([0xab])], 1_800_000_000);
  node.write(GRANTS, [new Uint8Array([9])], null); // an entry whose record carries no executing block: no chain time to ask for
  node.identity('acc://agent-one.fic-grantor.acme', ['acc://agent-one.fic-grantor.acme/book']);
  node.book(`${GRANTOR}/book`, [{ keyHashes: ['aa'.repeat(32)], threshold: 1 }, { keyHashes: ['bb'.repeat(32), 'cc'.repeat(32)], delegates: ['acc://fic-risk.acme/risk'], threshold: 2 }]);
  const cache = new ReadCache(node.query);
  const base = await serve(createRelayClientsHandler({
    ...baseDeps, clients: [{ name: 'console', key: KEY, scopes: ['chain'] }, { name: 'proof-only', key: NOKEY, scopes: ['proof'] }], chainReader: () => cache.evaluation(),
  }));
  const call = async (path: string, over: { method?: string; client?: string; key?: string } = {}) => {
    const r = await fetch(base + path, { method: over.method ?? 'GET', headers: { 'x-relay-client': over.client ?? 'console', 'x-api-key': over.key ?? KEY } });
    return { status: r.status, json: (await r.json()) as any, headers: r.headers };
  };
  return { node, cache, call };
}
const enc = (u: string): string => encodeURIComponent(u);

describe('the chain relay routes (GET only, strictly validated)', () => {
  it('GET /relay/data/:account -> { entries: [{ txId, time?, elements: [hex] }] }, in chain order, `time` omitted when the node gave none', async () => {
    const { call } = await start();
    const r = await call(`/relay/data/${enc(GRANTS)}`);
    expect(r.status).toBe(200);
    expect(Object.keys(r.json)).toEqual(['entries']);
    expect(r.json.entries).toHaveLength(2);
    expect(r.json.entries[0]).toMatchObject({ time: 1_800_000_000, elements: ['010203', 'ab'] });
    expect(r.json.entries[0].txId).toMatch(/^acc:..[0-9a-f]{64}@/);
    expect('time' in r.json.entries[1]).toBe(false); // never invented
    expect(r.json.entries[1].elements).toEqual(['09']);
  });

  it('GET /relay/authorities/:account -> { authorities: [url] } for a CERTEN data account and for an ADI', async () => {
    const { call } = await start();
    expect((await call(`/relay/authorities/${enc(GRANTS)}`)).json).toEqual({ authorities: [`${GRANTOR}/book`] });
    expect((await call(`/relay/authorities/${enc('acc://agent-one.fic-grantor.acme')}`)).json).toEqual({ authorities: ['acc://agent-one.fic-grantor.acme/book'] });
  });

  it('GET /relay/history/:account -> { types, incomplete } from the creation', async () => {
    const { call } = await start();
    expect((await call(`/relay/history/${enc(GRANTS)}`)).json).toEqual({ types: ['createDataAccount', 'writeData', 'writeData'], incomplete: false });
  });

  it('GET /relay/keybook/:book -> { pages: [{ url, keyHashes, delegates, threshold }] } (the quorum roster), a page URL is refused', async () => {
    const { call } = await start();
    expect((await call(`/relay/keybook/${enc(`${GRANTOR}/book`)}`)).json).toEqual({
      pages: [
        { url: `${GRANTOR}/book/1`, keyHashes: ['aa'.repeat(32)], delegates: [], threshold: 1 },
        { url: `${GRANTOR}/book/2`, keyHashes: ['bb'.repeat(32), 'cc'.repeat(32)], delegates: ['acc://fic-risk.acme/risk'], threshold: 2 },
      ],
    });
    expect((await call(`/relay/keybook/${enc(`${GRANTOR}/book/1`)}`)).status).toBe(400);
  });

  it('GET /relay/chainlen/:account -> { length } is ONE node query, and moves when the chain does', async () => {
    const { call, node } = await start();
    const before = node.calls.length;
    const a = await call(`/relay/chainlen/${enc(GRANTS)}`);
    expect(a.status).toBe(200);
    expect(a.json).toEqual({ length: 3 });
    expect(node.calls.length - before).toBe(1);
    expect(a.headers.get('x-reader-queries')).toBe('1');
    node.write(GRANTS, [new Uint8Array([5])], 1_800_000_200);
    expect((await call(`/relay/chainlen/${enc(GRANTS)}`)).json).toEqual({ length: 4 });
  });

  it('chainlen has the same account whitelist and the same refusals as data and history', async () => {
    const { call, node } = await start();
    const before = node.calls.length;
    expect((await call(`/relay/chainlen/${enc(`${GRANTOR}/some-other-data-account`)}`)).status).toBe(400);
    expect((await call(`/relay/chainlen/${enc('acc://agent-one.fic-grantor.acme')}`)).status).toBe(400);
    expect((await call(`/relay/chainlen/${enc('acc://FIC-GRANTOR.acme/certen-grants')}`)).status).toBe(400);
    expect((await call(`/relay/chainlen/${enc(`${GRANTOR}/book/1`)}`)).status).toBe(400);
    expect((await call('/relay/chainlen/%E0%A4%A')).status).toBe(400);
    expect((await call(`/relay/chainlen/${enc(GRANTS)}?x=1`)).status).toBe(400);
    for (const method of ['POST', 'PUT', 'DELETE']) expect((await call(`/relay/chainlen/${enc(GRANTS)}`, { method })).status).toBe(405);
    expect((await call(`/relay/chainlen/${enc(GRANTS)}`, { client: 'proof-only', key: NOKEY })).status).toBe(403);
    expect((await call(`/relay/chainlen/${enc(GRANTS)}`, { key: 'wrong-key-wrong-key-wrong' })).status).toBe(401);
    expect(node.calls.length).toBe(before); // not one refused request reached the node
    node.down.add(GRANTS);
    const down = await call(`/relay/chainlen/${enc(GRANTS)}`);
    expect(down.status).toBe(502);
    expect(down.json).toEqual({ error: 'unreadable' });
    node.down.delete(GRANTS);
    node.accounts.delete(GRANTS);
    expect((await call(`/relay/chainlen/${enc(GRANTS)}`)).status).toBe(502);
  });

  it('refuses what is not a CERTEN account, a malformed or upper-case URL, a raw slash, any query string, any method but GET', async () => {
    const { call, node } = await start();
    const before = node.calls.length;
    expect((await call(`/relay/data/${enc(`${GRANTOR}/some-other-data-account`)}`)).status).toBe(400); // not a generic chain reader
    expect((await call(`/relay/history/${enc('acc://agent-one.fic-grantor.acme')}`)).status).toBe(400);
    expect((await call(`/relay/authorities/${enc(`${GRANTOR}/some-other-data-account`)}`)).status).toBe(400);
    expect((await call(`/relay/data/${enc('acc://FIC-GRANTOR.acme/certen-grants')}`)).status).toBe(400);
    expect((await call(`/relay/data/${enc('not a url')}`)).status).toBe(400);
    expect((await call(`/relay/data/${enc('acc://x.acme/../certen-grants')}`)).status).toBe(400);
    expect((await call('/relay/data/%E0%A4%A')).status).toBe(400); // not valid percent-encoding
    expect((await call('/relay/data/acc://fic-grantor.acme/certen-grants')).status).not.toBe(200); // a raw slash is not one segment
    expect((await call(`/relay/data/${enc(GRANTS)}?x=1`)).status).toBe(400);
    for (const method of ['POST', 'PUT', 'DELETE']) expect((await call(`/relay/data/${enc(GRANTS)}`, { method })).status).toBe(405);
    expect(node.calls.length).toBe(before); // not one refused request reached the node
  });

  it('needs its own credential and the scope `chain`', async () => {
    const { call } = await start();
    expect((await call(`/relay/data/${enc(GRANTS)}`, { key: 'wrong-key-wrong-key-wrong' })).status).toBe(401);
    expect((await call(`/relay/data/${enc(GRANTS)}`, { client: 'proof-only', key: NOKEY })).status).toBe(403);
  });

  it('answers 502 `unreadable` when the node cannot give the fact: never an empty answer', async () => {
    const { call, node } = await start();
    node.down.add(GRANTS);
    const r = await call(`/relay/data/${enc(GRANTS)}`);
    expect(r.status).toBe(502);
    expect(r.json).toEqual({ error: 'unreadable' });
  });

  it('serves through the SAME cache as the decision binding, and reports what a read cost (x-reader-* headers)', async () => {
    const { call, node, cache } = await start();
    const a = await call(`/relay/data/${enc(GRANTS)}`);
    expect(Number(a.headers.get('x-reader-queries'))).toBeGreaterThan(1);
    const before = node.calls.length;
    const b = await call(`/relay/data/${enc(GRANTS)}`);
    expect(node.calls.length - before).toBe(1); // the chain-length probe only
    expect(b.headers.get('x-reader-queries')).toBe('1');
    expect(Number(b.headers.get('x-reader-cache-hits'))).toBe(1);
    expect(cache.totals().cacheHits).toBeGreaterThan(0);
    // the signer's own evaluation reads the same facts from the same cache (the grants account is already cached)
    const w = createChainWorld({ evaluation: () => cache.evaluation(), nowSeconds: () => 1_800_000_500 });
    const seen = node.calls.length;
    const seenLog = node.log.length;
    await w.establish({ grantorAdi: GRANTOR, grantorBook: `${GRANTOR}/book`, grantId: 'x', asserted: null });
    // the entries of the grants account were not re-read: no block query, never the data chain. The relay read cached the entries only, so the
    // signer's evaluation reads the HISTORY of the same main chain once (one page); the entries and the history are separate facts
    const grantsAfter = node.log.slice(seenLog).filter((x) => x.scope === GRANTS);
    expect(grantsAfter.filter((x) => x.query?.queryType === 'block' || x.query?.queryType === 'data')).toEqual([]);
    expect(grantsAfter.filter((x) => x.query?.queryType === 'chain' && x.query.range.count > 1)).toHaveLength(1);
    expect(node.calls.length - seen).toBeGreaterThan(0);
  });

  it('is 503 when no reader is wired', async () => {
    const base = await serve(createRelayClientsHandler({ ...baseDeps, clients: [{ name: 'console', key: KEY, scopes: ['chain'] }] }));
    const r = await fetch(`${base}/relay/data/${enc(GRANTS)}`, { headers: { 'x-relay-client': 'console', 'x-api-key': KEY } });
    expect(r.status).toBe(503);
  });
});
