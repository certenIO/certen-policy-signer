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
import { MAX_DELEGATE_BOOKS } from '../src/binding/relay-routes.js';
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
  node.book(`${GRANTOR}/book`, [{ keyHashes: ['aa'.repeat(32)], threshold: 1 }, { keyHashes: ['bb'.repeat(32), 'cc'.repeat(32)], delegates: ['acc://fic-risk.acme/risk'], threshold: 2, rejectThreshold: 1, responseThreshold: 2, version: 4 }]);
  node.book('acc://fic-risk.acme/risk', [{ keyHashes: ['dd'.repeat(32), 'ee'.repeat(32)], threshold: 2, version: 2 }]);
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

  it('GET /relay/keybook/:book -> { pages: [Page], delegateBooks } (the quorum roster; DAX-F167a: rejectThreshold 0 = the page sets none; DAX-F170: each page its version, each delegate book its pages), a page URL is refused', async () => {
    const { call } = await start();
    expect((await call(`/relay/keybook/${enc(`${GRANTOR}/book`)}`)).json).toEqual({
      pages: [
        { url: `${GRANTOR}/book/1`, version: 1, keyHashes: ['aa'.repeat(32)], delegates: [], threshold: 1, rejectThreshold: 0, responseThreshold: 0, entries: [{ keyHash: 'aa'.repeat(32) }] },
        { url: `${GRANTOR}/book/2`, version: 4, keyHashes: ['bb'.repeat(32), 'cc'.repeat(32)], delegates: ['acc://fic-risk.acme/risk'], threshold: 2, rejectThreshold: 1, responseThreshold: 2, entries: [{ keyHash: 'bb'.repeat(32) }, { keyHash: 'cc'.repeat(32) }, { delegate: 'acc://fic-risk.acme/risk' }] },
      ],
      delegateBooks: {
        'acc://fic-risk.acme/risk': { pages: [{ url: 'acc://fic-risk.acme/risk/1', version: 2, keyHashes: ['dd'.repeat(32), 'ee'.repeat(32)], delegates: [], threshold: 2, rejectThreshold: 0, responseThreshold: 0, entries: [{ keyHash: 'dd'.repeat(32) }, { keyHash: 'ee'.repeat(32) }] }] },
      },
    });
    expect((await call(`/relay/keybook/${enc(`${GRANTOR}/book/1`)}`)).status).toBe(400);
  });

  it('DAX-F170 D4: the delegation closure is read transitively, each book once, a cycle closes on the book already read; a book with no delegate answers delegateBooks {}', async () => {
    const { call, node } = await start();
    // fic-risk's page delegates on to fic-ops, whose page delegates back to the grantor book (a cycle the chain allows: only self-delegation is refused)
    node.book('acc://fic-risk.acme/risk', [{ keyHashes: ['dd'.repeat(32)], delegates: ['acc://fic-ops.acme/ops'], threshold: 2 }]);
    node.book('acc://fic-ops.acme/ops', [{ keyHashes: ['ee'.repeat(32)], threshold: 1 }, { keyHashes: [], delegates: [`${GRANTOR}/book`], threshold: 1, version: 7 }]);
    const r = await call(`/relay/keybook/${enc(`${GRANTOR}/book`)}`);
    expect(r.status).toBe(200);
    expect(Object.keys(r.json.delegateBooks).sort()).toEqual([`${GRANTOR}/book`, 'acc://fic-ops.acme/ops', 'acc://fic-risk.acme/risk']);
    expect(r.json.delegateBooks[`${GRANTOR}/book`].pages).toEqual(r.json.pages);
    expect(r.json.delegateBooks['acc://fic-ops.acme/ops'].pages[1]).toMatchObject({ version: 7, entries: [{ delegate: `${GRANTOR}/book` }] });
    // each book read once: one book query and one query per page
    expect(node.calls.filter((c) => c === 'acc://fic-ops.acme/ops')).toHaveLength(1);
    expect(node.calls.filter((c) => c === `${GRANTOR}/book`)).toHaveLength(1);
    node.book('acc://fic-plain.acme/book', [{ keyHashes: ['ff'.repeat(32)], threshold: 1 }]);
    expect((await call(`/relay/keybook/${enc('acc://fic-plain.acme/book')}`)).json.delegateBooks).toEqual({});
  });

  it('DAX-F170 D4: ANY unreadable read in the closure makes the whole roster unreadable (a missing delegate book, an account that is not a book, a bad delegate page, a nested one), never a partial map', async () => {
    const cases: Array<(n: FakeNode) => void> = [
      (n) => { n.accounts.delete('acc://fic-risk.acme/risk'); },
      (n) => { n.accounts.get('acc://fic-risk.acme/risk')!.type = 'liteIdentity'; },
      (n) => { n.accounts.get('acc://fic-risk.acme/risk/1')!.version = undefined; },
      (n) => { n.down.add('acc://fic-risk.acme/risk/1'); },
      (n) => { n.book('acc://fic-risk.acme/risk', [{ keyHashes: ['dd'.repeat(32)], delegates: ['acc://fic-gone.acme/book'], threshold: 1 }]); },
      (n) => { n.book('acc://fic-risk.acme/risk', [{ keyHashes: ['dd'.repeat(32)], delegates: ['acc://fic-ops.acme/ops/1'], threshold: 1 }]); n.book('acc://fic-ops.acme/ops', [{ keyHashes: ['ee'.repeat(32)], threshold: 1 }]); },
    ];
    for (const mut of cases) {
      const { call, node } = await start();
      mut(node);
      const r = await call(`/relay/keybook/${enc(`${GRANTOR}/book`)}`);
      expect(r.status).toBe(502);
      expect(r.json).toEqual({ error: 'unreadable' });
    }
  });

  it('DAX-F170 D4: a closure of more than MAX_DELEGATE_BOOKS books is unreadable, never truncated', async () => {
    // fic-risk, then a line of `n` more books, each delegating to the next
    const line = async (n: number) => {
      const { call, node } = await start();
      const chain = Array.from({ length: n }, (_, i) => `acc://fic-d${i}.acme/book`);
      node.book('acc://fic-risk.acme/risk', [{ keyHashes: ['dd'.repeat(32)], delegates: [chain[0]!], threshold: 1 }]);
      chain.forEach((b, i) => node.book(b, [{ keyHashes: ['ee'.repeat(32)], delegates: i + 1 < chain.length ? [chain[i + 1]!] : [], threshold: 1 }]));
      return call(`/relay/keybook/${enc(`${GRANTOR}/book`)}`);
    };
    expect((await line(MAX_DELEGATE_BOOKS)).status).toBe(502); // 1 + 64 books
    const r = await line(MAX_DELEGATE_BOOKS - 1); // 1 + 63 books: exactly the bound
    expect(r.status).toBe(200);
    expect(Object.keys(r.json.delegateBooks)).toHaveLength(MAX_DELEGATE_BOOKS);
  });

  it('DAX-F170 D9: an emptied page past the first is answered (threshold 0, no entries) and the book stays readable', async () => {
    const { call, node } = await start();
    node.book('acc://fic-risk.acme/risk', [{ keyHashes: ['dd'.repeat(32)], threshold: 1 }, { keyHashes: [], threshold: 0, version: 5 }]);
    const r = await call(`/relay/keybook/${enc(`${GRANTOR}/book`)}`);
    expect(r.status).toBe(200);
    expect(r.json.delegateBooks['acc://fic-risk.acme/risk'].pages[1]).toEqual({ url: 'acc://fic-risk.acme/risk/2', version: 5, keyHashes: [], delegates: [], threshold: 0, rejectThreshold: 0, responseThreshold: 0, entries: [] });
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

  it('DAX-F131: the authority set of a transaction principal account (a payer data account) is served, the ENABLED authorities only', async () => {
    const { call, node } = await start();
    const PAYER = 'acc://harbor-mfg.acme/data';
    const acct = node.dataAccount(PAYER, ['acc://harbor-mfg.acme/book', 'acc://fdb-compliance.acme/book', 'acc://fdb-old.acme/book', 'acc://fdb-risk.acme/book']);
    acct.disabled = ['acc://fdb-old.acme/book']; // listed by the node with disabled: true
    const r = await call(`/relay/authorities/${enc(PAYER)}`);
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ authorities: ['acc://harbor-mfg.acme/book', 'acc://fdb-compliance.acme/book', 'acc://fdb-risk.acme/book'] });
    expect((await call(`/relay/data/${enc(PAYER)}`)).status).toBe(400); // still not a generic chain reader: only the authority set
    expect((await call(`/relay/history/${enc(PAYER)}`)).status).toBe(400);
  });

  it("AGT-2: the principal's certen-mandates account is served like the other CERTEN data accounts (data, history, authorities, chainlen)", async () => {
    const { call, node } = await start();
    const MANDATES = `${GRANTOR}/certen-mandates`;
    node.dataAccount(MANDATES, [`${GRANTOR}/book`]);
    node.write(MANDATES, [new Uint8Array([7]), new Uint8Array([8])], 1_800_000_100);
    const d = await call(`/relay/data/${enc(MANDATES)}`);
    expect([d.status, d.json.entries.length, d.json.entries[0]?.elements]).toEqual([200, 1, ['07', '08']]);
    expect((await call(`/relay/history/${enc(MANDATES)}`)).status).toBe(200);
    expect((await call(`/relay/authorities/${enc(MANDATES)}`)).json).toEqual({ authorities: [`${GRANTOR}/book`] });
    const before = (await call(`/relay/chainlen/${enc(MANDATES)}`)).json.length;
    node.write(MANDATES, [new Uint8Array([9])], 1_800_000_200); // a withdrawal: the main chain grows by one
    expect((await call(`/relay/chainlen/${enc(MANDATES)}`)).json).toEqual({ length: before + 1 });
    expect((await call(`/relay/data/${enc(`${GRANTOR}/certen-mandatesx`)}`)).status).toBe(400);
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
    expect((await call(`/relay/authorities/${enc(`${GRANTOR}/book/1`)}`)).status).toBe(400); // a key page has no authority set (DAX-F131 opened only accounts)
    expect((await call(`/relay/chainlen/${enc(`${GRANTOR}/some-other-data-account`)}`)).status).toBe(400);
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
