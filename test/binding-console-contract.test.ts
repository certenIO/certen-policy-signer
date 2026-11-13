/**
 * The contract with the Console's reader (DAX-4C). The Console parses every relay answer strictly: an unknown member, a missing member or a
 * value of the wrong type makes its WHOLE read unreadable, and unreadable is a named denial. This test runs the Console's own parsers (copied as
 * fixtures, test/support/console-relay-parsers.ts, pinned to its commit) against what the signer's relay actually answers on the wire, on a fake
 * node in the recorded shapes AND on the recorded real Kermit answers.
 */
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { FakeNode, replayNode } from './support/fake-node.js';
import { parseAuthorities, parseChainLen, parseDataEntries, parseHistory, parseKeybook } from './support/console-relay-parsers.js';
import { closeRelays, enc, serveRelay } from './support/relay-rig.js';

afterEach(closeRelays);

const GRANTOR = 'acc://fic-grantor.acme';
const GRANTS = `${GRANTOR}/certen-grants`;
const REGISTRY = `${GRANTOR}/certen-subjects`;
const SUBJECT = 'acc://agent-one.fic-grantor.acme';
const BOOK = `${GRANTOR}/book`;
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function scene() {
  const node = new FakeNode();
  node.dataAccount(GRANTS, [BOOK]);
  node.write(GRANTS, [new Uint8Array([1, 2, 3]), new Uint8Array([0xab])], 1_800_000_000);
  node.write(GRANTS, [new Uint8Array([9])], 1_800_000_100);
  node.dataAccount(REGISTRY, [BOOK]);
  node.identity(SUBJECT, [`${SUBJECT}/book`]);
  node.book(BOOK, [
    { keyHashes: ['aa'.repeat(32)], threshold: 1 },
    { keyHashes: ['bb'.repeat(32), 'CC'.repeat(32)], delegates: ['acc://fic-risk.acme/risk'], threshold: 2 },
    { keyHashes: [], delegates: ['acc://fic-ops.acme/ops'], threshold: 1 },
  ]);
  return node;
}

describe('every route answers what the Console strict parser accepts (fake node in the recorded shapes)', () => {
  it('data: txId, time and elements, nothing else; the parsed entries are the entries written', async () => {
    const { get } = await serveRelay(scene().query);
    const r = await get(`/relay/data/${enc(GRANTS)}`);
    expect(r.status).toBe(200);
    const parsed = parseDataEntries(r.body);
    expect(parsed).not.toBeNull();
    expect(parsed!.map((e) => e.time)).toEqual([1_800_000_000, 1_800_000_100]);
    expect(parsed![0]!.elements.map(hex)).toEqual(['010203', 'ab']);
    expect(parsed![0]!.txId).toMatch(/^acc:\/\/[0-9a-f]{64}@/);
  });

  it('data of an account with no entry yet: an empty list the Console parses (not a failure)', async () => {
    const { get } = await serveRelay(scene().query);
    expect(parseDataEntries((await get(`/relay/data/${enc(REGISTRY)}`)).body)).toEqual([]);
  });

  it('an entry the node gave no time for is NOT invented: the answer omits `time`, and the Console parser then reads the account as unreadable', async () => {
    const node = scene();
    node.write(GRANTS, [new Uint8Array([7])], null);
    const { get } = await serveRelay(node.query);
    const r = await get(`/relay/data/${enc(GRANTS)}`);
    expect(r.status).toBe(200);
    expect((r.body as { entries: Array<Record<string, unknown>> }).entries[2]).not.toHaveProperty('time');
    expect(parseDataEntries(r.body)).toBeNull(); // fail closed on the Console side: a missing time is a named denial there, never a guess here
  });

  it('authorities (a data account and an ADI) and history', async () => {
    const { get } = await serveRelay(scene().query);
    expect(parseAuthorities((await get(`/relay/authorities/${enc(GRANTS)}`)).body)).toEqual([BOOK]);
    expect(parseAuthorities((await get(`/relay/authorities/${enc(SUBJECT)}`)).body)).toEqual([`${SUBJECT}/book`]);
    expect(parseHistory((await get(`/relay/history/${enc(GRANTS)}`)).body)).toEqual({ types: ['createDataAccount', 'writeData', 'writeData'], incomplete: false });
  });

  it('keybook: key hashes (64 lower-case hex), delegate books and thresholds per page, the roster of the quorum', async () => {
    const { get } = await serveRelay(scene().query);
    const r = await get(`/relay/keybook/${enc(BOOK)}`);
    expect(r.status).toBe(200);
    expect(parseKeybook(r.body)).toEqual([
      { url: `${BOOK}/1`, keyHashes: ['aa'.repeat(32)], delegates: [], threshold: 1 },
      { url: `${BOOK}/2`, keyHashes: ['bb'.repeat(32), 'cc'.repeat(32)], delegates: ['acc://fic-risk.acme/risk'], threshold: 2 },
      { url: `${BOOK}/3`, keyHashes: [], delegates: ['acc://fic-ops.acme/ops'], threshold: 1 },
    ]);
  });

  it('chainlen: { length } and nothing else, one node query', async () => {
    const node = scene();
    const { get } = await serveRelay(node.query);
    const before = node.calls.length;
    const r = await get(`/relay/chainlen/${enc(GRANTS)}`);
    expect(r.status).toBe(200);
    expect(parseChainLen(r.body)).toBe(3);
    expect(node.calls.length - before).toBe(1);
    expect(r.headers.get('x-reader-queries')).toBe('1');
  });
});

describe('what the Console parsers would refuse is not what the relay answers (the parsers themselves, so the fixtures cannot rot into accepting anything)', () => {
  it('rejects an unknown member, a missing member, the wrong type, an upper-case or short key hash', () => {
    expect(parseDataEntries({ entries: [], extra: 1 })).toBeNull();
    expect(parseDataEntries({ entries: [{ txId: 'acc://x', elements: [] }] })).toBeNull();
    expect(parseDataEntries({ entries: [{ txId: 'acc://x', time: '1', elements: [] }] })).toBeNull();
    expect(parseDataEntries({ entries: [{ txId: 'acc://x', time: 1, elements: ['AB'] }] })).toBeNull();
    expect(parseKeybook({ pages: [{ url: 'u', keyHashes: ['aa'], delegates: [], threshold: 1 }] })).toBeNull();
    expect(parseKeybook({ pages: [{ url: 'u', keyHashes: [], threshold: 1 }] })).toBeNull();
    expect(parseHistory({ types: ['a'] })).toBeNull();
    expect(parseAuthorities({ authorities: [''] })).toBeNull();
    expect(parseChainLen({ length: -1 })).toBeNull();
    expect(parseChainLen({ length: 1, extra: 1 })).toBeNull();
    expect(parseChainLen({ length: '1' })).toBeNull();
  });
});

describe('the same contract on the recorded REAL Kermit answers (DAX-3A, FICTIONAL parties)', () => {
  const doc = JSON.parse(readFileSync(new URL('./fixtures/live-dax3a-answers-trimmed.json', import.meta.url), 'utf8'));
  const G = 'acc://d3adfbd25-grantor.acme';
  const sec = (iso: string): number => Date.parse(iso) / 1000;

  it('data, history, authorities, chainlen and keybook are all accepted; the real times are the block times', async () => {
    const { get } = await serveRelay(replayNode(doc).query);
    const data = parseDataEntries((await get(`/relay/data/${enc(`${G}/certen-grants`)}`)).body);
    expect(data).not.toBeNull();
    expect(data!.map((e) => e.time)).toEqual([sec('2026-11-12T20:47:34Z'), sec('2026-11-12T20:50:37Z'), sec('2026-11-12T22:10:13Z')]);
    expect(parseHistory((await get(`/relay/history/${enc(`${G}/certen-grants`)}`)).body)).toEqual({ types: ['createDataAccount', 'writeData', 'writeData', 'writeData'], incomplete: false });
    expect(parseAuthorities((await get(`/relay/authorities/${enc(`${G}/certen-grants`)}`)).body)).toEqual([`${G}/book`]);
    expect(parseChainLen((await get(`/relay/chainlen/${enc(`${G}/certen-grants`)}`)).body)).toBe(4);
    expect(parseKeybook((await get(`/relay/keybook/${enc(`${G}/book`)}`)).body)).toEqual([
      { url: `${G}/book/1`, keyHashes: ['23cdfdf6dde7d68ec49537e68e362df9c130057e3ed51f0873c157120e7554fd'], delegates: [], threshold: 1 },
    ]);
    expect(parseDataEntries((await get(`/relay/data/${enc(`${G}/certen-subjects`)}`)).body)).toHaveLength(3);
    expect(parseDataEntries((await get(`/relay/data/${enc('acc://d3adfbd25-agent.acme/certen-acceptances')}`)).body)).toHaveLength(3);
  });
});
