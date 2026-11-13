/**
 * The reader against REAL recorded Kermit answers (DAX-3A live run, public data, FICTIONAL lab parties, testnet): the node source and the
 * production chain world run on the answers the node actually gave, replayed offline from test/fixtures/live-dax3a-answers-trimmed.json
 * (16 of the 20 recorded answers; the minor-block answers keep recordType, index, time and source). Nothing here contacts a network.
 *
 * What the recorded answers settle (DAX4S-F17, F18 at the shape level; the live smoke settles them against a running node):
 *   - an entry has no timestamp; its chain time is the time of the minor block in `value.received`;
 *   - the entries are the main chain's WriteData transactions; the account's main chain begins with createDataAccount;
 *   - the three accounts of the grant scene resolve to the same head and the same subject the DAX-3A chain-check verified.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createChainWorld } from '../src/binding/chain-world.js';
import { createNodeSource, type Meter } from '../src/binding/node-source.js';
import { ReadCache } from '../src/binding/read-cache.js';
import { replayNode } from './support/fake-node.js';

const doc = JSON.parse(readFileSync(new URL('./fixtures/live-dax3a-answers-trimmed.json', import.meta.url), 'utf8'));
const GRANTOR = 'acc://d3adfbd25-grantor.acme';
const BOOK = `${GRANTOR}/book`;
const GRANTS = `${GRANTOR}/certen-grants`;
const REGISTRY = `${GRANTOR}/certen-subjects`;
const SUBJECT = 'acc://d3adfbd25-agent.acme';
const ACCEPT = `${SUBJECT}/certen-acceptances`;
const sec = (iso: string): number => Date.parse(iso) / 1000;
const meter = (): Meter => ({ n: 0 });

describe('the node source on the recorded answers', () => {
  const src = () => createNodeSource(replayNode(doc).query);

  it('chain length, authority set and the main chain from its creation', async () => {
    const s = src();
    expect(await s.chainLength(GRANTS, meter())).toBe(4);
    expect(await s.authorities(GRANTS, meter())).toEqual([BOOK]);
    expect(await s.authorities(SUBJECT, meter())).toEqual([`${SUBJECT}/book`]);
    expect(await s.history(GRANTS, 4, meter())).toEqual({ types: ['createDataAccount', 'writeData', 'writeData', 'writeData'], incomplete: false });
    expect(await s.history(REGISTRY, 4, meter())).toEqual({ types: ['createDataAccount', 'writeData', 'writeData', 'writeData'], incomplete: false });
    expect(await s.history(ACCEPT, 4, meter())).toEqual({ types: ['createDataAccount', 'writeData', 'writeData', 'writeData'], incomplete: false });
  });

  it('the entries carry the REAL transaction ids and the time of the block named by `value.received`', async () => {
    const s = src();
    const grants = (await s.entries(GRANTS, 4, meter()))!;
    expect(grants.map((e) => e.txId)).toEqual([
      'acc://ebcad483e68139658d75e7eb5c1419e48f122de17470428e15b91d380c1df18f@d3adfbd25-grantor.acme/certen-grants',
      'acc://652a3637ca35928f851cc6287bf8f8e9a0c436cea4c8d7f7c517ca661a4f65ce@d3adfbd25-grantor.acme/certen-grants',
      'acc://cbe4f11f14ab9f41effda6e6f6e6bddd1773297feb82a0a8c59f7ff229279c77@d3adfbd25-grantor.acme/certen-grants',
    ]);
    expect(grants.map((e) => e.time)).toEqual([sec('2026-11-12T20:47:34Z'), sec('2026-11-12T20:50:37Z'), sec('2026-11-12T22:10:13Z')]);
    expect(grants.every((e) => e.elements.length === 2)).toBe(true);
    // two partitions, two block clocks: the subject's acceptances executed on another BVN than the grantor's accounts
    expect((await s.entries(ACCEPT, 4, meter()))!.map((e) => e.time)).toEqual([sec('2026-11-12T20:52:51Z'), sec('2026-11-12T21:44:20Z'), sec('2026-11-12T21:44:40Z')]);
    expect((await s.entries(REGISTRY, 4, meter()))!.map((e) => e.time)).toEqual([sec('2026-11-12T20:52:58Z'), sec('2026-11-12T21:44:13Z'), sec('2026-11-12T21:44:46Z')]);
  });

  it('reads one main chain page and one block query per entry for an account, and never the data chain', async () => {
    const r = replayNode(doc);
    const s = createNodeSource(r.query);
    const m = meter();
    await s.history(GRANTS, 4, m);
    await s.entries(GRANTS, 4, m);
    expect(r.calls.filter((c) => c === `${GRANTS} chain`)).toHaveLength(1);
    expect(r.calls.filter((c) => c.includes(' block ')).sort()).toEqual([`${GRANTS} block 16875756`, `${GRANTS} block 16875937`, `${GRANTS} block 16880672`]);
    expect(m.n).toBe(4);
    expect(r.calls.filter((c) => c.endsWith(' data'))).toEqual([]);
  });
});

describe('the production chain world on the recorded answers', () => {
  const NOW = sec('2026-11-12T22:21:35Z');
  // The recording holds no main-chain length probe of the subject's ADI ROOT (the DAX-3A driver never asked one): this single answer is SYNTHESIZED,
  // in the recorded shape of a chain answer. The live precheck replaces it with the node's own answer.
  const SYNTHETIC = { [`${SUBJECT} chain main`]: { recordType: 'range', start: 0, total: 3, records: [] } };
  const establish = async () => {
    const node = replayNode(doc, SYNTHETIC);
    const cache = new ReadCache(node.query);
    const world = createChainWorld({ evaluation: () => cache.evaluation(), nowSeconds: () => NOW });
    const r = await world.establish({ grantorAdi: GRANTOR, grantorBook: BOOK, grantId: 'fic-lab-pay', asserted: { adi: SUBJECT, assertedBy: GRANTOR } });
    return { r, node };
  };

  it('resolves the Grant head (v3) and the subject exactly as the DAX-3A chain-check did', async () => {
    const { r } = await establish();
    expect(r.head.ok).toBe(true);
    if (!r.head.ok) throw new Error(r.head.detail);
    expect(r.head.value.hash).toMatch(/^(0x)?8255a5cded910969385e60d71dbcdffc48265475fdb27c62816173e7bed9517f$/);
    expect(r.head.value.grant).toMatchObject({ version: 3, grantId: 'fic-lab-pay' });
    expect(r.subject).toEqual({ ok: true, value: { adi: SUBJECT, type: 'agent' } });
  });

  it('asks no key page, no transaction by id and no data chain', async () => {
    const { node } = await establish();
    expect(node.calls.filter((c) => /\/book(\/\d+)?( |$)/.test(c))).toEqual([]);
    expect(node.calls.filter((c) => /@/.test(c.split(' ')[0]!))).toEqual([]);
    expect(node.calls.filter((c) => c.endsWith(' data'))).toEqual([]);
  });
});
