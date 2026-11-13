/**
 * The live precheck script (scripts/verify/reader-live-precheck.ts) run offline over the recorded real Kermit answers, so that its code path is
 * proven before it is pointed at a live node once. Its summary shape is what the live run prints.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { runPrecheck } from '../scripts/verify/reader-live-precheck.js';
import { replayNode } from './support/fake-node.js';

const doc = JSON.parse(readFileSync(new URL('./fixtures/live-dax3a-answers-trimmed.json', import.meta.url), 'utf8'));
const G = 'acc://d3adfbd25-grantor.acme';

describe('the live precheck over recorded answers', () => {
  it('resolves the head and the subject, reports the query counts of a cold and a steady-state evaluation, and every relay answer parses', async () => {
    // the recording holds no length probe of the subject ADI root (never asked by the DAX-3A driver): the ONE synthesized answer, as in binding-real-shapes
    const node = replayNode(doc, { 'acc://d3adfbd25-agent.acme chain main': { recordType: 'range', start: 0, total: 3, records: [] } });
    const out = await runPrecheck(node.query, { endpoint: 'replay', grantorAdi: G, grantorBook: `${G}/book`, grantId: 'fic-lab-pay', subject: 'acc://d3adfbd25-agent.acme', nowSeconds: () => Date.parse('2026-11-12T22:21:35Z') / 1000 });
    expect(out.cold.head).toMatchObject({ ok: true });
    expect(out.cold.subject).toMatchObject({ ok: true, adi: 'acc://d3adfbd25-agent.acme', type: 'agent' });
    expect(out.steadyState.head).toMatchObject({ ok: true });
    expect(out.steadyState.nodeQueries).toBe(4); // the four chain-length probes, nothing else
    expect(out.cold.nodeQueries).toBeGreaterThan(out.steadyState.nodeQueries);
    expect(out.relay.map((r) => [r.route, r.status, r.consoleParses])).toEqual([['data', 200, true], ['history', 200, true], ['authorities', 200, true], ['chainlen', 200, true], ['keybook', 200, true]]);
    expect(out.relay[0]!.body).toMatchObject({ entries: [{ iso: '2026-11-12T20:47:34.000Z' }, { iso: '2026-11-12T20:50:37.000Z' }, { iso: '2026-11-12T22:10:13.000Z' }] });
    expect(out.totalNodeQueries).toBe(out.cold.nodeQueries + out.steadyState.nodeQueries + out.relay.reduce((n, r) => n + Number(r.queries), 0));
  });
});
