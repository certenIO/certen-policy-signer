/**
 * The decision journal and the nonce store (DAX-4-A1 replay, DE-02, DE-03, DE-47): durable before it returns, surviving a
 * restart, refusing to start on tamper, never skipping an append. FICTIONAL data, temp directories only.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DecisionJournal, JournalError } from '../src/binding/journal.js';
import { NonceStore } from '../src/binding/nonces.js';
import { appendEntry } from '../src/core/log.js';
import { logEntryHash } from '../src/core/hashes.js';
import { H } from './support/binding-fixtures.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-j-')); dirs.push(d); return d; };
const open = (d: string, extra: Partial<ConstructorParameters<typeof DecisionJournal>[0]> = {}): DecisionJournal => new DecisionJournal({ path: join(d, 'decision-journal.jsonl'), logId: 'fic-signer', ...extra });
const NOW = 1_800_000_000;

describe('append, restart, nonce single use', () => {
  it('survives a restart: a nonce consumed before the restart is spent after it, in any request', async () => {
    const d = tmp();
    const a = new NonceStore(open(d), () => NOW);
    const out = await a.consumeWith((consumed) => ({ result: consumed.length, consume: { requestHash: H('req-1'), nonce: H('n-1') } }));
    expect(out).toBe(0);
    // a new process: nothing in memory, everything from the files
    const b = new NonceStore(open(d), () => NOW);
    expect(b.list()).toEqual([H('n-1')]);
    expect(b.has(H('n-1'))).toBe(true);
    const again = await b.consumeWith((consumed) => ({ result: consumed.includes(H('n-1')) ? 'replayed' : 'fresh' }));
    expect(again).toBe('replayed');
  });

  it('two presentations of one nonce at once: exactly one is accepted (the check and the append are one step)', async () => {
    const d = tmp();
    const n = new NonceStore(open(d), () => NOW);
    const present = (tag: string): Promise<string> => n.consumeWith((consumed) => (consumed.includes(H('n-x')) ? { result: `${tag}:replayed` } : { result: `${tag}:accepted`, consume: { requestHash: H('req-' + tag), nonce: H('n-x') } }));
    const results = await Promise.all([present('a'), present('b'), present('c')]);
    expect(results.filter((r) => r.endsWith(':accepted'))).toHaveLength(1);
    expect(results.filter((r) => r.endsWith(':replayed'))).toHaveLength(2);
    expect(open(d).entries().filter((e) => e.kind === 'decision.consumed')).toHaveLength(1);
  });

  it('a voided nonce stays spent after a restart (the old nonce of a re-issued decision)', async () => {
    const d = tmp();
    const n = new NonceStore(open(d), () => NOW);
    expect((await n.voidNonces([H('old-1'), H('old-1')], 'policy_changed')).voided).toEqual([H('old-1')]);
    expect((await n.voidNonces([H('old-1')], 'policy_changed')).voided).toEqual([]);
    expect(new NonceStore(open(d), () => NOW).has(H('old-1'))).toBe(true);
    await expect(n.voidNonces(['nope'], 'x')).rejects.toThrow(JournalError);
  });
});

describe('the journal refuses what it cannot make durable and what was tampered with', () => {
  const seed = async (d: string, count = 4): Promise<string> => {
    const j = open(d);
    for (let i = 1; i <= count; i++) j.appendNow('decision.consumed', NOW + i, { requestHash: H('r' + i), nonce: H('n' + i) });
    return join(d, 'decision-journal.jsonl');
  };
  const lines = (p: string): string[] => readFileSync(p, 'utf8').trimEnd().split('\n');
  const reason = (d: string): string => { try { open(d); return 'started'; } catch (e) { return (e as JournalError).reason; } };

  it('cuts off a torn last line (a crash inside an append that never returned) and goes on', async () => {
    const d = tmp();
    const p = await seed(d);
    appendFileSync(p, '{"seq":5,"kind":"decision.cons');
    let torn = 0;
    const j = open(d, { onTornTail: (b) => { torn = b; } });
    expect(torn).toBeGreaterThan(0);
    expect(j.entries()).toHaveLength(4);
    expect(j.appendNow('decision.consumed', NOW + 9, { requestHash: H('r9'), nonce: H('n9') }).seq).toBe(5);
    expect(open(d).entries()).toHaveLength(5);
  });

  it('brings a pin that lags by one append up to the verified head (a crash between the line and the pin)', async () => {
    const d = tmp();
    const p = await seed(d, 3);
    const j = open(d);
    const made = appendEntry({ logId: 'fic-signer', head: j.currentHead(), kind: 'decision.consumed', at: NOW + 50, payload: { requestHash: H('r50'), nonce: H('n50') } });
    if (!made.ok) throw new Error(made.reason);
    appendFileSync(p, JSON.stringify(made.entry) + '\n'); // the line is durable, the pin was not rewritten
    const again = open(d);
    expect(again.entries()).toHaveLength(4);
    expect(JSON.parse(readFileSync(join(d, 'decision-journal.jsonl.pin.json'), 'utf8')).seq).toBe(4);
  });

  it('refuses to start on an edited payload, a deleted middle entry, a reorder, an insert', async () => {
    let d = tmp();
    let p = await seed(d);
    let l = lines(p);
    l[1] = l[1]!.replace(H('n2'), H('nX'));
    writeFileSync(p, l.join('\n') + '\n');
    expect(reason(d)).toBe('log_entry_hash_mismatch');

    d = tmp(); p = await seed(d); l = lines(p); l.splice(1, 1);
    writeFileSync(p, l.join('\n') + '\n');
    expect(reason(d)).toBe('log_seq_gap');

    d = tmp(); p = await seed(d); l = lines(p); [l[1], l[2]] = [l[2]!, l[1]!];
    writeFileSync(p, l.join('\n') + '\n');
    expect(['log_seq_out_of_order', 'log_seq_duplicate', 'log_seq_gap']).toContain(reason(d));

    d = tmp(); p = await seed(d); l = lines(p);
    const forged = { ...JSON.parse(l[1]!), seq: 2, payload: { requestHash: H('forged'), nonce: H('forged') } };
    l.splice(1, 0, JSON.stringify(forged));
    writeFileSync(p, l.join('\n') + '\n');
    expect(reason(d)).not.toBe('started');
  });

  it('refuses a truncated tail, a deleted pin, a wrong pin and an edit re-chained to the end (only the pin sees these)', async () => {
    let d = tmp();
    let p = await seed(d);
    let l = lines(p);
    writeFileSync(p, l.slice(0, 3).join('\n') + '\n'); // the last line is gone, the pin still names seq 4
    expect(reason(d)).toBe('log_truncated');

    d = tmp(); p = await seed(d);
    rmSync(join(d, 'decision-journal.jsonl.pin.json'));
    expect(reason(d)).toBe('journal_pin_missing');

    d = tmp(); p = await seed(d);
    writeFileSync(join(d, 'decision-journal.jsonl.pin.json'), JSON.stringify({ seq: 4, hash: H('not the head') }));
    expect(reason(d)).toBe('log_head_mismatch');

    // an edit of the LAST entry followed by re-chaining it: a hash chain alone accepts it, the pin does not
    d = tmp(); p = await seed(d); l = lines(p);
    const last = JSON.parse(l[3]!);
    last.payload = { requestHash: H('r4'), nonce: H('replacement') };
    last.hash = logEntryHash({ prev: last.prev, seq: last.seq, kind: last.kind, payload: last.payload, at: last.at });
    l[3] = JSON.stringify(last);
    writeFileSync(p, l.join('\n') + '\n');
    expect(reason(d)).toBe('log_head_mismatch');
  });

  it('refuses a foreign log (another signer id) and an unparseable line', async () => {
    let d = tmp();
    const p = await seed(d);
    expect(() => new DecisionJournal({ path: p, logId: 'another-signer' })).toThrow(JournalError);
    d = tmp();
    const p2 = await seed(d);
    appendFileSync(p2, 'this is not json\n');
    expect(reason(d)).toBe('journal_line_unparseable');
  });

  it('fails the append (never skips it) when the pin cannot be written, and refuses every later append', async () => {
    const d = tmp();
    const pinDir = join(d, 'pin');
    const j = new DecisionJournal({ path: join(d, 'j.jsonl'), pinPath: join(pinDir, 'p.json'), logId: 'fic-signer' });
    j.appendNow('decision.consumed', NOW, { requestHash: H('r1'), nonce: H('n1') });
    rmSync(pinDir, { recursive: true, force: true });
    expect(() => j.appendNow('decision.consumed', NOW, { requestHash: H('r2'), nonce: H('n2') })).toThrow(/journal_pin_write_failed/);
    expect(() => j.appendNow('decision.consumed', NOW, { requestHash: H('r3'), nonce: H('n3') })).toThrow(/journal_broken/);
    const n = new NonceStore(new DecisionJournal({ logId: 'x' }), () => NOW);
    expect(await n.consumeWith(() => ({ result: 1 }))).toBe(1);
  });

  it('refuses a payload the core log refuses (back-pressure: the decision fails, nothing is skipped)', () => {
    const j = new DecisionJournal({ logId: 'fic-signer' });
    expect(() => j.appendNow('decision.consumed', NOW, { nonce: H('n') })).toThrow(/log_payload_invalid/);
    expect(() => j.appendNow('decision.consumed', -1, { requestHash: H('r'), nonce: H('n') })).toThrow(/log_at_invalid/);
    expect(() => j.appendNow('made.up.kind', NOW, {})).toThrow(/log_kind_unknown/);
    expect(j.entries()).toHaveLength(0);
  });
});
