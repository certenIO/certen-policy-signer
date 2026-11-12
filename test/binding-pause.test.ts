/**
 * The persisted pause (DAX-4-A3 at module level, DE-24 to DE-28): scopes, who and why, resume rules, restart, tamper, the
 * crash window between the journal and the state file, and the re-read before every signature. The real PROCESS restart is
 * test/pause-process.test.ts. FICTIONAL data, temp directories only.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DecisionJournal } from '../src/binding/journal.js';
import { PauseStateError, PauseStore } from '../src/binding/pause-store.js';
import { serializePauseState, emptyPauseState } from '../src/core/pause.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-p-')); dirs.push(d); return d; };
const SEATS = ['seat:fic-treasury', 'seat:fic-risk'];
const SUBJECT = 'acc://agent-one.fic-grantor.acme';
const NOW = 1_800_000_000;
const BY = 'seat:fic-operator';
const WHY = 'FICTIONAL: suspected key misuse, stopping';
const open = (d: string, onHeal?: (m: string) => void): PauseStore =>
  new PauseStore({ journal: new DecisionJournal({ path: join(d, 'j.jsonl'), logId: 'fic-signer' }), statePath: join(d, 'pause-state.json'), seats: SEATS, nowSeconds: () => NOW, ...(onHeal ? { onHeal } : {}) });
const ok = (r: { ok: boolean; reason?: string }): void => { if (!r.ok) throw new Error('refused ' + r.reason); };
const sign = (p: PauseStore, seat = SEATS[0]!, subject: string | null = null, vote: 'approve' | 'reject' = 'approve') => p.check({ seat, subject, vote });

describe('scopes, who, why, resume rules (DE-24, DE-26, DE-27)', () => {
  it('a paused seat signs nothing, a reject vote included; another seat still signs', async () => {
    const p = open(tmp());
    expect(sign(p)).toEqual({ ok: true });
    ok(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    expect(sign(p, SEATS[0], null, 'approve')).toMatchObject({ ok: false, reason: 'paused', scope: 'seat', id: SEATS[0], by: BY });
    expect(sign(p, SEATS[0], null, 'reject')).toMatchObject({ ok: false, reason: 'paused' });
    expect(sign(p, SEATS[1])).toEqual({ ok: true });
  });

  it('a paused subject signs nothing for any seat; a seat pause is reported before it', async () => {
    const p = open(tmp());
    ok(await p.set({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY }));
    expect(sign(p, SEATS[0], SUBJECT)).toMatchObject({ ok: false, reason: 'paused', scope: 'subject', id: SUBJECT });
    expect(sign(p, SEATS[1], SUBJECT, 'reject')).toMatchObject({ ok: false, reason: 'paused' });
    expect(sign(p, SEATS[0], null)).toEqual({ ok: true });
    ok(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    expect(sign(p, SEATS[0], SUBJECT)).toMatchObject({ scope: 'seat' });
  });

  it('a resume lifts only its own scope and id (wrong-scope resume refused by name)', async () => {
    const p = open(tmp());
    ok(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    ok(await p.set({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY }));
    expect(await p.resume({ scope: 'subject', id: 'acc://another.acme', by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'not_paused' });
    ok(await p.resume({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY }));
    expect(sign(p, SEATS[0], SUBJECT)).toMatchObject({ ok: false, scope: 'seat' }); // the seat stays paused
    expect(sign(p, SEATS[1], SUBJECT)).toEqual({ ok: true }); // the subject is free again
    expect(await p.resume({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'not_paused' });
    ok(await p.resume({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    expect(sign(p, SEATS[0])).toEqual({ ok: true });
  });

  it('needs a named seat and a reason, by name', async () => {
    const p = open(tmp());
    expect(await p.set({ scope: 'seat', id: SEATS[0]!, by: '', reason: WHY })).toMatchObject({ ok: false, reason: 'seat_required' });
    expect(await p.set({ scope: 'seat', id: SEATS[0]!, by: 'alice', reason: WHY })).toMatchObject({ ok: false, reason: 'seat_invalid' });
    expect(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: 'short' })).toMatchObject({ ok: false, reason: 'reason_required' });
    ok(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    expect(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'already_paused' });
    expect(await p.resume({ scope: 'seat', id: SEATS[0]!, by: BY, reason: '' })).toMatchObject({ ok: false, reason: 'reason_required' });
    expect(sign(p)).toMatchObject({ ok: false, reason: 'paused' }); // none of the refusals changed anything
  });

  it('pauses and resumes every configured seat (the old "stop everything") and never a subject', async () => {
    const p = open(tmp());
    ok(await p.set({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY }));
    ok(await p.setAllSeats(BY, WHY));
    expect(SEATS.map((s) => sign(p, s).ok)).toEqual([false, false]);
    expect(await p.setAllSeats(BY, WHY)).toMatchObject({ ok: false, reason: 'already_paused' });
    ok(await p.resumeAllSeats(BY, WHY));
    expect(SEATS.map((s) => sign(p, s).ok)).toEqual([true, true]);
    expect(sign(p, SEATS[0], SUBJECT)).toMatchObject({ ok: false, scope: 'subject' });
    expect(await p.resumeAllSeats(BY, WHY)).toMatchObject({ ok: false, reason: 'not_paused' });
  });
});

describe('persistence and tamper (DE-25, DE-28)', () => {
  it('a pause survives a restart, with who, why and when; the journal records both entries', async () => {
    const d = tmp();
    ok(await open(d).set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    const q = open(d); // a new process: nothing in memory
    expect(sign(q)).toMatchObject({ ok: false, reason: 'paused', by: BY, since: NOW });
    expect(q.snapshot().pauses[0]).toMatchObject({ scope: 'seat', id: SEATS[0], by: BY, reason: WHY, at: NOW });
    ok(await q.resume({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    expect(sign(open(d))).toEqual({ ok: true });
    expect(new DecisionJournal({ path: join(d, 'j.jsonl'), logId: 'fic-signer' }).entries().map((e) => e.kind)).toEqual(['pause.set', 'pause.clear']);
  });

  it('refuses to start when a pause record was dropped from the state file (it must never read as "not paused")', async () => {
    const d = tmp();
    const p = open(d);
    ok(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    ok(await p.set({ scope: 'seat', id: SEATS[1]!, by: BY, reason: WHY }));
    // drop the FIRST record (the later one would look like a crash window)
    const state = JSON.parse(readFileSync(join(d, 'pause-state.json'), 'utf8'));
    state.pauses = state.pauses.filter((r: { id: string }) => r.id !== SEATS[0]);
    writeFileSync(join(d, 'pause-state.json'), JSON.stringify(state));
    expect(() => open(d)).toThrow(/pause_state_log_mismatch/);
    // a record added that the journal never saw
    const d2 = tmp();
    ok(await open(d2).set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    const s2 = JSON.parse(readFileSync(join(d2, 'pause-state.json'), 'utf8'));
    s2.pauses.push({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY, at: NOW });
    writeFileSync(join(d2, 'pause-state.json'), JSON.stringify(s2));
    expect(() => open(d2)).toThrow(/pause_state_log_mismatch/);
  });

  it('refuses to start on an unreadable state file and signs nothing when it becomes unreadable at run time', async () => {
    const d = tmp();
    const p = open(d);
    ok(await p.set({ scope: 'seat', id: SEATS[1]!, by: BY, reason: WHY }));
    writeFileSync(join(d, 'pause-state.json'), '{not json');
    expect(sign(p, SEATS[0])).toMatchObject({ ok: false, reason: 'pause_state_unreadable' }); // a seat that was never paused signs nothing either
    expect(p.anyPaused()).toBe(true);
    expect(() => open(d)).toThrow(PauseStateError);
  });

  it('heals a crash between the journal entry and the state write (the file is one change behind), restoring the pause', async () => {
    const d = tmp();
    const p = open(d);
    ok(await p.set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    // the crash: the pause.set for the second seat reached the journal, the state file was never written
    const j = new DecisionJournal({ path: join(d, 'j.jsonl'), logId: 'fic-signer' });
    j.appendNow('pause.set', NOW, { scope: 'seat', id: SEATS[1], by: BY, reason: WHY });
    const healed: string[] = [];
    const q = open(d, (m) => healed.push(m));
    expect(healed).toHaveLength(1);
    expect(healed[0]).toMatch(/behind the journal/);
    expect(sign(q, SEATS[1])).toMatchObject({ ok: false, reason: 'paused' });
    expect(sign(q, SEATS[0])).toMatchObject({ ok: false, reason: 'paused' });
    expect(open(d).snapshot().pauses).toHaveLength(2);
  });

  it('a missing state file with one pause entry in the journal is rewritten; with none it is created empty', async () => {
    const d = tmp();
    const q0 = open(d);
    expect(readFileSync(join(d, 'pause-state.json'), 'utf8')).toBe(serializePauseState(emptyPauseState()));
    ok(await q0.set({ scope: 'subject', id: SUBJECT, by: BY, reason: WHY }));
    rmSync(join(d, 'pause-state.json'));
    expect(sign(open(d), SEATS[0], SUBJECT)).toMatchObject({ ok: false, reason: 'paused' });
  });

  it('re-reads the file before every signature: a pause set by another tool applies without a restart', async () => {
    const d = tmp();
    const p = open(d);
    expect(sign(p)).toEqual({ ok: true });
    ok(await open(d).set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY })); // a second handle on the same files
    expect(sign(p)).toMatchObject({ ok: false, reason: 'paused' });
  });

  it('a journal that was tampered with refuses to start through the journal (the pause cannot be edited away in both)', async () => {
    const d = tmp();
    ok(await open(d).set({ scope: 'seat', id: SEATS[0]!, by: BY, reason: WHY }));
    const j = join(d, 'j.jsonl');
    const lines = readFileSync(j, 'utf8').trimEnd().split('\n');
    writeFileSync(j, lines.slice(0, -1).join('\n'));
    appendFileSync(j, '');
    writeFileSync(join(d, 'pause-state.json'), serializePauseState(emptyPauseState()));
    expect(() => open(d)).toThrow(/log_truncated|journal_pin_missing|log_head_mismatch/);
  });
});
