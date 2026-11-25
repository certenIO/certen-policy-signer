/**
 * DAX-F191b: a cause that persists costs a bounded, small number of journal entries per decision.
 *
 * DAX-F191 gives back a bound decision whose vote was provably not cast. Left there, while the cause persists (a custody refusal, a gateway
 * refusal before signing, a refused submit the chain shows absent) EVERY poll (15 s) consumed the decision again (one `decision.consumed`
 * entry) and released it again (one `recheck.result` `decision_released` entry) until the decision window ended: 2 entries per poll, about
 * 720 for one 90-minute decision.
 *
 * The rule now: the release entry carries its attempt number and the time before which the same decision is not consumed again
 * (`retryAfter`). The first release is retried at the next poll; each further release doubles the wait from 15 s up to 600 s. A poll
 * inside the wait consumes nothing, casts nothing and writes nothing to the journal; it is logged and recorded on the item
 * (`decision_retry_held`). The wait is derived from the journal, so it holds across a restart. Single use, the chain read before releasing a
 * sent vote, and the voided rule are unchanged. The real Orchestrator, journal and core binding over a temp directory; a mock Accumulate
 * client. FICTIONAL.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pino from 'pino';
import { H, intentBody } from './support/binding-fixtures.js';
import { NOW_S, TX, approveFor, rig } from './support/binding-rig.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import type { TxSignatures } from '../src/accumulate/client.js';
import type { VoteBackend, VoteResult } from '../src/vote/backend.js';

const BASE = intentBody();
const NONCE = H('nonce-fixed');
const SEED = new Uint8Array(32).fill(7);
const POLL_S = 15;
/** the decision window of the live seats: SEAT_DECISION_WINDOW_SECONDS = 5400 */
const WINDOW_S = 5400;
const ISSUED = NOW_S - 10;
const reply = approveFor(BASE, { issuedAt: ISSUED, expiresAt: ISSUED + WINDOW_S });

/** the seat key; its sign() refuses while `refusing()` (a custody refusal: nothing is signed) */
function custodyKey(refusing: () => boolean): LocalSigner & { signs: number } {
  const k = new LocalSigner(SEED) as LocalSigner & { signs: number };
  k.signs = 0;
  const real = k.sign.bind(k);
  k.sign = async (m: Uint8Array) => {
    k.signs += 1;
    if (refusing()) throw new Error('custody refused (FICTIONAL)');
    return real(m);
  };
  return k;
}

type Entry = { kind: string; at: number; payload: Record<string, unknown> };
const journalLines = (dir: string): Entry[] =>
  readFileSync(join(dir, 'decision-journal.jsonl'), 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l) as Entry);
/** the journal entries this decision cost: its consumptions, its releases, and binding refusals that name it */
const decisionEntries = (dir: string): Entry[] =>
  journalLines(dir).filter((e) => e.payload['nonce'] === NONCE && (e.kind === 'decision.consumed' || e.kind === 'binding.refused' || (e.kind === 'recheck.result' && e.payload['outcome'] === 'decision_released')));
const releases = (dir: string): Entry[] => journalLines(dir).filter((e) => e.kind === 'recheck.result' && e.payload['outcome'] === 'decision_released');

const chainAbsent = async (): Promise<TxSignatures> => ({ status: 'pending', delivered: false, signatures: [] });

function capture(): { logger: pino.Logger; lines: Array<Record<string, unknown>> } {
  const lines: Array<Record<string, unknown>> = [];
  const logger = pino({ level: 'info' }, { write: (s: string) => { lines.push(JSON.parse(s) as Record<string, unknown>); } });
  return { logger, lines };
}

/** the attempts (seconds after the first poll) a persisting cause gets inside the 5400 s window, polled every 15 s */
const EXPECTED_ATTEMPTS = [0, 15, 30, 60, 120, 240, 480, 960, 1560, 2160, 2760, 3360, 3960, 4560, 5160];

describe('DAX-F191b: a persisting cause costs a bounded number of journal entries per decision', () => {
  it('a custody refusal (nothing signed) every attempt, polled every 15 s for the whole window: 15 attempts, 30 entries, not 2 per poll', async () => {
    let t = 0;
    const key = custodyKey(() => true);
    const { logger, lines } = capture();
    const r = rig({ body: BASE, reply, keyring: singleKeyring(key), clock: () => NOW_S + t, logger });
    let polls = 0;
    let expiredPolls = 0;
    const attemptsAt: number[] = [];
    for (t = 0; t < WINDOW_S + 60; t += POLL_S) {
      const before = key.signs;
      const row = await r.handle();
      polls += 1;
      if (key.signs > before) attemptsAt.push(t);
      else if (t < WINDOW_S - 10) expect(row.lastError).toBe('binding: decision_retry_held');
      else { expiredPolls += 1; expect(row.lastError).toBe('binding: decision_expired'); }
    }
    const entries = decisionEntries(r.dir);
    const consumed = entries.filter((e) => e.kind === 'decision.consumed').length;
    const released = entries.filter((e) => e.kind === 'recheck.result').length;
    const refused = entries.filter((e) => e.kind === 'binding.refused');
    // the measure the lead asked for: polls vs entries
    console.log(`DAX-F191b custody: polls=${polls} attempts=${attemptsAt.length} consumed=${consumed} released=${released} refused=${refused.length} entries=${entries.length} (2 per poll would be ${2 * polls})`);
    expect(attemptsAt).toEqual(EXPECTED_ATTEMPTS);
    expect(consumed).toBe(EXPECTED_ATTEMPTS.length);
    expect(released).toBe(EXPECTED_ATTEMPTS.length);
    // the window ends: one refusal, decision_expired, written once
    expect(refused.map((e) => e.payload['reason'])).toEqual(['decision_expired']);
    expect(entries.length).toBe(2 * EXPECTED_ATTEMPTS.length + 1);
    expect(entries.length).toBeLessThan(polls / 10);
    expect(r.acc.submissions).toHaveLength(0);
    // each release names its attempt and its wait, and is the failure record
    const rel = releases(r.dir);
    expect(rel.map((e) => e.payload['attempt'])).toEqual(EXPECTED_ATTEMPTS.map((_, i) => i + 1));
    // the first release waits for nothing (the next poll); then 15 s doubling to 600 s from each attempt
    expect(rel.map((e) => Number(e.payload['retryAfter']) - NOW_S)).toEqual([0, ...EXPECTED_ATTEMPTS.slice(2), 5760]);
    for (const e of rel) expect(e.payload).toMatchObject({ chain: 'not_signed', reason: 'vote_not_cast', txHash: TX });
    // the audit log names every release, every failed cast, and every held poll
    expect(lines.filter((l) => String(l['msg']).startsWith('decision released for a retry'))).toHaveLength(EXPECTED_ATTEMPTS.length);
    expect(lines.filter((l) => l['msg'] === 'vote submission failed')).toHaveLength(EXPECTED_ATTEMPTS.length);
    const held = lines.filter((l) => String(l['msg']).startsWith('decision retry held'));
    expect(held.length).toBe(polls - EXPECTED_ATTEMPTS.length - expiredPolls);
    for (const l of held) expect(l).toMatchObject({ nonce: NONCE, tx: TX });
  });

  it('a refused submit the chain shows absent, every attempt: the same bound; the chain is read once per attempt, never per poll', async () => {
    let t = 0;
    const r = rig({ body: BASE, reply, clock: () => NOW_S + t });
    for (let i = 0; i < 1000; i++) r.acc.submitQueue.push({ ok: false, code: 'error', error: 'node refused the envelope (FICTIONAL)' });
    let reads = 0;
    (r.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => { reads += 1; return chainAbsent(); };
    let polls = 0;
    for (t = 0; t < WINDOW_S - 10; t += POLL_S) { await r.handle(); polls += 1; }
    const entries = decisionEntries(r.dir);
    console.log(`DAX-F191b chain-absent: polls=${polls} submissions=${r.acc.submissions.length} reads=${reads} entries=${entries.length} (2 per poll would be ${2 * polls})`);
    expect(r.acc.submissions).toHaveLength(EXPECTED_ATTEMPTS.length);
    expect(reads).toBe(EXPECTED_ATTEMPTS.length);
    expect(entries.length).toBe(2 * EXPECTED_ATTEMPTS.length);
    for (const e of releases(r.dir)) expect(e.payload['chain']).toBe('absent');
  });

  it('a gateway refusal before signing (cast: none) every attempt: the same bound', async () => {
    let t = 0;
    let casts = 0;
    const votes: VoteBackend = { cast: async (): Promise<VoteResult> => { casts += 1; return { ok: false, error: 'gateway: signing data refused (FICTIONAL)', cast: 'none' }; } };
    const r = rig({ body: BASE, reply, votes, clock: () => NOW_S + t });
    let polls = 0;
    for (t = 0; t < WINDOW_S - 10; t += POLL_S) { await r.handle(); polls += 1; }
    const entries = decisionEntries(r.dir);
    console.log(`DAX-F191b gateway: polls=${polls} casts=${casts} entries=${entries.length} (2 per poll would be ${2 * polls})`);
    expect(casts).toBe(EXPECTED_ATTEMPTS.length);
    expect(entries.length).toBe(2 * EXPECTED_ATTEMPTS.length);
  });
});

describe('DAX-F191b: the retry is prompt when the cause clears', () => {
  it('one failure is retried at the very next poll; after four, the cause clears and the decision signs at the end of the current wait (60 s), once', async () => {
    let t = 0;
    let refusing = true;
    const key = custodyKey(() => refusing);
    const r = rig({ body: BASE, reply, keyring: singleKeyring(key), clock: () => NOW_S + t });
    for (t = 0; t <= 60; t += POLL_S) await r.handle(); // attempts at 0, 15, 30, 60; held at 45
    expect(releases(r.dir).map((e) => e.payload['attempt'])).toEqual([1, 2, 3, 4]);
    expect(Number(releases(r.dir)[3]!.payload['retryAfter'])).toBe(NOW_S + 120);
    refusing = false; // the custody service is back at t = 75
    const signs = key.signs;
    for (t = 75; t < 120; t += POLL_S) {
      const row = await r.handle();
      expect(row.lastError).toBe('binding: decision_retry_held');
    }
    expect(key.signs).toBe(signs); // nothing was attempted inside the wait
    t = 120;
    expect((await r.handle()).status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
    expect(r.nonces.has(NONCE)).toBe(true);
    // landed: single use is exact, now and after a restart
    t = 135;
    const again = await r.handle();
    expect(again.status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
    const restarted = rig({ dir: r.dir, body: BASE, reply, clock: () => NOW_S + t });
    expect((await restarted.handle()).lastError).toBe('binding: decision_replayed');
    expect(restarted.acc.submissions).toHaveLength(0);
  });

  it('a fresh decision (another nonce) is never held by the wait of an earlier one', async () => {
    let t = 0;
    let nonce = NONCE;
    let refusing = true;
    const key = custodyKey(() => refusing);
    const r = rig({ body: BASE, reply: () => approveFor(BASE, { issuedAt: ISSUED, expiresAt: ISSUED + WINDOW_S, nonce })(), keyring: singleKeyring(key), clock: () => NOW_S + t });
    for (t = 0; t <= 30; t += POLL_S) await r.handle(); // attempts 1..3, wait until 60
    refusing = false;
    nonce = H('nonce-fresh');
    t = 45;
    expect((await r.handle()).status).toBe('signed');
  });
});

describe('DAX-F191b: restart, void and single use', () => {
  it('the wait and the attempt count are derived from the journal after a restart', async () => {
    let t = 0;
    const r = rig({ body: BASE, reply, keyring: singleKeyring(custodyKey(() => true)), clock: () => NOW_S + t });
    for (t = 0; t <= 60; t += POLL_S) await r.handle(); // releases 1..4, retryAfter = +120
    const n = journalLines(r.dir).length;

    t = 90;
    const key2 = custodyKey(() => true);
    const a = rig({ dir: r.dir, body: BASE, reply, keyring: singleKeyring(key2), clock: () => NOW_S + t });
    expect(a.nonces.has(NONCE)).toBe(false);
    expect((await a.handle()).lastError).toBe('binding: decision_retry_held');
    expect(key2.signs).toBe(0);
    expect(journalLines(r.dir).length).toBe(n); // a held poll writes nothing
    t = 120;
    await a.handle(); // attempt 5 fails: the count carries on from the journal
    const rel = releases(r.dir);
    expect(rel.map((e) => e.payload['attempt'])).toEqual([1, 2, 3, 4, 5]);
    expect(Number(rel[4]!.payload['retryAfter'])).toBe(NOW_S + 240);

    t = 239;
    const b = rig({ dir: r.dir, body: BASE, reply, keyring: singleKeyring(new LocalSigner(SEED)), clock: () => NOW_S + t });
    expect((await b.handle()).lastError).toBe('binding: decision_retry_held');
    expect(b.acc.submissions).toHaveLength(0);
    t = 240;
    expect((await b.handle()).status).toBe('signed');
    expect(b.acc.submissions).toHaveLength(1);
  });

  it('a decision voided while it waits is never released or retried', async () => {
    let t = 0;
    const r = rig({ body: BASE, reply, keyring: singleKeyring(custodyKey(() => true)), clock: () => NOW_S + t });
    for (t = 0; t <= 15; t += POLL_S) await r.handle(); // released twice, retryAfter = +30
    await r.nonces.voidNonces([NONCE], 'reissued (FICTIONAL)');
    t = 30;
    expect((await r.handle()).lastError).toBe('binding: decision_replayed');
    const restarted = rig({ dir: r.dir, body: BASE, reply, clock: () => NOW_S + 600 });
    expect(restarted.nonces.has(NONCE)).toBe(true);
    expect((await restarted.handle()).lastError).toBe('binding: decision_replayed');
    expect(restarted.acc.submissions).toHaveLength(0);
  });

  it('a sent vote the chain cannot read stays consumed: no release, so no wait, and never a second cast', async () => {
    let t = 0;
    const r = rig({ body: BASE, reply, options: { submitOutcomeTimeoutMs: 1 }, clock: () => NOW_S + t });
    r.acc.submitQueue.push({ ok: false, uncertain: true, error: 'timeout (FICTIONAL)' });
    (r.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async (): Promise<TxSignatures> => ({ status: '', delivered: false, signatures: [], unavailable: 'node timeout (FICTIONAL)' });
    for (t = 0; t <= 600; t += POLL_S) await r.handle();
    expect(releases(r.dir)).toHaveLength(0);
    expect(r.acc.submissions).toHaveLength(1);
    expect(decisionEntries(r.dir).filter((e) => e.kind === 'decision.consumed')).toHaveLength(1);
  });
});
