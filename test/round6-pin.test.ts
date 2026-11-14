/**
 * DAX-4S round 6, the policy pin (DE-93, DE-94, DE-104): a bound seat with no pin decides nothing and answers `policy_pin_missing`
 * BEFORE anything of the step is read; the pin is set only by the explicit pin step (a named seat identity, a reason of at least ten
 * characters, the hash the seat LOADED), is persisted across a restart as a `policy.pinned` entry of the verified journal, and leaves a
 * seat whose loaded hash differs from its pin `pin_stale` until the step is repeated. FICTIONAL data, temp directories only.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { DecisionJournal } from '../src/binding/journal.js';
import { PinStore } from '../src/binding/pin-store.js';
import { verifyLog } from '../src/core/log.js';
import { H, SEAT, intentBody, record } from './support/binding-fixtures.js';
import { NOW_S, TX, approveFor, rig, tmp, RULES, requestHashOf } from './support/binding-rig.js';

const BY = 'seat:fic-operator';
const WHY = 'FICTIONAL: the rule set v1 was reviewed by two officers';
const P1 = H('policy-v1');
const P2 = H('policy-v2');
const mk = (dir: string, loaded: string = P1, seats: string[] = [SEAT]) => {
  const journal = new DecisionJournal({ path: join(dir, 'j.jsonl'), logId: 'fic-signer' });
  const pins = new PinStore({ journal, seats: seats.map((seat) => ({ seat, loadedHash: loaded })), nowSeconds: () => NOW_S });
  return { journal, pins };
};
const pinnedEntries = (j: DecisionJournal) => j.entries().filter((e) => e.kind === 'policy.pinned');

describe('the pin step and the gate', () => {
  it('a seat that loaded a hash and has no pin is pin_pending: every step is policy_pin_missing', () => {
    const { pins } = mk(tmp());
    expect(pins.gate(SEAT)).toEqual({ ok: false, reason: 'policy_pin_missing' });
    expect(pins.snapshot()).toEqual([{ seat: SEAT, loaded: P1, pin: null, phase: 'pin_pending' }]);
  });

  it('a seat the store does not know has no pin either', () => {
    expect(mk(tmp()).pins.gate('seat:other')).toEqual({ ok: false, reason: 'policy_pin_missing' });
  });

  it('the pin step pins what the seat loaded, writes ONE policy.pinned entry naming the previous pin, and opens the gate', async () => {
    const { journal, pins } = mk(tmp());
    const r = await pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY });
    expect(r).toMatchObject({ ok: true, phase: 'pinned' });
    expect(pins.gate(SEAT)).toEqual({ ok: true, pin: P1 });
    const e = pinnedEntries(journal);
    expect(e).toHaveLength(1);
    expect(e[0]!.payload).toEqual({ seat: SEAT, policyHash: P1, by: BY, reason: WHY, previous: null });
    expect(verifyLog({ logId: 'fic-signer', entries: journal.entries(), expectedHead: journal.currentHead() })).toMatchObject({ ok: true });
  });

  it('refuses by name: no seat identity, a name that is not a seat, a reason under ten characters, a hash the seat did not load, a seat it does not know', async () => {
    const { journal, pins } = mk(tmp());
    expect(await pins.pin({ seat: SEAT, hash: P1, by: '', reason: WHY })).toMatchObject({ ok: false, reason: 'seat_required' });
    expect(await pins.pin({ seat: SEAT, hash: P1, by: 'alice', reason: WHY })).toMatchObject({ ok: false, reason: 'seat_invalid' });
    expect(await pins.pin({ seat: SEAT, hash: P1, by: BY, reason: 'too short' })).toMatchObject({ ok: false, reason: 'reason_required' });
    expect(await pins.pin({ seat: SEAT, hash: P2, by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'pin_hash_not_loaded' });
    expect(await pins.pin({ seat: SEAT, hash: 'nope', by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'pin_hash_malformed' });
    expect(await pins.pin({ seat: 'seat:unknown', hash: P1, by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'pin_seat_unknown' });
    expect(pinnedEntries(journal)).toHaveLength(0);
    expect(pins.gate(SEAT)).toEqual({ ok: false, reason: 'policy_pin_missing' });
  });

  it('pinning the pinned hash again is idempotent and writes no second entry', async () => {
    const { journal, pins } = mk(tmp());
    await pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY });
    const again = await pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY + ' (repeated)' });
    expect(again).toMatchObject({ ok: true, idempotent: true });
    expect(pinnedEntries(journal)).toHaveLength(1);
  });
});

describe('the pin is persisted: a restart keeps it, a changed rule set leaves the seat pin_stale until the step is repeated (DE-94)', () => {
  it('survives a restart of the journal and the store', async () => {
    const dir = tmp();
    const a = mk(dir, P1);
    await a.pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY });
    const b = mk(dir, P1); // a new process: the journal is read and verified, the loaded hash is computed again at boot
    expect(b.pins.gate(SEAT)).toEqual({ ok: true, pin: P1 });
    expect(b.pins.snapshot()[0]).toMatchObject({ pin: P1, loaded: P1, phase: 'pinned' });
  });

  it('a seat whose loaded hash differs from its pin is pin_stale: policy_hash_mismatch with detail pin_stale, then pins again and names the previous pin', async () => {
    const dir = tmp();
    await mk(dir, P1).pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY });
    const { journal, pins } = mk(dir, P2); // the rule set changed: the seat loads P2
    expect(pins.gate(SEAT)).toEqual({ ok: false, reason: 'policy_hash_mismatch', detail: 'pin_stale' });
    expect(pins.snapshot()[0]).toMatchObject({ pin: P1, loaded: P2, phase: 'pin_stale' });
    // it cannot be pinned to the OLD hash (the step pins what the seat loaded)
    expect(await pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'pin_hash_not_loaded' });
    const r = await pins.pin({ seat: SEAT, hash: P2, by: BY, reason: 'FICTIONAL: rule set v2 activated by two officers' });
    expect(r).toMatchObject({ ok: true, previous: P1 });
    expect(pins.gate(SEAT)).toEqual({ ok: true, pin: P2 });
    expect(pinnedEntries(journal).map((e) => e.payload['previous'])).toEqual([null, P1]);
    // and that survives a restart too
    expect(mk(dir, P2).pins.gate(SEAT)).toEqual({ ok: true, pin: P2 });
  });

  it('keeps the pin of one seat apart from another, and a pin entry of a seat no longer configured does not stop the start', async () => {
    const dir = tmp();
    const a = mk(dir, P1, [SEAT, 'seat:fic-risk']);
    await a.pins.pin({ seat: 'seat:fic-risk', hash: P1, by: BY, reason: WHY });
    expect(a.pins.gate(SEAT)).toEqual({ ok: false, reason: 'policy_pin_missing' });
    expect(a.pins.gate('seat:fic-risk')).toEqual({ ok: true, pin: P1 });
    expect(mk(dir, P1, [SEAT]).pins.gate(SEAT)).toEqual({ ok: false, reason: 'policy_pin_missing' });
  });

  it('is in the same hash-chained journal file as the nonces (one verified log), and the text carries the entry kind', async () => {
    const dir = tmp();
    await mk(dir, P1).pins.pin({ seat: SEAT, hash: P1, by: BY, reason: WHY });
    const file = readdirSync(dir).find((n) => n.endsWith('.jsonl'))!;
    expect(readFileSync(join(dir, file), 'utf8')).toContain('"kind":"policy.pinned"');
  });
});

describe('the gate comes before anything of the step is read (DE-93): through the orchestrator', () => {
  const body = intentBody();
  const reply = approveFor(body);

  it('an unpinned seat refuses a valid approval as policy_pin_missing, signs nothing and consumes no nonce', async () => {
    const r = rig({ body, reply, pinned: false });
    const out = await r.handle();
    expect(out.status).toBe('awaiting_policy');
    expect(out.lastError).toBe('binding: policy_pin_missing');
    expect(r.nonces.list()).toEqual([]);
    expect(r.acc.submissions).toHaveLength(0);
  });

  it('an unpinned seat also refuses a DENY (a reject vote is a signature): nothing is cast', async () => {
    const r = rig({ body, reply: approveFor(body, {}, 'deny'), pinned: false, submitRejectVote: true });
    const out = await r.handle();
    expect(out.lastError).toBe('binding: policy_pin_missing');
    expect(out.status).not.toBe('denied');
    expect(r.nonces.list()).toEqual([]);
  });

  it('a pin_stale seat refuses even a decision that carries the OLD pinned hash, naming the cause', async () => {
    const r = rig({ body, reply: approveFor(body, { policyHash: P1 }), pinned: false, stalePin: P1, rules: { policyHash: P2 } });
    const out = await r.handle();
    expect(out.lastError).toBe('binding: policy_hash_mismatch');
    const refused = r.journal.entries().filter((e) => e.kind === 'binding.refused');
    expect(refused).toHaveLength(1);
    expect((await r.store.getReceipt(r.tx))?.policyEvidence).toMatchObject({ blockedBy: 'decision_binding', reason: 'policy_hash_mismatch', detail: 'pin_stale' });
    expect(r.nonces.list()).toEqual([]);
  });

  it('a pinned seat accepts the decision under the pinned hash and refuses one under another hash by the core', async () => {
    const good = rig({ body, reply });
    expect((await good.handle()).status).not.toBe('awaiting_policy');
    expect(good.nonces.list()).toHaveLength(1);
    const other = rig({ body, reply: approveFor(body, { policyHash: P2 }) });
    expect((await other.handle()).lastError).toBe('binding: policy_hash_mismatch');
    expect(other.nonces.list()).toEqual([]);
  });

  it('the request hash recorded for the refusal is the one built from the transaction', () => {
    expect(requestHashOf(body)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(RULES.policyHash).toBe(H('policy-v1'));
    expect(record({ requestHash: requestHashOf(body), issuedAt: NOW_S, nonce: H('x') })['policyHash']).toBe(RULES.policyHash);
    expect(TX).toHaveLength(64);
  });
});
