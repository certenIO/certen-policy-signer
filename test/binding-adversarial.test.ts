/**
 * DAX-4S adversarial pass: attempts to get a signature the binding must not give, each one run against the real Orchestrator, the
 * real core and the real journal. Every attempt names the refusal it gets and asserts that nothing reached Accumulate. The last
 * attempts are KNOWN LIMITS: they pass because the behaviour is what it is, and say so (DAX4S-F4, DAX4S-F5).
 */
import { describe, expect, it } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DecisionJournal } from '../src/binding/journal.js';
import { NonceStore } from '../src/binding/nonces.js';
import { DECISION_RECORD_MEMBER } from '../src/binding/verify.js';
import { ADDR, APPROVER, GRANT_HASH, H, KEY, SEAT, commitmentOfLeg, fakeWorld, intentBody, leg, record, subjectClaim } from './support/binding-fixtures.js';
import { NOW_S, SIGNER, TX, approveFor, requestHashOf, rig, tmp } from './support/binding-rig.js';
import { createHash } from 'node:crypto';
import { LocalSigner } from '../src/signer/signer.js';
import { MapKeyring } from '../src/signer/keyring.js';

const BASE = intentBody();
const OTHER_SEAT = 'seat:fic-other';
const OTHER_PAGE = 'acc://o2.acme/book/1';

describe('adversarial attempts at the signer', () => {
  it('ADV-1 replay in another seat: the record names its seat (seat_mismatch); a record for the other seat with a spent nonce is a replay (nonces are process-wide)', async () => {
    const a = rig({ body: BASE, reply: approveFor(BASE) });
    expect((await a.handle()).status).toBe('signed');
    const b = rig({ dir: a.dir, seat: OTHER_SEAT, page: OTHER_PAGE, rules: { authorizedApprovers: [APPROVER] }, body: BASE, reply: approveFor(BASE) });
    expect((await b.handle()).lastError).toBe('binding: seat_mismatch');
    const b2 = rig({ dir: a.dir, seat: OTHER_SEAT, page: OTHER_PAGE, rules: { authorizedApprovers: [APPROVER] }, body: BASE, reply: approveFor(BASE, { seat: OTHER_SEAT }) });
    expect((await b2.handle()).lastError).toBe('binding: decision_replayed');
    expect(b.acc.submissions.length + b2.acc.submissions.length).toBe(0);
  });

  it('ADV-2 replay after a restart of the service: the journal on disk spends the nonce', async () => {
    const first = rig({ body: BASE, reply: approveFor(BASE) });
    await first.handle();
    const again = rig({ dir: first.dir, body: BASE, reply: approveFor(BASE) });
    expect((await again.handle()).lastError).toBe('binding: decision_replayed');
    expect(again.acc.submissions).toHaveLength(0);
  });

  it('ADV-3 the approver is a display name, an ADI in another spelling, or an identity the seat never authorised', async () => {
    const tries: Array<[string, string]> = [
      ['Alice Officer', 'binding: decision_malformed'],
      ['adi:acc://Alice.acme', 'binding: decision_malformed'],
      ['key:' + 'AB'.repeat(32), 'binding: decision_malformed'],
      [KEY('someone-else'), 'binding: approver_not_authorized'],
      ['adi:acc://alice.acme', 'binding: approver_not_authorized'],
    ];
    for (const [approver, reason] of tries) {
      const r = rig({ body: BASE, reply: approveFor(BASE, { approver }) });
      expect((await r.handle()).lastError, approver).toBe(reason);
      expect(r.acc.submissions).toHaveLength(0);
    }
  });

  it('ADV-4 the request is mutated after the approval by one unit, one hex digit, or the asset', async () => {
    const tries: Array<[string, ReturnType<typeof intentBody>]> = [
      ['amount + 1', intentBody({ legs: [leg({ amount: '301' })] })],
      ['the token', intentBody({ legs: [leg({ token: ADDR.other })] })],
      ['native instead of token', intentBody({ legs: [leg({ kind: 'native' })] })],
      ['a spender instead of a recipient', intentBody({ legs: [leg({ kind: 'erc20.approve' })] })],
    ];
    for (const [name, mutated] of tries) {
      const r = rig({ body: mutated, reply: approveFor(BASE) });
      expect((await r.handle()).lastError, name).toBe('binding: request_mismatch');
      expect(r.acc.submissions).toHaveLength(0);
    }
    // one hex digit of the stated commitment: the signer recomputes the commitment over the execution it would sign, so the intent is
    // refused before any decision is compared (presented_malformed, detail execution_commitment_mismatch), and nothing is signed
    const bad = commitmentOfLeg(leg()).slice(0, -1) + '0';
    const r = rig({ body: intentBody({ legs: [leg({ commitment: bad })] }), reply: approveFor(BASE) });
    expect((await r.handle()).lastError).toBe('binding: presented_malformed');
    expect(r.acc.submissions).toHaveLength(0);
  });

  it('ADV-5 time at the edges: valid from issuedAt, expired exactly at expiresAt, a window equal to the cap passes and one second more does not', async () => {
    const at = (over: Record<string, number>) => rig({ body: BASE, reply: approveFor(BASE, over) });
    expect((await at({ issuedAt: NOW_S }).handle()).status).toBe('signed'); // now == issuedAt
    expect((await at({ issuedAt: NOW_S - 60, expiresAt: NOW_S }).handle()).lastError).toBe('binding: decision_expired'); // now == expiresAt
    expect((await at({ issuedAt: NOW_S - 1, expiresAt: NOW_S - 1 + 7200 }).handle()).status).toBe('signed'); // window == cap
    expect((await at({ issuedAt: NOW_S - 1, expiresAt: NOW_S - 1 + 7201 }).handle()).lastError).toBe('binding: decision_window_too_long');
    expect((await at({ issuedAt: NOW_S + 1 }).handle()).lastError).toBe('binding: decision_not_yet_valid');
  });

  it('ADV-6 pause, then a resume of the WRONG scope: the seat stays paused; the right resume lifts it and the same decision (not spent) signs', async () => {
    const r = rig({ body: BASE, submitRejectVote: true, reply: approveFor(BASE) });
    const BY = 'seat:fic-operator', WHY = 'FICTIONAL: stop signing now';
    await r.pauses.set({ scope: 'seat', id: SEAT, by: BY, reason: WHY });
    expect(await r.pauses.resume({ scope: 'subject', id: 'acc://agent-one.fic-grantor.acme', by: BY, reason: WHY })).toMatchObject({ ok: false, reason: 'not_paused' });
    expect((await r.handle()).lastError).toBe('paused');
    expect(r.acc.submissions).toHaveLength(0);
    await r.pauses.resume({ scope: 'seat', id: SEAT, by: BY, reason: WHY });
    expect((await r.handle()).status).toBe('signed');
  });

  it('ADV-7 a crash between consume and sign: the nonce is spent, the same record cannot be used again, a fresh one can', async () => {
    const crashing = { async cast(): Promise<never> { throw new Error('killed'); } };
    const first = rig({ body: BASE, reply: approveFor(BASE), votes: crashing as never });
    await expect(first.handle()).rejects.toThrow('killed');
    const again = rig({ dir: first.dir, body: BASE, reply: approveFor(BASE) });
    expect((await again.handle()).lastError).toBe('binding: decision_replayed');
    expect((await rig({ dir: first.dir, body: BASE, reply: approveFor(BASE, { nonce: H('fresh') }) }).handle()).status).toBe('signed');
  });

  it('ADV-8 a record smuggled where the signer does not look, a downgrade to the legacy reply, extra members, an upper-case nonce, a pending reply', async () => {
    const rec = (): Record<string, unknown> => record({ requestHash: requestHashOf(BASE), issuedAt: NOW_S - 10, nonce: H('n-adv8') });
    const cases: Array<[string, () => Record<string, unknown>, string]> = [
      ['record inside evidence', () => ({ decision: 'approve', evidence: { record: rec() } }), 'binding: decision_malformed'],
      ['no record at all (downgrade to the legacy reply)', () => ({ decision: 'approve', evidence: { approverKeyRef: 'x' } }), 'binding: decision_malformed'],
      ['an extra member in the record', () => ({ decision: 'approve', [DECISION_RECORD_MEMBER]: { ...rec(), sneaky: 1 } }), 'binding: decision_malformed'],
      ['an upper-case nonce', () => ({ decision: 'approve', [DECISION_RECORD_MEMBER]: { ...rec(), nonce: '0x' + 'AB'.repeat(32) } }), 'binding: nonce_malformed'],
      ['a null record', () => ({ decision: 'approve', [DECISION_RECORD_MEMBER]: null }), 'binding: decision_malformed'],
      ['an approve record in a deny reply', () => ({ decision: 'deny', [DECISION_RECORD_MEMBER]: rec() }), 'binding: decision_malformed'],
    ];
    for (const [name, reply, reason] of cases) {
      const r = rig({ body: BASE, submitRejectVote: true, reply: reply as never });
      expect((await r.handle()).lastError, name).toBe(reason);
      expect(r.acc.submissions, name).toHaveLength(0);
      expect(r.nonces.list(), name).toEqual([]);
    }
    // a `pending` reply carries no decision to bind: withheld, nothing consumed
    const p = rig({ body: BASE, reply: () => ({ decision: 'pending', [DECISION_RECORD_MEMBER]: rec() }) as never });
    expect((await p.handle()).status).toBe('awaiting_policy');
    expect(p.nonces.list()).toEqual([]);
  });

  it('ADV-9 the producer lies about its Grant: a claim equal to the decision but not the head, and a subject asserted for another agent', async () => {
    const ref = { grantId: 'fic-agent-pay', version: 1, grantHash: GRANT_HASH };
    const body = intentBody({ grantRef: ref, subject: subjectClaim() });
    const grantRules = { requireGrant: true, grantorAdi: 'acc://fic-grantor.acme', grantorBook: 'acc://fic-grantor.acme/book' };
    const stale = rig({ body, rules: grantRules, world: fakeWorld({ head: { hash: H('grant-v2'), subject: { adi: 'acc://agent-one.fic-grantor.acme', type: 'agent' } } }), reply: approveFor(body, { grantHash: GRANT_HASH }) });
    expect((await stale.handle()).lastError).toBe('binding: grant_superseded');
    // the intent ASSERTS agent-one, the registry resolves it to agent-two: the Grant is agent-one's
    const other = rig({ body, rules: grantRules, world: fakeWorld({ resolved: { adi: 'acc://agent-two.fic-grantor.acme', type: 'agent' } }), reply: approveFor(body, { grantHash: GRANT_HASH }) });
    expect((await other.handle()).lastError).toBe('binding: grant_subject_mismatch');
    expect(stale.acc.submissions.length + other.acc.submissions.length).toBe(0);
  });

  it('ADV-10 the journal is edited between runs: a deleted journal with a pin on another medium refuses to start', () => {
    const d = tmp();
    const pin = join(tmp(), 'pin', 'journal.pin.json');
    mkdirSync(join(pin, '..'), { recursive: true });
    const j = new DecisionJournal({ path: join(d, 'j.jsonl'), pinPath: pin, logId: 'fic-signer' });
    new NonceStore(j, () => NOW_S);
    j.appendNow('decision.consumed', NOW_S, { requestHash: H('r'), nonce: H('n') });
    rmSync(join(d, 'j.jsonl')); // the attacker deletes the spent nonces
    expect(() => new DecisionJournal({ path: join(d, 'j.jsonl'), pinPath: pin, logId: 'fic-signer' })).toThrow(/log_truncated/);
  });

  it('ADV-11 KNOWN LIMIT (DAX4S-F4): journal AND pin deleted together reads as a fresh signer, so the spent nonces are forgotten; only a pin on another medium prevents the deletion of the journal alone', () => {
    const d = tmp();
    const j = new DecisionJournal({ path: join(d, 'j.jsonl'), logId: 'fic-signer' });
    j.appendNow('decision.consumed', NOW_S, { requestHash: H('r'), nonce: H('n') });
    rmSync(join(d, 'j.jsonl'));
    rmSync(join(d, 'j.jsonl.pin.json'));
    const fresh = new NonceStore(new DecisionJournal({ path: join(d, 'j.jsonl'), logId: 'fic-signer' }), () => NOW_S);
    expect(fresh.list()).toEqual([]); // this is the limit: a writer who can delete both files can un-spend a nonce
    writeFileSync(join(d, 'marker'), 'documented');
  });

  it('ADV-12 KNOWN LIMIT (DAX4S-F5): the record names ONE approver; the signing key comes from the decision evidence, as it always did, and is not tied to that identity', async () => {
    // The binding authenticates WHICH identity approved (APPROVER, authorised by the seat). Which of the signer own keys then casts
    // the vote is still named by `evidence.approverKeyRefs` of the same authenticated reply (T29); the two are not compared. Here a
    // reply bound to APPROVER makes the signer sign with a DIFFERENT named key. An unknown ref is still refused by the keyring.
    const named = new LocalSigner(new Uint8Array(32).fill(8));
    const scope = { page: SIGNER, book: 'acc://o.acme/book', signer: new LocalSigner(new Uint8Array(32).fill(7)), keys: { 'officer-b': named } };
    const withRef = (ref: string) => () => ({ ...approveFor(BASE)(), evidence: { approverKeyRefs: [ref] } });
    const r = rig({ body: BASE, keyring: new MapKeyring([scope]), reply: withRef('officer-b') });
    expect((await r.handle()).status).toBe('signed');
    const receipt = await r.store.getReceipt(TX);
    expect(receipt?.binding?.approver).toBe(APPROVER);
    expect(receipt?.signedBy?.publicKeyHash).toBe(createHash('sha256').update(await named.publicKey()).digest('hex'));
    expect(APPROVER).not.toBe('key:' + receipt?.signedBy?.publicKeyHash); // the identity that approved is not the key that signed
    const unknown = rig({ body: BASE, keyring: new MapKeyring([scope]), reply: withRef('no-such-key') });
    expect((await unknown.handle()).status).toBe('error'); // the keyring refuses an unknown ref; the nonce is spent
    expect(unknown.acc.submissions).toHaveLength(0);
  });
});
