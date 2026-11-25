/**
 * DAX-F216 — a seat's DEFINITE refusal ends on chain as the seat's bound reject.
 *
 * Live (tcl98, 2026-11-25, transaction ea22300d): a Grant-less treasury funding payment at two seats that require a Grant. Both seats refused it
 * grant_required; the Console could issue no deny record the binding would accept (the core refused a deny of a Grant-less request as grant_required,
 * the very reason it was being denied), the signer refused the recordless deny (decision_malformed, record_absent), and nothing ever rejected the
 * payment: it stood pending on its payer, which then cannot be proven at settlement.
 *
 * DE-115: a deny is bound without the Grant checks that refuse an approval; only the agreement of decision and transaction about the Grant applies.
 * The real Orchestrator, the real core binding, the real journal; the mock Accumulate client records every `submit`. FICTIONAL parties only.
 */
import { describe, expect, it } from 'vitest';
import { GRANTOR, GRANTOR_BOOK, GRANT_HASH, H, SUBJECT, fakeWorld, intentBody, subjectClaim } from './support/binding-fixtures.js';
import { TX, approveFor, rig } from './support/binding-rig.js';

const BASE = intentBody();
const grantRules = { requireGrant: true, grantorAdi: GRANTOR, grantorBook: GRANTOR_BOOK };
const reject = (r: ReturnType<typeof rig>) => (r.acc.submissions as Array<{ signatures: Array<{ vote?: string }> }>).map((s) => s.signatures[0]!.vote);

describe('DAX-F216: a bound deny of a definite refusal is cast as the seat\'s reject (DE-115)', () => {
  it('a seat that requires a Grant: the grant_required deny of a Grant-less payment is bound, the reject vote is cast and the decision is spent', async () => {
    const r = rig({ body: BASE, rules: grantRules, world: fakeWorld(), submitRejectVote: true, reply: approveFor(BASE, { grantHash: null, reason: 'grant_required' }, 'deny') });
    const row = await r.handle();
    expect(row.status, row.lastError).toBe('rejected');
    expect(reject(r)).toEqual(['reject']);
    expect(r.nonces.list()).toEqual([H('nonce-fixed')]);
    const receipt = await r.store.getReceipt(TX);
    expect(receipt).toMatchObject({ decision: 'deny', vote: 'reject' });
    expect(receipt?.binding).toMatchObject({ grantHash: null, nonce: H('nonce-fixed') });
  });

  it('the control: an APPROVAL of the same Grant-less payment is still refused grant_required and nothing is signed', async () => {
    const r = rig({ body: BASE, rules: grantRules, world: fakeWorld(), submitRejectVote: true, reply: approveFor(BASE, { grantHash: null }) });
    expect((await r.handle()).lastError).toBe('binding: grant_required');
    expect(r.acc.submissions).toHaveLength(0);
    expect(r.nonces.list()).toEqual([]);
  });

  it('the control: a deny WITHOUT a record is still refused record_absent and nothing is signed (an unbound decision is never acted on)', async () => {
    const r = rig({ body: BASE, rules: grantRules, world: fakeWorld(), submitRejectVote: true, reply: () => ({ decision: 'deny', reason: 'grant_required' }) });
    expect((await r.handle()).lastError).toBe('binding: decision_malformed');
    expect(r.acc.submissions).toHaveLength(0);
    expect((await r.store.getReceipt(TX))?.policyEvidence).toMatchObject({ reason: 'decision_malformed', detail: 'record_absent' });
  });

  describe('a payment that names a Grant', () => {
    const ref = { grantId: 'fic-agent-pay', version: 1, grantHash: GRANT_HASH };
    const body = intentBody({ grantRef: ref, subject: subjectClaim() });
    const deny = (over = {}) => approveFor(body, { grantHash: GRANT_HASH, ...over }, 'deny');

    it('a superseded Grant: the deny of the stale claim is bound and rejected (an approval of it is grant_superseded)', async () => {
      const world = fakeWorld({ head: { hash: H('grant-v2'), subject: { ...SUBJECT } } });
      const r = rig({ body, rules: grantRules, world, submitRejectVote: true, reply: deny({ reason: 'grant_superseded' }) });
      expect((await r.handle()).status).toBe('rejected');
      expect(reject(r)).toEqual(['reject']);
      const approve = rig({ body, rules: grantRules, world: fakeWorld({ head: { hash: H('grant-v2'), subject: { ...SUBJECT } } }), reply: approveFor(body, { grantHash: GRANT_HASH }) });
      expect((await approve.handle()).lastError).toBe('binding: grant_superseded');
    });

    it('a head that cannot be established, another subject, no resolved subject: each deny is bound and rejected', async () => {
      for (const world of [fakeWorld({ head: null }), fakeWorld({ resolved: { adi: 'acc://agent-two.fic-grantor.acme', type: 'agent' } }), fakeWorld({ resolved: null })]) {
        const r = rig({ body, rules: grantRules, world, submitRejectVote: true, reply: deny() });
        const row = await r.handle();
        expect(row.status, row.lastError).toBe('rejected');
        expect(reject(r)).toEqual(['reject']);
      }
    });

    it('a deny that names another Grant than its transaction is still grant_hash_mismatch: nothing is cast', async () => {
      const r = rig({ body, rules: grantRules, world: fakeWorld(), submitRejectVote: true, reply: deny({ grantHash: H('another grant') }) });
      expect((await r.handle()).lastError).toBe('binding: grant_hash_mismatch');
      expect(r.acc.submissions).toHaveLength(0);
      const none = rig({ body, rules: grantRules, world: fakeWorld(), submitRejectVote: true, reply: deny({ grantHash: null }) });
      expect((await none.handle()).lastError).toBe('binding: grant_hash_mismatch');
      expect(none.acc.submissions).toHaveLength(0);
    });
  });

  it('recovery: a transaction whose recordless deny was refused on every earlier poll is rejected on the first poll that carries the bound deny', async () => {
    let answer: 'recordless' | 'bound' = 'recordless';
    const bound = approveFor(BASE, { grantHash: null, reason: 'grant_required' }, 'deny');
    const r = rig({ body: BASE, rules: grantRules, world: fakeWorld(), submitRejectVote: true, reply: () => (answer === 'recordless' ? { decision: 'deny', reason: 'grant_required' } : bound()) as never });
    for (let i = 0; i < 3; i++) expect((await r.handle()).status).toBe('awaiting_policy'); // the old Console: retryable, nothing signed
    expect(r.acc.submissions).toHaveLength(0);
    answer = 'bound'; // the upgraded Console answers the same request with its bound deny
    expect((await r.handle()).status).toBe('rejected');
    expect(reject(r)).toEqual(['reject']);
  });
});
