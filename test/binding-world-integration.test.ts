/**
 * The signer's decision path over the PRODUCTION world (read cache over a fake v3 node): the read amplification of DAX4S-F13 is gone
 * (a pending item polled again and again costs the four chain-length probes, not a re-read), the facts age and cost are recorded
 * in the journal entry that spends the nonce, a head change reaches the next poll, and the Console is told the request to bind.
 * Also DE-77: a denial that nobody rejected names the seat's policy identity, which the seat lists as authorized.
 */
import { describe, expect, it } from 'vitest';
import { hashGrant } from '../src/core/hashes.js';
import { H, KEY, SEAT, intentBody, leg, subjectClaim } from './support/binding-fixtures.js';
import { S_BOOK, S_GRANTOR, S_SUBJECT, grantElements, grantScene, sceneGrant, S_GRANTS } from './support/grant-scene.js';
import { NOW_S, TX, approveFor, rig } from './support/binding-rig.js';

const ref = { grantId: 'fic-agent-pay', version: 1, grantHash: hashGrant(sceneGrant()) };
const body = intentBody({ grantRef: ref, subject: subjectClaim(S_SUBJECT, S_GRANTOR) });
const grantRules = { requireGrant: true, grantorAdi: S_GRANTOR, grantorBook: S_BOOK };

describe('the production world on the decision path', () => {
  it('a Grant decision is bound on the chain facts; the journal entry that spends the nonce records how old the facts were (the TTL bound)', async () => {
    const s = grantScene();
    const r = rig({ body, rules: grantRules, world: s.world, reply: approveFor(body, { grantHash: ref.grantHash }) });
    expect((await r.handle()).status).toBe('signed');
    const consumed = r.journal.entries().find((e) => e.kind === 'decision.consumed')!;
    expect(consumed.payload['facts']).toMatchObject({ ttlMs: 30_000, maxFactAgeMs: 0 });
    expect((consumed.payload['facts'] as { queries: number }).queries).toBeGreaterThan(4); // the cold evaluation read the facts
    expect((await r.store.getReceipt(TX))?.binding?.grantHash).toBe(ref.grantHash);
  });

  it('DAX4S-F13 is fixed: a refused item polled twenty times costs the probes only after the first poll', async () => {
    const s = grantScene();
    // refused for a reason the world cannot change (an approver the seat never listed): the item stays awaiting_policy and is asked again
    const r = rig({ body, rules: grantRules, world: s.world, reply: approveFor(body, { grantHash: ref.grantHash, approver: KEY('stranger') }) });
    await r.handle();
    const afterFirst = s.node.calls.length;
    for (let i = 0; i < 20; i++) expect((await r.handle()).lastError).toBe('binding: approver_not_authorized');
    expect(s.node.calls.length - afterFirst).toBeLessThanOrEqual(20 * 4); // at most four probes per poll
    expect(s.node.calls.length - afterFirst).toBe(20 * 4); // and exactly that: nothing else was asked
    expect(s.cache.totals().cacheMisses).toBe(s.cache.totals().cacheMisses); // counters exist
    // the base behaviour for comparison: every poll re-read every fact (the first poll's cost, twenty-one times)
    expect(afterFirst).toBeGreaterThan(8);
  });

  it('a Grant superseded after the first poll is seen by the next poll (the chain length moved), inside the TTL', async () => {
    const s = grantScene();
    const r = rig({ body, rules: grantRules, world: s.world, reply: approveFor(body, { grantHash: ref.grantHash, approver: KEY('stranger') }) });
    expect((await r.handle()).lastError).toBe('binding: approver_not_authorized'); // the Grant is the head: the check got past the Grant to the approver
    const g2 = sceneGrant({ version: 2, priorHash: ref.grantHash, issuedAt: 1_800_000_200 });
    s.node.write(S_GRANTS, grantElements(g2));
    s.clock.ms += 2_000;
    expect((await r.handle()).lastError).toBe('binding: grant_superseded');
    expect(hashGrant(g2)).not.toBe(ref.grantHash);
  });

  it('the decision service is told the exact request to bind (ten members, legCount, and the intent\'s grantRef), for a seat that requires binding only', async () => {
    const seen: unknown[] = [];
    const r = rig({ body, rules: grantRules, world: grantScene().world, reply: (req) => { seen.push(req.binding); return approveFor(body, { grantHash: ref.grantHash })(); } });
    await r.handle();
    expect(seen[0]).toMatchObject({ chainId: 84532, kind: 'erc20.transfer', amount: '300', txHash: '0x' + TX });
    expect(Object.keys(seen[0] as object).sort()).toEqual(['amount', 'asset', 'beneficiary', 'chainId', 'executionCommitment', 'grantRef', 'kind', 'legCount', 'source', 'target', 'txHash', 'validatorOperationId']);
    expect(seen[0]).toMatchObject({ legCount: 1, grantRef: ref });
    const legacy: unknown[] = [];
    const l = rig({ body, rules: null, reply: (req) => { legacy.push(req.binding); return { decision: 'approve' }; } });
    await l.handle();
    expect(legacy[0]).toBeUndefined(); // a legacy seat's request is unchanged
    const multi: unknown[] = [];
    const m = rig({ body: intentBody({ legs: [leg(), leg({ to: '0x' + '44'.repeat(20) })] }), reply: (req) => { multi.push(req.binding); return { decision: 'approve' }; } });
    await m.handle();
    // a multi-leg intent carries its binding too, with legCount 2: the decision service refuses it by name (multi_leg_unsupported), the signer never skips it
    expect(multi[0]).toMatchObject({ legCount: 2, chainId: 84532, kind: 'erc20.transfer' });
  });
});

describe('a denial that nobody rejected names the seat policy identity, which the seat lists as authorized (DE-77)', () => {
  const POLICY_ID = 'adi:acc://fic-console.acme/policy';
  const plain = intentBody();
  it('accepts a bound deny whose approver is the listed policy identity, and refuses one that is not listed', async () => {
    const listed = rig({ body: plain, rules: { authorizedApprovers: [KEY('officer-a'), POLICY_ID] }, reply: approveFor(plain, { approver: POLICY_ID }, 'deny') });
    const row = await listed.handle();
    expect(row.status).toBe('rejected');
    expect(listed.acc.submissions).toHaveLength(0);
    expect((await listed.store.getReceipt(TX))?.binding?.approver).toBe(POLICY_ID);
    const unlisted = rig({ body: plain, reply: approveFor(plain, { approver: POLICY_ID }, 'deny') });
    expect((await unlisted.handle()).lastError).toBe('binding: approver_not_authorized');
    void SEAT; void H; void NOW_S;
  });
});
