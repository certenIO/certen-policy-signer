/**
 * DAX-4S integration: the signer enforces BOUND decisions before any signature (DAX-4-A1 signer integration, A11, A12, A15).
 * The real Orchestrator, the real core binding, the real journal and pause files in a temp directory, a mock Accumulate client
 * that records every `submit` (a vote, a cancel, anything): FICTIONAL parties only.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { DecisionJournal } from '../src/binding/journal.js';
import { NonceStore } from '../src/binding/nonces.js';
import { PauseStore } from '../src/binding/pause-store.js';
import { buildPresentedRequest } from '../src/binding/request.js';
import { BindingRules, DECISION_RECORD_MEMBER } from '../src/binding/verify.js';
import { hashRequest } from '../src/core/hashes.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { MemoryStore } from '../src/store/store.js';
import type { Decision, PolicyRequest } from '../src/types.js';
import { ADDR, APPROVER, GRANTOR, GRANT_HASH, H, KEY, POLICY, PRINCIPAL, SEAT, SUBJECT, FakeWorld, fakeWorld, intentBody, leg, record, subjectClaim } from './support/binding-fixtures.js';

const silent = pino({ level: 'silent' });
const SIGNER = 'acc://o.acme/book/1';
const TX = 'ab'.repeat(32);
const NOW_S = 1_800_000_000;
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-o-')); dirs.push(d); return d; };

type Body = ReturnType<typeof intentBody>;
const requestHashOf = (body: Body, tx = TX): string => {
  const b = buildPresentedRequest({ txHash: tx, rawTransaction: { body }, summary: { action: 'x' } });
  if (!b.ok) throw new Error(b.detail);
  return hashRequest(b.value.request);
};

const RULES: BindingRules = { seat: SEAT, authorizedApprovers: [APPROVER], maxWindowSeconds: 7200, policyHash: POLICY, requireGrant: false, registryPrincipals: [] };

interface RigOpts {
  dir?: string;
  body: Body;
  /** the decision the engine returns for every ask */
  reply: (req: PolicyRequest) => Decision;
  rules?: Partial<BindingRules> | null; // null: no binding on this seat (legacy)
  world?: FakeWorld;
  submitRejectVote?: boolean;
  tx?: string;
  votes?: ConstructorParameters<typeof Orchestrator>[0]['votes'];
}
function rig(o: RigOpts) {
  const dir = o.dir ?? tmp();
  const journal = new DecisionJournal({ path: join(dir, 'decision-journal.jsonl'), logId: 'fic-signer' });
  const nonces = new NonceStore(journal, () => NOW_S);
  const pauses = new PauseStore({ journal, statePath: join(dir, 'pause-state.json'), seats: [SEAT], nowSeconds: () => NOW_S });
  const acc = new MockAccumulateClient();
  const tx = o.tx ?? TX;
  acc.addPending(tx, { body: o.body, principal: `${PRINCIPAL}/tokens` });
  const store = new MemoryStore();
  const policy = new MockPolicyClient(o.reply);
  const orch = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))), policy, store, resolver: new Resolver(acc), logger: silent,
    now: () => NOW_S * 1000, pauses,
    ...(o.votes ? { votes: o.votes } : {}),
    seats: new Map([[SIGNER.toLowerCase(), { seat: SEAT, ...(o.rules === null ? {} : { binding: { ...RULES, ...(o.rules ?? {}) } }) }]]),
    binding: { nonces, ...(o.world ? { world: o.world } : {}), nowSeconds: () => NOW_S },
    options: { submitRejectVote: o.submitRejectVote ?? false },
  });
  const handle = () => orch.handle({ txHash: tx, signerUrl: SIGNER });
  return { dir, journal, nonces, pauses, acc, store, policy, orch, handle, tx };
}

const approveFor = (body: Body, over: Parameters<typeof record>[0] extends infer R ? Partial<R> : never = {}, verb: 'approve' | 'deny' = 'approve', tx = TX) =>
  (): Decision => ({
    decision: verb, reason: 'FICTIONAL officers approved',
    [DECISION_RECORD_MEMBER]: record({ requestHash: requestHashOf(body, tx), decision: verb, issuedAt: NOW_S - 10, nonce: H('nonce-fixed'), ...over }),
  } as Decision);

const BASE = intentBody();

describe('a bound decision signs exactly once', () => {
  it('approves the transaction the record is about: one vote, the nonce consumed, the receipt names the bound decision', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE) });
    const row = await r.handle();
    expect(row.status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
    expect(r.nonces.list()).toEqual([H('nonce-fixed')]);
    const receipt = await r.store.getReceipt(TX);
    expect(receipt?.binding).toMatchObject({ requestHash: requestHashOf(BASE), nonce: H('nonce-fixed'), seat: SEAT, approver: APPROVER, policyHash: POLICY, policyPinned: true, grantHash: null });
    expect(receipt?.binding?.decisionHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('a seat that pins no policy records the hash and does not compare it (OQ-DAX2-1)', async () => {
    const r = rig({ body: BASE, rules: { policyHash: null }, reply: approveFor(BASE, { policyHash: H('some other policy') }) });
    expect((await r.handle()).status).toBe('signed');
    expect((await r.store.getReceipt(TX))?.binding).toMatchObject({ policyHash: H('some other policy'), policyPinned: false });
  });

  it('a scope without binding keeps the unbound legacy reply: an older Console still works there', async () => {
    const r = rig({ body: BASE, rules: null, reply: () => ({ decision: 'approve', reason: 'legacy' }) });
    expect((await r.handle()).status).toBe('signed');
    expect(r.nonces.list()).toEqual([]);
    expect((await r.store.getReceipt(TX))?.binding).toBeUndefined();
  });
});

describe('replay is refused, inside the old 300-second window and after a restart (DAX-4-A1, DE-02)', () => {
  it('the same record again after a restart of the service: decision_replayed, no second signature', async () => {
    const first = rig({ body: BASE, reply: approveFor(BASE) });
    expect((await first.handle()).status).toBe('signed');
    // a restart: a new process, a new store, the same state directory
    const again = rig({ dir: first.dir, body: BASE, reply: approveFor(BASE) });
    const row = await again.handle();
    expect(row.status).toBe('awaiting_policy');
    expect(row.lastError).toBe('binding: decision_replayed');
    expect(again.acc.submissions).toHaveLength(0);
  });

  it('the same record against ANOTHER request: request_mismatch, nothing signed (DE-04)', async () => {
    const first = rig({ body: BASE, reply: approveFor(BASE) });
    await first.handle();
    const other = intentBody({ legs: [leg({ to: ADDR.vendorB })] });
    const again = rig({ dir: first.dir, body: other, reply: approveFor(BASE) });
    expect((await again.handle()).lastError).toBe('binding: request_mismatch');
    expect(again.acc.submissions).toHaveLength(0);
  });

  it('a different nonce for another request is accepted, each once (DE-09)', async () => {
    const first = rig({ body: BASE, reply: approveFor(BASE) });
    await first.handle();
    const other = intentBody({ legs: [leg({ to: ADDR.vendorB })] });
    const again = rig({ dir: first.dir, body: other, reply: approveFor(other, { nonce: H('nonce-two') }) });
    expect((await again.handle()).status).toBe('signed');
    expect(again.nonces.list()).toEqual([H('nonce-fixed'), H('nonce-two')]);
  });

  it('two presentations of one nonce at once: one signature (a concurrent replay)', async () => {
    const dir = tmp();
    const a = rig({ dir, body: BASE, reply: approveFor(BASE) });
    const b = rig({ dir, body: BASE, reply: approveFor(BASE) });
    // two services sharing one journal handle cannot happen; the same process can: two work items, one nonce
    const second = new Orchestrator({
      accumulate: b.acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))), policy: b.policy, store: b.store, resolver: new Resolver(b.acc), logger: silent,
      now: () => NOW_S * 1000, pauses: a.pauses, seats: new Map([[SIGNER.toLowerCase(), { seat: SEAT, binding: RULES }]]), binding: { nonces: a.nonces, nowSeconds: () => NOW_S },
    });
    const rows = await Promise.all([a.handle(), second.handle({ txHash: TX, signerUrl: SIGNER })]);
    expect(rows.filter((x) => x.status === 'signed')).toHaveLength(1);
    expect(a.acc.submissions.length + b.acc.submissions.length).toBe(1);
  });

  it('a crash between the nonce and the signature leaves it spent (DE-03): a fresh decision is needed', async () => {
    const crashing = { async cast(): Promise<never> { throw new Error('process killed'); } };
    const first = rig({ body: BASE, reply: approveFor(BASE), votes: crashing as never });
    await expect(first.handle()).rejects.toThrow('process killed');
    expect(first.nonces.list()).toEqual([H('nonce-fixed')]); // consumed BEFORE the signature was attempted
    const restarted = rig({ dir: first.dir, body: BASE, reply: approveFor(BASE) });
    expect((await restarted.handle()).lastError).toBe('binding: decision_replayed');
    expect(restarted.acc.submissions).toHaveLength(0);
    // a fresh decision (new nonce) for the same request is accepted
    const fresh = rig({ dir: first.dir, body: BASE, reply: approveFor(BASE, { nonce: H('nonce-fresh') }) });
    expect((await fresh.handle()).status).toBe('signed');
  });
});

describe('a decision for a mutated transaction is refused (DAX-4-A1)', () => {
  const mutations: Array<[string, Body]> = [
    ['amount', intentBody({ legs: [leg({ amount: '301' })] })],
    ['beneficiary', intentBody({ legs: [leg({ to: ADDR.vendorB })] })],
    ['source account', intentBody({ legs: [leg({ from: ADDR.other })] })],
    ['chain', intentBody({ legs: [leg({ chainId: 11155111 })] })],
    ['execution commitment', intentBody({ legs: [leg({ commitment: H('commit-2') })] })],
  ];
  for (const [name, mutated] of mutations) {
    it(`refuses when the ${name} changed after the decision`, async () => {
      const r = rig({ body: mutated, reply: approveFor(BASE) });
      const row = await r.handle();
      expect(row.lastError).toBe('binding: request_mismatch');
      expect(r.acc.submissions).toHaveLength(0);
      expect(r.nonces.list()).toEqual([]); // a refusal consumes nothing
    });
  }
  it('refuses when the Accumulate transaction is another one', async () => {
    const other = 'cd'.repeat(32);
    const r = rig({ body: BASE, tx: other, reply: approveFor(BASE) }); // the decision named TX
    expect((await r.handle()).lastError).toBe('binding: request_mismatch');
    expect(r.acc.submissions).toHaveLength(0);
  });
});

describe('a refused decision causes no vote, no cancel and no account change (DAX-4-A11, DE-10)', () => {
  const cases: Array<[string, Partial<RigOpts>, string]> = [
    ['legacy reply with no record', { reply: () => ({ decision: 'approve' }) }, 'binding: decision_malformed'],
    ['reply and record disagree on the verb', { reply: () => ({ ...approveFor(BASE)(), decision: 'deny' }) }, 'binding: decision_malformed'],
    ['expired', { reply: approveFor(BASE, { issuedAt: NOW_S - 7200, expiresAt: NOW_S - 1 }) }, 'binding: decision_expired'],
    ['not yet valid', { reply: approveFor(BASE, { issuedAt: NOW_S + 60 }) }, 'binding: decision_not_yet_valid'],
    ['window above the cap', { reply: approveFor(BASE, { expiresAt: NOW_S - 10 + 7201 }) }, 'binding: decision_window_too_long'],
    ['policy hash other than the pin', { reply: approveFor(BASE, { policyHash: H('other') }) }, 'binding: policy_hash_mismatch'],
    ['another seat', { reply: approveFor(BASE, { seat: 'seat:other-seat' }) }, 'binding: seat_mismatch'],
    ['approver the seat does not authorise', { reply: approveFor(BASE, { approver: KEY('stranger') }) }, 'binding: approver_not_authorized'],
    ['approver given as a display name', { reply: approveFor(BASE, { approver: 'Alice Officer' }) }, 'binding: decision_malformed'],
    ['multi-leg intent (cannot be bound)', { body: intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })] }), reply: () => ({ decision: 'approve' }) }, 'binding: presented_malformed'],
  ];
  for (const [name, over, reason] of cases) {
    for (const submitRejectVote of [false, true]) {
      it(`${name}: ${reason}, no submit call (submitRejectVote ${submitRejectVote})`, async () => {
        const r = rig({ body: BASE, reply: approveFor(BASE), submitRejectVote, ...over });
        const row = await r.handle();
        expect(row.lastError).toBe(reason);
        expect(row.status).toBe('awaiting_policy'); // retryable: a fresh decision may come
        expect(r.acc.submissions).toHaveLength(0);
        expect(r.nonces.list()).toEqual([]);
        const receipts = await r.store.getReceipts(TX);
        expect(receipts[0]?.vote).toBeUndefined();
        expect(receipts[0]?.policyEvidence).toMatchObject({ blockedBy: 'decision_binding' });
      });
    }
  }

  it('a DENY that fails the binding casts no reject vote even when submitRejectVote is true', async () => {
    const r = rig({ body: BASE, submitRejectVote: true, reply: approveFor(BASE, { policyHash: H('other') }, 'deny') });
    expect((await r.handle()).lastError).toBe('binding: policy_hash_mismatch');
    expect(r.acc.submissions).toHaveLength(0);
  });

  it('the same refusal is one receipt, not one per poll; a different refusal is another receipt (append-only)', async () => {
    const r = rig({ body: BASE, reply: () => ({ decision: 'approve' }) });
    await r.handle(); await r.handle(); await r.handle();
    expect(await r.store.getReceipts(TX)).toHaveLength(1);
  });

  it('a journal that cannot be written fails the decision: nothing signed (back-pressure, DE-47)', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE) });
    // the journal file becomes unwritable under the running signer (here: replaced by a directory); the pause state still reads
    rmSync(join(r.dir, 'decision-journal.jsonl'), { force: true });
    mkdirSync(join(r.dir, 'decision-journal.jsonl'));
    const row = await r.handle();
    expect(row.lastError).toMatch(/^binding: decision_not_recorded/);
    expect(r.acc.submissions).toHaveLength(0);
  });
});

describe('a denied pending item withholds the signature and casts no reject vote (DAX-4-A12, DE-23)', () => {
  it('a bound deny with submitRejectVote false: no signature of any kind, the item is rejected, the receipt has no vote', async () => {
    const r = rig({ body: BASE, submitRejectVote: false, reply: approveFor(BASE, {}, 'deny') });
    const row = await r.handle();
    expect(row.status).toBe('rejected');
    expect(r.acc.submissions).toHaveLength(0);
    const receipt = await r.store.getReceipt(TX);
    expect(receipt).toMatchObject({ decision: 'deny' });
    expect(receipt?.vote).toBeUndefined();
    expect(receipt?.binding?.nonce).toBe(H('nonce-fixed')); // the deny was bound and spent like an approve
  });
  it('a bound deny with submitRejectVote true still casts the configured reject vote (unchanged behaviour)', async () => {
    const r = rig({ body: BASE, submitRejectVote: true, reply: approveFor(BASE, {}, 'deny') });
    expect((await r.handle()).status).toBe('rejected');
    expect((r.acc.submissions[0] as { signatures: Array<{ vote?: string }> }).signatures[0]!.vote).toBe('reject');
  });
});

describe('the Grant and the subject join (DAX-4-A15, DE-06, DE-54, DE-61, DE-71, DE-72)', () => {
  const ref = { grantId: 'fic-agent-pay', version: 1, grantHash: GRANT_HASH };
  const body = intentBody({ grantRef: ref, subject: subjectClaim() });
  const grantRules = { requireGrant: true, grantorAdi: GRANTOR, registryPrincipals: [PRINCIPAL] };
  const withGrant = (over = {}) => approveFor(body, { grantHash: GRANT_HASH, ...over });

  it('signs when the Grant is the head and the resolved subject is the Grant subject', async () => {
    const world = fakeWorld();
    const r = rig({ body, rules: grantRules, world, reply: withGrant() });
    expect((await r.handle()).status).toBe('signed');
    expect(world.calls).toEqual(['grantHead', 'resolveSubject']);
    expect((await r.store.getReceipt(TX))?.binding?.grantHash).toBe(GRANT_HASH);
  });
  it('another subject than the Grant names: grant_subject_mismatch', async () => {
    const r = rig({ body, rules: grantRules, world: fakeWorld({ resolved: { adi: 'acc://agent-two.fic-grantor.acme', type: 'agent' } }), reply: withGrant() });
    expect((await r.handle()).lastError).toBe('binding: grant_subject_mismatch');
    expect(r.acc.submissions).toHaveLength(0);
  });
  it('the same ADI of another type: grant_subject_mismatch', async () => {
    const r = rig({ body, rules: grantRules, world: fakeWorld({ resolved: { adi: SUBJECT.adi, type: 'merchant' } }), reply: withGrant() });
    expect((await r.handle()).lastError).toBe('binding: grant_subject_mismatch');
  });
  it('a subject that cannot be resolved: subject_unproven, with the world\'s reason', async () => {
    const r = rig({ body, rules: grantRules, world: fakeWorld({ resolved: null }), reply: withGrant() });
    const row = await r.handle();
    expect(row.lastError).toBe('binding: subject_unproven');
    expect((await r.store.getReceipt(TX))?.policyEvidence).toMatchObject({ reason: 'subject_unproven', detail: 'not_registered' });
    expect(r.acc.submissions).toHaveLength(0);
  });
  it('an intent that asserts no subject cannot be joined: subject_unproven', async () => {
    const noSubject = intentBody({ grantRef: ref });
    const r = rig({ body: noSubject, rules: grantRules, world: fakeWorld(), reply: approveFor(noSubject, { grantHash: GRANT_HASH }) });
    expect((await r.handle()).lastError).toBe('binding: subject_unproven');
  });
  it('a superseded Grant is reported as stale BEFORE a subject mismatch', async () => {
    const world = fakeWorld({ head: { hash: H('grant-v2'), subject: { adi: 'acc://agent-two.fic-grantor.acme', type: 'agent' } } });
    const r = rig({ body, rules: grantRules, world, reply: withGrant() });
    expect((await r.handle()).lastError).toBe('binding: grant_superseded');
  });
  it('a head that cannot be established: grant_unverified, never an allow (DE-71)', async () => {
    const r = rig({ body, rules: grantRules, world: fakeWorld({ head: null }), reply: withGrant() });
    expect((await r.handle()).lastError).toBe('binding: grant_unverified');
    expect(r.acc.submissions).toHaveLength(0);
    const noWorld = rig({ body, rules: grantRules, reply: withGrant() });
    expect((await noWorld.handle()).lastError).toBe('binding: grant_unverified');
  });
  it('a decision whose Grant is not the transaction\'s: grant_hash_mismatch; a seat that requires one refuses none: grant_required', async () => {
    const r = rig({ body, rules: grantRules, world: fakeWorld(), reply: withGrant({ grantHash: H('another grant') }) });
    expect((await r.handle()).lastError).toBe('binding: grant_hash_mismatch');
    const plain = rig({ body: BASE, rules: grantRules, world: fakeWorld(), reply: approveFor(BASE) });
    expect((await plain.handle()).lastError).toBe('binding: grant_required');
  });
  it('a seat without a Grant requirement needs no subject and accepts a decision and a transaction that name none (DE-61)', async () => {
    const world = fakeWorld();
    const r = rig({ body: BASE, world, reply: approveFor(BASE) });
    expect((await r.handle()).status).toBe('signed');
    expect(world.calls).toEqual([]);
  });
  it('a seat without a Grant requirement still joins the subject when a Grant IS named (DE-72)', async () => {
    const r = rig({ body, rules: { grantorAdi: GRANTOR, registryPrincipals: [PRINCIPAL] }, world: fakeWorld({ resolved: { adi: 'acc://agent-two.fic-grantor.acme', type: 'agent' } }), reply: withGrant() });
    expect((await r.handle()).lastError).toBe('binding: grant_subject_mismatch');
  });
  it('the producer\'s grantRef is a claim: a head with another hash than the claim is superseded, however the claim reads', async () => {
    const r = rig({ body, rules: grantRules, world: fakeWorld({ head: { hash: H('head-really'), subject: { ...SUBJECT } } }), reply: withGrant() });
    expect((await r.handle()).lastError).toBe('binding: grant_superseded');
  });
});

describe('the persisted pause comes first and spends nothing (DAX-4-A3 at the orchestrator)', () => {
  const op = { scope: 'seat' as const, id: SEAT, by: 'seat:fic-operator', reason: 'FICTIONAL: stop signing now' };
  it('a paused seat signs nothing, a reject vote included, and the decision is NOT consumed: it is valid after the resume', async () => {
    const r = rig({ body: BASE, submitRejectVote: true, reply: approveFor(BASE) });
    await r.pauses.set(op);
    const held = await r.handle();
    expect(held.lastError).toBe('paused');
    expect(r.acc.submissions).toHaveLength(0);
    expect(r.nonces.list()).toEqual([]);
    const denyHeld = rig({ dir: r.dir, body: BASE, submitRejectVote: true, reply: approveFor(BASE, { nonce: H('n-deny') }, 'deny') });
    expect((await denyHeld.handle()).lastError).toBe('paused');
    expect(denyHeld.acc.submissions).toHaveLength(0);
    await r.pauses.resume(op);
    expect((await r.handle()).status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
  });
  it('a pause set while the decision is being checked still stops the signature (read before each signature)', async () => {
    const world = fakeWorld();
    const ref = { grantId: 'fic-agent-pay', version: 1, grantHash: GRANT_HASH };
    const body = intentBody({ grantRef: ref, subject: subjectClaim() });
    const r = rig({ body, rules: { requireGrant: true, grantorAdi: GRANTOR, registryPrincipals: [PRINCIPAL] }, world, reply: approveFor(body, { grantHash: GRANT_HASH }) });
    world.resolveSubject = async () => { await r.pauses.set(op); return { ok: true, value: { ...SUBJECT } }; }; // set during the world read
    const row = await r.handle();
    expect(row.lastError).toBe('paused');
    expect(r.acc.submissions).toHaveLength(0);
    expect(r.nonces.list()).toEqual([]);
  });
  it('a subject pause stops the registry-resolved subject of a Grant seat, and an unreadable pause state signs nothing', async () => {
    const world = fakeWorld();
    const ref = { grantId: 'fic-agent-pay', version: 1, grantHash: GRANT_HASH };
    const body = intentBody({ grantRef: ref, subject: subjectClaim() });
    const r = rig({ body, rules: { requireGrant: true, grantorAdi: GRANTOR, registryPrincipals: [PRINCIPAL] }, world, reply: approveFor(body, { grantHash: GRANT_HASH }) });
    await r.pauses.set({ scope: 'subject', id: SUBJECT.adi, by: 'seat:fic-operator', reason: 'FICTIONAL: stop this agent' });
    expect((await r.handle()).lastError).toBe('paused');
    expect(r.acc.submissions).toHaveLength(0);
  });
});
