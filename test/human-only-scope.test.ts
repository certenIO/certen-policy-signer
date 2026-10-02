/**
 * G-69: a party with no machine page can run a seat.
 *
 * A human-only scope (`wallet.human_scopes`) is discovered, resolved, stored and decided exactly as a keyed
 * scope, and this signer NEVER signs for it: a decision that needs a signature becomes `awaiting_human`, a
 * person signs through officer intake (test/phase7-officer-intake.test.ts drives that end to end), and the
 * landed signature ends the request. Config validation, poller discovery (account and header authority),
 * the orchestrator (approve, deny, pending, G-65, already-decided), the landed hook, and a FileStore restart.
 * All parties FICTIONAL: summit-inspection-tcl1 is the second inspection firm, with only book/1 and people.
 */
import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { loadConfig, isIntakeOnly } from '../src/config.js';
import { MockAccumulateClient, type AccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient, type PolicyClient } from '../src/policy/policy.js';
import { FileStore, MemoryStore, type Store } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring, noKeyKeyring, MapKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Poller } from '../src/poller.js';
import { recordHumanSignature } from '../src/officer/landed.js';
import type { PageState } from '../src/ops/rotate.js';
import type { Decision } from '../src/types.js';

const silent = pino({ level: 'silent' });
const SUMMIT_P1 = 'acc://summit-inspection-tcl1.acme/book/1';
const SUMMIT_BOOK = 'acc://summit-inspection-tcl1.acme/book';
const TX = '5a'.repeat(32);
const KEY_A = 'a1'.repeat(32);

/* ------------------------------------------------------------------ */
/* config                                                              */
/* ------------------------------------------------------------------ */

describe('config: wallet.human_scopes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'g69-'));
  let n = 0;
  const load = (wallet: string, extra = '') => {
    const p = join(dir, `c${n++}.yaml`);
    writeFileSync(p, `wallet:
  org_id: "summit-inspection-tcl1 (FICTIONAL)"
  accumulate_endpoints: ["http://127.0.0.1:1/v3"]
${wallet}
policy:
  url: "http://127.0.0.1:9099/decision"
${extra}`);
    return loadConfig(p);
  };
  const intake = (pages: string[], enabled = true) => `officer_intake:\n  enabled: ${enabled}\n  human_pages: [${pages.map((p) => `"${p}"`).join(', ')}]`;
  const human = `  human_scopes:\n    - { page: "${SUMMIT_P1}" }`;

  it('a human-only signer: no key anywhere, a policy engine, and not intake-only', () => {
    const cfg = load(human, intake([SUMMIT_P1]));
    expect(cfg.wallet.human_scopes).toEqual([{ page: SUMMIT_P1 }]);
    expect(isIntakeOnly(cfg)).toBe(false);
    expect(cfg.signer).toBeUndefined();
    expect(cfg.wallet.scopes).toBeUndefined();
  });

  it('needs a policy engine (it decides), unlike intake-only', () => {
    const p = join(dir, 'nopolicy.yaml');
    writeFileSync(p, `wallet:\n  org_id: "x"\n  accumulate_endpoints: ["http://127.0.0.1:1/v3"]\n${human}\n${intake([SUMMIT_P1])}\n`);
    expect(() => loadConfig(p)).toThrow(/policy is required/);
  });

  it('refuses a key on a human-only scope, in any form', () => {
    // `.strict()`: there is no key field to write into.
    expect(() => load(`  human_scopes:\n    - { page: "${SUMMIT_P1}", key: { provider: "local", local: { allow_ephemeral: true } } }`, intake([SUMMIT_P1]))).toThrow();
    // The same page as a keyed scope.
    expect(() => load(`  scopes:\n    - { page: "${SUMMIT_P1}", key: { provider: "local", local: { allow_ephemeral: true } } }\n${human}`, intake([SUMMIT_P1])))
      .toThrow(/both a human-only scope and a keyed scope/);
    // The same page as signer_url + signer.
    expect(() => load(`  signer_url: "${SUMMIT_P1}"\n${human}`, `${intake([SUMMIT_P1])}\nsigner: { provider: "local", local: { allow_ephemeral: true } }`))
      .toThrow(/both a human-only scope and a keyed scope/);
  });

  it('the page must be a key page listed in officer_intake.human_pages, with intake enabled, once', () => {
    expect(() => load(human, intake(['acc://summit-inspection-tcl1.acme/book/2']))).toThrow(/must be listed in officer_intake.human_pages/);
    expect(() => load(human)).toThrow(/requires officer_intake.enabled/);
    expect(() => load(`  human_scopes:\n    - { page: "${SUMMIT_BOOK}" }`, intake([SUMMIT_P1]))).toThrow(/key page URL/);
    expect(() => load(`${human}\n    - { page: "${SUMMIT_P1.toUpperCase().replace('ACC://', 'acc://')}" }`, intake([SUMMIT_P1]))).toThrow(/twice/);
  });

  it('sits beside keyed scopes', () => {
    const cfg = load(`  scopes:\n    - { page: "acc://summit-inspection-tcl1.acme/book/2", key: { provider: "local", local: { allow_ephemeral: true } } }\n${human}`, intake([SUMMIT_P1]));
    expect(cfg.wallet.scopes).toHaveLength(1);
    expect(cfg.wallet.human_scopes).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ */
/* poller                                                              */
/* ------------------------------------------------------------------ */

describe('poller: a human-only page is discovered like any other', () => {
  it('as an account authority (the page Pending index) and as a header authority (the book signature chain)', async () => {
    const VIA_PENDING = '01'.repeat(32);
    const VIA_SIGCHAIN = '02'.repeat(32);
    const acc = {
      listPendingForSigner: vi.fn(async (page: string) => (page === SUMMIT_P1 ? [VIA_PENDING] : [])),
      listPendingViaSignatureChain: vi.fn(async (book: string) => (book === SUMMIT_BOOK ? [VIA_SIGCHAIN] : [])),
    } as unknown as AccumulateClient;
    const handled: Array<{ txHash: string; signerUrl: string }> = [];
    const orch = { handle: async (r: { txHash: string; signerUrl: string }) => { handled.push(r); return {} as never; } } as unknown as Orchestrator;
    const p = new Poller(acc, orch, SUMMIT_P1, 60_000, silent, Date.now, undefined, SUMMIT_BOOK);
    p.start();
    await vi.waitFor(() => expect(handled).toHaveLength(2));
    p.stop();
    expect(handled).toEqual([{ txHash: VIA_PENDING, signerUrl: SUMMIT_P1 }, { txHash: VIA_SIGCHAIN, signerUrl: SUMMIT_P1 }]);
    expect(p.healthy()).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* orchestrator                                                        */
/* ------------------------------------------------------------------ */

const PAYMENT = { type: 'sendTokens', to: [{ url: 'acc://fictional-payee-tcl1.acme/tokens', amount: '5000' }] };

function seat(o: {
  policy: PolicyClient; store?: Store; body?: { type: string; [k: string]: unknown }; principal?: string;
  submitRejectVote?: boolean; readPage?: (p: string) => Promise<PageState>; keyring?: 'wildcard' | 'none';
}) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, {
    body: o.body ?? PAYMENT, principal: o.principal ?? 'acc://fictional-payer-tcl1.acme/tokens',
    rawTransaction: { header: { principal: o.principal ?? 'acc://fictional-payer-tcl1.acme/tokens', authorities: [SUMMIT_BOOK] }, body: o.body ?? PAYMENT },
  });
  const store = o.store ?? new MemoryStore();
  // The wildcard keyring WOULD sign for any page. A human-only seat must not use it even so.
  const keyring = o.keyring === 'none' ? noKeyKeyring('human-only signer') : singleKeyring(new LocalSigner(new Uint8Array(32).fill(3)), SUMMIT_P1);
  const orchestrator = new Orchestrator({
    accumulate: acc, keyring, policy: o.policy, store, resolver: new Resolver(acc), logger: silent,
    humanOnlyPages: [SUMMIT_P1], ...(o.readPage ? { readPage: o.readPage } : {}),
    options: { submitRejectVote: o.submitRejectVote ?? true },
  });
  return { acc, store, orchestrator, go: () => orchestrator.handle({ txHash: TX, signerUrl: SUMMIT_P1 }) };
}

describe('orchestrator: a human-only seat never signs', () => {
  it('approve -> awaiting_human: no signature, PolicyRequest stored, receipt keeps the decision and says whose signature is owed', async () => {
    const s = seat({ policy: new MockPolicyClient({ decision: 'approve', reason: 'FICTIONAL rule: inspection accepted', evidence: { ruleSetVersion: 'summit-rules-1' } }) });
    const r = await s.go();
    expect(r).toMatchObject({ status: 'awaiting_human', decision: 'approve' });
    expect(s.acc.submissions).toHaveLength(0);
    const pr = await s.store.getPolicyRequest(TX);
    expect(pr).toMatchObject({ txHash: TX, signerUrl: SUMMIT_P1, header: { authorities: [SUMMIT_BOOK] } });
    expect(pr?.display?.length).toBeGreaterThan(0);
    expect(pr?.summaryHash).toMatch(/^[0-9a-f]{64}$/);
    const receipt = await s.store.getReceipt(TX);
    expect(receipt).toMatchObject({ decision: 'approve', reason: 'FICTIONAL rule: inspection accepted', policyEvidence: { ruleSetVersion: 'summit-rules-1', awaitingHumanSignature: { page: SUMMIT_P1, vote: 'approve' } } });
    expect(receipt?.vote).toBeUndefined();
    expect(receipt?.signedBy).toBeUndefined();
  });

  it('deny with submit_reject_vote -> awaiting_human (a person casts the reject); without it -> rejected; never a signature', async () => {
    const s1 = seat({ policy: new MockPolicyClient({ decision: 'deny', reason: 'FICTIONAL' }), submitRejectVote: true });
    expect(await s1.go()).toMatchObject({ status: 'awaiting_human', decision: 'deny' });
    expect((await s1.store.getReceipt(TX))?.policyEvidence).toMatchObject({ awaitingHumanSignature: { vote: 'reject' } });
    expect(s1.acc.submissions).toHaveLength(0);

    const s2 = seat({ policy: new MockPolicyClient({ decision: 'deny', reason: 'FICTIONAL' }), submitRejectVote: false });
    expect((await s2.go()).status).toBe('rejected');
    expect(s2.acc.submissions).toHaveLength(0);
  });

  it('works with a keyring that holds no key at all', async () => {
    const s = seat({ policy: new MockPolicyClient({ decision: 'approve' }), keyring: 'none' });
    expect((await s.go()).status).toBe('awaiting_human');
  });

  it('pending is held exactly as for a keyed seat, with the G-64 hold record', async () => {
    const s = seat({ policy: new MockPolicyClient({ decision: 'pending', reason: 'waiting on the FICTIONAL inspection-status provider', evidence: { ruleSetVersion: 'summit-rules-1' } }) });
    const r = await s.go();
    expect(r).toMatchObject({ status: 'awaiting_policy', pending: { reason: 'waiting on the FICTIONAL inspection-status provider', versions: { ruleSetVersion: 'summit-rules-1' } } });
    expect(s.acc.submissions).toHaveLength(0);
  });

  it('once awaiting_human, a later poll does not ask the engine again; the transaction going away ends it', async () => {
    const policy = new MockPolicyClient({ decision: 'approve' });
    const decide = vi.spyOn(policy, 'decide');
    const s = seat({ policy });
    await s.go();
    expect((await s.go()).status).toBe('awaiting_human');
    expect(decide).toHaveBeenCalledTimes(1);
    s.acc.pending.get(TX)!.executed = true;
    expect((await s.go()).status).toBe('signed');
    expect(s.acc.submissions).toHaveLength(0);
  });

  it('G-65 applies: an approve of a change that would brick the page is refused, not routed to a person', async () => {
    const page: PageState = { version: 1, threshold: 1, keyHashes: [KEY_A], entries: [{ keyHash: KEY_A, delegate: null }] };
    const s = seat({
      policy: new MockPolicyClient({ decision: 'approve' }), principal: SUMMIT_P1, readPage: async () => page,
      body: { type: 'updateKeyPage', operation: [{ type: 'setThreshold', threshold: 2 }] },
    });
    expect(await s.go()).toMatchObject({ status: 'rejected', lastError: 'keypage_guard: threshold_exceeds_entries' });
    expect(s.acc.submissions).toHaveLength(0);
  });

  it('a keyed page in the same process still signs (the human-only list is per page)', async () => {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body: PAYMENT, principal: 'acc://fictional-payer-tcl1.acme/tokens' });
    const KEYED = 'acc://summit-inspection-tcl1.acme/book/2';
    const o = new Orchestrator({
      accumulate: acc, keyring: new MapKeyring([{ page: KEYED, book: SUMMIT_BOOK, signer: new LocalSigner(new Uint8Array(32).fill(4)) }]),
      policy: new MockPolicyClient({ decision: 'approve' }), store: new MemoryStore(), resolver: new Resolver(acc), logger: silent, humanOnlyPages: [SUMMIT_P1],
    });
    expect((await o.handle({ txHash: TX, signerUrl: KEYED })).status).toBe('signed');
    expect(acc.submissions).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ */
/* the landed hook and a restart                                       */
/* ------------------------------------------------------------------ */

describe('a landed personal signature ends the request; all of it survives a restart', () => {
  const landed = { txHash: TX, authority: SUMMIT_P1, page: SUMMIT_P1, delegators: [] as string[], keyHash: 'b2'.repeat(32), vote: 'approve' as const };

  it('only an awaiting_human request for the page the signature satisfied is ended', async () => {
    const s = seat({ policy: new MockPolicyClient({ decision: 'approve' }) });
    await s.go();
    expect(await recordHumanSignature(s.store, { ...landed, authority: 'acc://summit-inspection-tcl1.acme/book/2' })).toBe(false);
    expect((await s.store.get(TX))?.status).toBe('awaiting_human');
    expect(await recordHumanSignature(s.store, { ...landed, txHash: 'ff'.repeat(32) })).toBe(false);
    expect(await recordHumanSignature(s.store, landed)).toBe(true);
    expect((await s.store.get(TX))?.status).toBe('signed');
    expect(await s.store.getReceipt(TX)).toMatchObject({
      decision: 'approve', vote: 'approve',
      signedBy: { page: SUMMIT_P1, signatureType: 'ecdsaSha256', publicKeyHash: landed.keyHash, delegators: [] },
      policyEvidence: { awaitingHumanSignature: { page: SUMMIT_P1, vote: 'approve' } },
    });
    // Finished: a second landing changes nothing.
    expect(await recordHumanSignature(s.store, landed)).toBe(false);
  });

  it('a reject vote ends it as rejected', async () => {
    const s = seat({ policy: new MockPolicyClient({ decision: 'deny' }), submitRejectVote: true });
    await s.go();
    expect(await recordHumanSignature(s.store, { ...landed, vote: 'reject' })).toBe(true);
    expect((await s.store.get(TX))?.status).toBe('rejected');
  });

  it('FileStore: awaiting_human, the stored request and the receipt survive a restart; the engine is not asked again', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'g69-store-')), 'state.json');
    const first = seat({ policy: new MockPolicyClient({ decision: 'approve', reason: 'FICTIONAL rule passed' }), store: new FileStore(path) });
    expect((await first.go()).status).toBe('awaiting_human');

    const reopened = new FileStore(path);
    expect((await reopened.get(TX))?.status).toBe('awaiting_human');
    expect((await reopened.getPolicyRequest(TX))?.summaryHash).toMatch(/^[0-9a-f]{64}$/);
    expect((await reopened.getReceipt(TX))?.policyEvidence).toMatchObject({ awaitingHumanSignature: { page: SUMMIT_P1 } });

    const policy = new MockPolicyClient({ decision: 'deny' });
    const decide = vi.spyOn(policy, 'decide');
    const second = seat({ policy, store: reopened });
    expect((await second.go()).status).toBe('awaiting_human');
    expect(decide).not.toHaveBeenCalled();

    expect(await recordHumanSignature(reopened, landed)).toBe(true);
    expect((await new FileStore(path).get(TX))?.status).toBe('signed');
    expect(first.acc.submissions).toHaveLength(0);
    expect(second.acc.submissions).toHaveLength(0);
  });
});
