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
import { FileStore, MemoryStore, humanRecordId, type Store } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring, noKeyKeyring, MapKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Poller } from '../src/poller.js';
import { advanceAwaitingHuman } from '../src/officer/landed.js';
import type { PageState } from '../src/ops/rotate.js';
import type { Decision } from '../src/types.js';

const silent = pino({ level: 'silent' });
const SUMMIT_P1 = 'acc://summit-inspection-tcl1.acme/book/1';
const SUMMIT_BOOK = 'acc://summit-inspection-tcl1.acme/book';
const TX = '5a'.repeat(32);
const KEY_A = 'a1'.repeat(32);
/** A human-only seat's record key for TX (review #1: its own record, never the keyed seat's). */
const HID = humanRecordId(TX, SUMMIT_P1);

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

  it('refuses a delegator_url that is a human page: a machine key would satisfy the people\u2019s page (security review 2026-10-02)', () => {
    const keyed = `  scopes:\n    - { page: "acc://summit-inspection-tcl1.acme/book/2", key: { provider: "local", local: { allow_ephemeral: true } } }`;
    // The human-only scope itself as the delegator every keyed vote is cast through.
    expect(() => load(`${keyed}\n${human}\n  attachment_model: delegate\n  delegator_url: "${SUMMIT_P1}"`, intake([SUMMIT_P1])))
      .toThrow(/delegator_url .* is a human page/);
    // An officer page (no human-only scope), and the same page spelt with a trailing slash and other case.
    const officer = 'acc://summit-inspection-tcl1.acme/book/3';
    expect(() => load(`${keyed}\n  attachment_model: delegate\n  delegator_url: "${officer.toUpperCase().replace('ACC://', 'acc://')}/"`, intake([officer])))
      .toThrow(/is a human page/);
    // Named even while unused (attachment_model authority): still a mistake, still refused.
    expect(() => load(`${keyed}\n${human}\n  delegator_url: "${SUMMIT_P1}"`, intake([SUMMIT_P1]))).toThrow(/is a human page/);
    // A delegator page that holds no human seat is fine.
    const ok = load(`${keyed}\n${human}\n  attachment_model: delegate\n  delegator_url: "acc://fictional-customer-tcl1.acme/book/2"`, intake([SUMMIT_P1]));
    expect(ok.wallet.delegator_url).toBe('acc://fictional-customer-tcl1.acme/book/2');
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
    const orch = { handleAll: async (r: { txHash: string; signerUrl: string }) => { handled.push(r); return [] as never; } } as unknown as Orchestrator;
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
    const receipt = await s.store.getReceipt(HID);
    expect(receipt).toMatchObject({ decision: 'approve', reason: 'FICTIONAL rule: inspection accepted', policyEvidence: { ruleSetVersion: 'summit-rules-1', awaitingHumanSignature: { page: SUMMIT_P1, vote: 'approve' } } });
    expect(receipt?.vote).toBeUndefined();
    expect(receipt?.signedBy).toBeUndefined();
  });

  it('deny with submit_reject_vote -> awaiting_human (a person casts the reject); without it -> rejected; never a signature', async () => {
    const s1 = seat({ policy: new MockPolicyClient({ decision: 'deny', reason: 'FICTIONAL' }), submitRejectVote: true });
    expect(await s1.go()).toMatchObject({ status: 'awaiting_human', decision: 'deny' });
    expect((await s1.store.getReceipt(HID))?.policyEvidence).toMatchObject({ awaitingHumanSignature: { vote: 'reject' } });
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

describe('the people\u2019s signatures, counted from the chain, end the request; all of it survives a restart', () => {
  const PEOPLE = ['b1', 'b2', 'b3'].map((x) => x.repeat(32));
  /** SUMMIT_P1 as the chain has it: three people, accept threshold `accept`, reject threshold `reject`. */
  const pageOf = (accept: number, reject = 0): PageState => ({
    version: 2, threshold: accept, rejectThreshold: reject, keyHashes: PEOPLE, entries: PEOPLE.map((keyHash) => ({ keyHash, delegate: null })),
  });
  const sig = (keyHash: string, vote: 'approve' | 'reject' = 'approve', signer = SUMMIT_P1) => ({ type: 'ecdsaSha256', publicKeyHash: keyHash, delegators: [] as string[], hops: [] as string[], signer, vote });
  /** A seat whose chain reports `onChain` as the signature set (mutable), and `page` as the page. */
  function chainSeat(o: { decision: 'approve' | 'deny'; page: PageState; store?: Store }) {
    const onChain: ReturnType<typeof sig>[] = [];
    const st = seat({ policy: new MockPolicyClient({ decision: o.decision, reason: 'FICTIONAL seat rule' }), readPage: async () => o.page, ...(o.store ? { store: o.store } : {}) });
    (st.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => ({ status: 'pending', delivered: false, signatures: [...onChain] });
    return { ...st, onChain, tally: () => advanceAwaitingHuman({ store: st.store, getTxSignatures: async () => ({ status: 'pending', delivered: false, signatures: [...onChain] }), readPage: async () => o.page }, TX, SUMMIT_P1) };
  }

  it('one signature on a 2-of-3 page does not end it; the partial signer is kept; the second ends it', async () => {
    const s = chainSeat({ decision: 'approve', page: pageOf(2) });
    expect((await s.go()).status).toBe('awaiting_human');
    s.onChain.push(sig(PEOPLE[0]!));
    const r1 = await s.tally();
    expect(r1).toMatchObject({ status: 'awaiting_human', humanSignatures: [{ seat: `key:${PEOPLE[0]}`, vote: 'approve' }] });
    // The same seat twice is still one seat.
    s.onChain.push(sig(PEOPLE[0]!));
    expect((await s.tally())?.status).toBe('awaiting_human');
    s.onChain.push(sig(PEOPLE[1]!));
    const r2 = await s.tally();
    expect(r2).toMatchObject({ status: 'signed' });
    expect(r2?.humanSignatures).toHaveLength(2);
    expect(r2?.humanOverride).toBeUndefined();
    expect(await s.store.getReceipt(HID)).toMatchObject({
      decision: 'approve', vote: 'approve', signedBy: { page: SUMMIT_P1, publicKeyHash: PEOPLE[0] },
      policyEvidence: { awaitingHumanSignature: { page: SUMMIT_P1, vote: 'approve' } },
    });
    expect(s.acc.submissions).toHaveLength(0);
  });

  it('only signatures that are this page\u2019s count: another page, or a key not on the page, does not', async () => {
    const s = chainSeat({ decision: 'approve', page: pageOf(1) });
    await s.go();
    s.onChain.push(sig(PEOPLE[0]!, 'approve', 'acc://summit-inspection-tcl1.acme/book/2'), sig('ee'.repeat(32)));
    const r = await s.tally();
    expect(r?.status).toBe('awaiting_human');
    expect(r?.humanSignatures ?? []).toEqual([]);
  });

  it('a late landing is picked up by the next poll: the orchestrator reads the chain (review #3)', async () => {
    const s = chainSeat({ decision: 'approve', page: pageOf(1) });
    await s.go();
    s.onChain.push(sig(PEOPLE[2]!));        // landed after officer intake stopped watching
    expect((await s.go()).status).toBe('signed');
  });

  it('nothing changes when the chain or the page cannot be read', async () => {
    const s = seat({ policy: new MockPolicyClient({ decision: 'approve' }), readPage: async () => { throw new Error('FICTIONAL node down'); } });
    await s.go();
    (s.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => ({ status: 'pending', delivered: false, signatures: [sig(PEOPLE[0]!)] });
    expect((await s.go()).status).toBe('awaiting_human');
    expect(await advanceAwaitingHuman({ store: s.store, readPage: async () => pageOf(1), getTxSignatures: async () => ({ status: '', delivered: false, signatures: [], unavailable: 'FICTIONAL' }) }, TX, SUMMIT_P1))
      .toMatchObject({ status: 'awaiting_human' });
  });

  it('rejections reaching the reject threshold end it as rejected (0 = the accept threshold)', async () => {
    const s = chainSeat({ decision: 'deny', page: pageOf(2) });
    expect((await s.go()).status).toBe('awaiting_human');
    s.onChain.push(sig(PEOPLE[0]!, 'reject'));
    expect((await s.tally())?.status).toBe('awaiting_human');
    s.onChain.push(sig(PEOPLE[1]!, 'reject'));
    expect((await s.tally())).toMatchObject({ status: 'rejected' });
    expect((await s.store.getReceipt(HID))?.humanOverride).toBeUndefined();
  });

  it('a vote that contradicts the one owed is recorded as an override, not as fulfilling the decision (review #6)', async () => {
    const s = chainSeat({ decision: 'approve', page: pageOf(1) });
    await s.go();
    s.onChain.push(sig(PEOPLE[0]!, 'reject'));
    const r = await s.tally();
    expect(r).toMatchObject({ status: 'rejected', humanOverride: { owed: 'approve', cast: 'reject' }, lastError: 'human_override: owed approve, cast reject' });
    expect(await s.store.getReceipt(HID)).toMatchObject({ decision: 'approve', vote: 'reject', humanOverride: { owed: 'approve', cast: 'reject' } });

    const d = chainSeat({ decision: 'deny', page: pageOf(1) });
    await d.go();
    d.onChain.push(sig(PEOPLE[0]!, 'approve'));
    expect(await d.tally()).toMatchObject({ status: 'signed', humanOverride: { owed: 'reject', cast: 'approve' } });
  });

  it('FileStore: awaiting_human, the partial signers, the stored request and the receipt survive a restart; the engine is not asked again', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'g69-store-')), 'state.json');
    const first = chainSeat({ decision: 'approve', page: pageOf(2), store: new FileStore(path) });
    expect((await first.go()).status).toBe('awaiting_human');
    first.onChain.push(sig(PEOPLE[0]!));
    await first.tally();

    const reopened = new FileStore(path);
    expect(await reopened.get(HID)).toMatchObject({ status: 'awaiting_human', humanSignatures: [{ seat: `key:${PEOPLE[0]}` }] });
    expect((await reopened.getPolicyRequest(TX))?.summaryHash).toMatch(/^[0-9a-f]{64}$/);
    expect((await reopened.getReceipt(HID))?.policyEvidence).toMatchObject({ awaitingHumanSignature: { page: SUMMIT_P1 } });

    const policy = new MockPolicyClient({ decision: 'deny' });
    const decide = vi.spyOn(policy, 'decide');
    const second = chainSeat({ decision: 'deny', page: pageOf(2), store: reopened });
    second.onChain.push(sig(PEOPLE[0]!), sig(PEOPLE[1]!));
    (second.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => ({ status: 'pending', delivered: false, signatures: [...second.onChain] });
    const st2 = seat({ policy, store: reopened, readPage: async () => pageOf(2) });
    (st2.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = async () => ({ status: 'pending', delivered: false, signatures: [...second.onChain] });
    expect((await st2.go()).status).toBe('signed');
    expect(decide).not.toHaveBeenCalled();
    expect((await new FileStore(path).get(HID))?.status).toBe('signed');
    expect(first.acc.submissions).toHaveLength(0);
    expect(st2.acc.submissions).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/* review #1: a human-only page never pre-empts a keyed seat           */
/* ------------------------------------------------------------------ */

describe('one transaction, a keyed page and a human-only page in the same book (review #1)', () => {
  const KEYED = 'acc://summit-inspection-tcl1.acme/book/2';

  function both(order: 'human-first' | 'keyed-first') {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body: PAYMENT, principal: 'acc://fictional-payer-tcl1.acme/tokens' });
    const store = new MemoryStore();
    const o = new Orchestrator({
      accumulate: acc, keyring: new MapKeyring([{ page: KEYED, book: SUMMIT_BOOK, signer: new LocalSigner(new Uint8Array(32).fill(6)) }]),
      policy: new MockPolicyClient({ decision: 'approve', reason: 'FICTIONAL rule passed' }), store, resolver: new Resolver(acc), logger: silent,
      humanOnlyPages: [SUMMIT_P1],
    });
    const pages = order === 'human-first' ? [SUMMIT_P1, KEYED] : [KEYED, SUMMIT_P1];
    return { acc, store, run: async () => { for (const p of pages) await o.handle({ txHash: TX, signerUrl: p }); for (const p of pages) await o.handle({ txHash: TX, signerUrl: p }); } };
  }

  for (const order of ['human-first', 'keyed-first'] as const) {
    it(`each page keeps and decides its own record; the keyed seat still votes (${order})`, async () => {
      const s = both(order);
      await s.run();
      expect((await s.store.get(TX))).toMatchObject({ status: 'signed', signerUrl: KEYED });
      expect((await s.store.get(HID))).toMatchObject({ status: 'awaiting_human', signerUrl: SUMMIT_P1, recordId: HID });
      expect(s.acc.submissions).toHaveLength(1);   // the keyed seat's vote; nothing for the human-only page
      expect((await s.store.getReceipt(TX))?.vote).toBe('approve');
      expect((await s.store.getReceipt(HID))?.policyEvidence).toMatchObject({ awaitingHumanSignature: { page: SUMMIT_P1 } });
      expect((await s.store.listForTx(TX)).map((r) => r.signerUrl).sort()).toEqual([SUMMIT_P1, KEYED].sort());
    });
  }

  it('a FileStore keeps both records apart across a restart, including their stored PolicyRequests', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'g69-two-')), 'state.json');
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body: PAYMENT, principal: 'acc://fictional-payer-tcl1.acme/tokens' });
    const o = new Orchestrator({
      accumulate: acc, keyring: new MapKeyring([{ page: KEYED, book: SUMMIT_BOOK, signer: new LocalSigner(new Uint8Array(32).fill(6)) }]),
      policy: new MockPolicyClient({ decision: 'approve' }), store: new FileStore(path), resolver: new Resolver(acc), logger: silent, humanOnlyPages: [SUMMIT_P1],
    });
    await o.handle({ txHash: TX, signerUrl: SUMMIT_P1 });
    await o.handle({ txHash: TX, signerUrl: KEYED });
    const re = new FileStore(path);
    expect((await re.get(TX))?.status).toBe('signed');
    expect((await re.get(HID))?.status).toBe('awaiting_human');
    expect((await re.getPolicyRequest(HID))?.signerUrl).toBe(SUMMIT_P1);
    expect((await re.getPolicyRequest(TX))?.signerUrl).toBe(KEYED);
  });
});
