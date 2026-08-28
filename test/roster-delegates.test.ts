/**
 * A seat on a role page, held by a person's own key book — and the consent that guards it.
 *
 * Runbook F Phase F3. F2 put one key per approver on a page and proved the protocol counts them. A
 * roster goes one level up: the seat is a DELEGATE entry pointing at the employee's own key book, so
 * revoking authority is one entry removed and it retires no identity.
 *
 * ── WHY THIS IS NOT `add-key` WITH A DIFFERENT PAYLOAD ────────────────────────────────────────────
 *
 * Adding a KEY confirms on chain in the next block: the page's own threshold authorised it and nobody
 * else is involved. Adding a DELEGATE does not, and must not. `update_key_page.go` `TransactionIsReady`
 * requires that "all new delegates must sign the transaction" — so the org proposes, the protocol holds
 * the transaction pending, and it executes only when the employee's own key co-signs.
 *
 * That is invariant F-5, and it is enforced by the network rather than by us. The consequence for this
 * code is the whole point of these tests: an `add-delegate` that comes back "not confirmed" is the
 * control WORKING. Waiting for a confirmation that cannot arrive, and then reporting a timeout, would
 * present a functioning guard as a failure — and the obvious next fix, on a tired afternoon, is to
 * route around it.
 *
 * ── AND WHY THE TARGET MUST BE A BOOK ─────────────────────────────────────────────────────────────
 *
 * `verifyIsNotPage` (update_key_page.go) refuses a delegate that is a page. Caught here rather than on
 * chain, because a transaction spent to learn what a local check knows is a transaction spent for
 * nothing — the same reasoning as the enrolment gateway plan's preflight, whose lesson is: validate
 * before you spend.
 */
import { describe, it, expect, vi } from 'vitest';
import { applyKeyPageOp } from '../src/ops/keypage.js';
import { LocalSigner } from '../src/signer/signer.js';
import { logger } from '../src/logger.js';

const silent = logger.child({ level: 'silent' });
const ROSTER = 'acc://bank.acme/roles/treasury/1';
const ALICE_BOOK = 'acc://bank.acme/alice/book';
const BOB_BOOK = 'acc://bank.acme/bob/book';
const ORG_KEY = 'aa'.repeat(32);

/**
 * A fake Accumulate that reports a page and records submissions.
 *
 * `entries` is what the page holds: a key hash, a delegate, or both. The version never advances,
 * which is exactly the situation a pending delegate addition produces — the transaction is held, so
 * the page does not move.
 */
function fakeAcc(entries: Array<{ publicKeyHash?: string; delegate?: string }>, version = 1) {
  const submitted: any[] = [];
  return {
    submitted,
    query: vi.fn(async () => ({ account: { version, acceptThreshold: 1, keys: entries } })),
    getSignerInfo: vi.fn(async () => ({ version, lastUsedOn: 0, creditBalance: 100 })),
    submit: vi.fn(async (env: any) => { submitted.push(env); return { ok: true }; }),
  } as any;
}

const deps = (acc: any, page = ROSTER) => ({
  accumulate: acc, signer: new LocalSigner(new Uint8Array(32).fill(7)), logger: silent, page,
});

/** The updateKeyPage operation inside whatever envelope was submitted. */
function operationOf(env: any): any {
  const body = env?.transaction?.[0]?.body ?? env?.transaction?.body ?? env?.body;
  return body?.operation?.[0];
}

describe('proposing a seat', () => {
  it('submits a delegate entry naming the employee’s key book', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: ALICE_BOOK }, 1000);

    expect(r.ok).toBe(true);
    expect(acc.submitted).toHaveLength(1);
    const op = operationOf(acc.submitted[0]);
    expect(op.type).toBe('add');
    expect(String(op.entry.delegate)).toBe(ALICE_BOOK);
    // A seat, not a key. Sending a keyHash as well would put the employee's key directly on the role
    // page, which is the shape this design deliberately does not use: it cannot be revoked without
    // touching the role page's own membership, and it puts two churn rates on one object.
    expect(op.entry.keyHash).toBeUndefined();
  });

  /**
   * The control, and the assertion this whole file exists for. The transaction is submitted and the
   * page does NOT change, because the protocol is holding it for the employee's signature.
   */
  it('reports the seat as awaiting consent rather than as confirmed', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: ALICE_BOOK }, 1000);

    expect(r.ok).toBe(true);
    expect(r.awaitingConsent).toBe(true);
    expect(r.submitted).toHaveLength(1);
    // The page is unchanged, and the result says so rather than pretending otherwise.
    expect(r.after.entries.some((e) => e.delegate === ALICE_BOOK)).toBe(false);
  });

  /**
   * And it does not sit there waiting. `add-key` polls the page until the change lands; doing that
   * here would block for the full timeout on every enrolment and then report a timeout — a working
   * control, described as a fault.
   */
  it('does not block waiting for a confirmation that cannot arrive', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }]);
    const started = Date.now();
    await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: ALICE_BOOK }, 30_000);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('refuses a delegate that is a page rather than a book, without spending a transaction', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: 'acc://bank.acme/alice/book/1' }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/book, not a page/i);
    expect(acc.submitted).toHaveLength(0);
  });

  it('refuses anything that is not an acc:// URL at all', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }]);
    for (const bad of ['alice', 'https://bank.example/alice', '', 'acc://']) {
      const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: bad }, 1000);
      expect(r.ok, `"${bad}" must be refused`).toBe(false);
    }
    expect(acc.submitted).toHaveLength(0);
  });

  it('refuses a seat the page already holds', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }, { delegate: ALICE_BOOK }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: ALICE_BOOK }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/already/i);
    expect(acc.submitted).toHaveLength(0);
  });

  /** Case-insensitively, because an acc:// URL is not case-sensitive and a second seat is not a seat. */
  it('refuses a seat the page holds under a different spelling', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }, { delegate: ALICE_BOOK }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: ALICE_BOOK.toUpperCase() }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/already/i);
  });
});

describe('revoking a seat', () => {
  /**
   * Removal needs no consent — it is the org's own page and the employee is not being asked for
   * anything. So unlike the proposal, this one confirms on chain, and a caller may rely on the result.
   */
  it('removes the entry and confirms, because nobody else has to agree', async () => {
    // The page as the chain would show it: the seat is there when `before` is read, and gone by the
    // time the confirmation read happens. Swapping it up front would have the operation refuse a seat
    // it was about to remove -- which is what the first version of this test actually did.
    let removed = false;
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }, { delegate: ALICE_BOOK }]);
    acc.query = vi.fn(async () => (removed
      ? { account: { version: 2, acceptThreshold: 1, keys: [{ publicKeyHash: ORG_KEY }] } }
      : { account: { version: 1, acceptThreshold: 1, keys: [{ publicKeyHash: ORG_KEY }, { delegate: ALICE_BOOK }] } }));
    const submit = acc.submit;
    acc.submit = vi.fn(async (env: any) => { removed = true; return submit(env); });

    const r = await applyKeyPageOp(deps(acc), { op: 'remove-delegate', delegate: ALICE_BOOK }, 1000);

    expect(r.ok).toBe(true);
    expect(r.awaitingConsent).toBeFalsy();
    const op = operationOf(acc.submitted[0]);
    expect(op.type).toBe('remove');
    expect(String(op.entry.delegate)).toBe(ALICE_BOOK);
  });

  it('refuses to revoke a seat the page does not hold', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }, { delegate: ALICE_BOOK }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'remove-delegate', delegate: BOB_BOOK }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not on/i);
    expect(acc.submitted).toHaveLength(0);
  });

  /**
   * The same protection `remove-key` has, for the same reason: a page with nothing on it authorises
   * nothing, forever. A roster whose last seat is removed is a role nobody can ever exercise again.
   */
  it('refuses to remove the last entry on the page', async () => {
    const acc = fakeAcc([{ delegate: ALICE_BOOK }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'remove-delegate', delegate: ALICE_BOOK }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/only|last/i);
    expect(acc.submitted).toHaveLength(0);
  });
});

describe('the seats a page holds', () => {
  it('reads delegates and keys apart, so a roster can be listed', async () => {
    const acc = fakeAcc([{ publicKeyHash: ORG_KEY }, { delegate: ALICE_BOOK }, { delegate: BOB_BOOK }]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-delegate', delegate: 'acc://bank.acme/carla/book' }, 1000);

    expect(r.before.entries).toHaveLength(3);
    expect(r.before.entries.filter((e) => e.delegate).map((e) => e.delegate)).toEqual([ALICE_BOOK, BOB_BOOK]);
    expect(r.before.keyHashes).toEqual([ORG_KEY]);
  });
});
