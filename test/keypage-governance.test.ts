/**
 * Typed key-page governance replaces blind hash-signing.
 *
 * The old endpoint would sign ANY 32-byte hash handed to it. However well credentialed, the wallet had no
 * idea what it was authorising — the hash could have been a token transfer emptying the org's accounts.
 * These tests pin the properties that make the replacement safe: the wallet builds the transaction, the
 * principal is always OUR page, and operations that would destroy the org's authority are refused.
 */
import { describe, it, expect, vi } from 'vitest';
import { applyKeyPageOp } from '../src/ops/keypage.js';
import { LocalSigner } from '../src/signer/signer.js';
import { logger } from '../src/logger.js';

const silent = logger.child({ level: 'silent' });
const OUR_PAGE = 'acc://org.acme/book/1';
const KEY_A = 'aa'.repeat(32);
const KEY_B = 'bb'.repeat(32);

/** A fake Accumulate that records what we submit and reports a page we control. */
function fakeAcc(keyHashes: string[], version = 1) {
  const submitted: any[] = [];
  return {
    submitted,
    query: vi.fn(async () => ({ account: { version, keys: keyHashes.map((h) => ({ publicKeyHash: h })) } })),
    getSignerInfo: vi.fn(async () => ({ version, lastUsedOn: 0, creditBalance: 100 })),
    submit: vi.fn(async (env: any) => { submitted.push(env); return { ok: true }; }),
  } as any;
}
const deps = (acc: any, page = OUR_PAGE) => ({
  accumulate: acc, signer: new LocalSigner(new Uint8Array(32).fill(7)), logger: silent, page,
});

describe('typed key-page governance', () => {
  it('rejects a malformed key hash instead of signing something meaningless', async () => {
    const acc = fakeAcc([KEY_A]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-key', keyHash: 'not-a-hash' } as any, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/64 hex chars/);
    expect(acc.submitted).toHaveLength(0);   // nothing was signed
  });

  it('refuses to remove the ONLY key — that would strip the org of its authority forever', async () => {
    const acc = fakeAcc([KEY_A]);
    const r = await applyKeyPageOp(deps(acc), { op: 'remove-key', keyHash: KEY_A }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/only key/i);
    expect(acc.submitted).toHaveLength(0);
  });

  it('refuses a threshold that could never be met', async () => {
    const acc = fakeAcc([KEY_A, KEY_B]);
    const r = await applyKeyPageOp(deps(acc), { op: 'set-threshold', threshold: 5 }, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceeds/);
    expect(acc.submitted).toHaveLength(0);
  });

  it('refuses to add a key that is already on the page', async () => {
    const acc = fakeAcc([KEY_A]);
    const r = await applyKeyPageOp(deps(acc), { op: 'add-key', keyHash: KEY_A }, 1000);
    expect(r.ok).toBe(false);
    expect(acc.submitted).toHaveLength(0);
  });

  it('rejects an unknown operation rather than doing something surprising', async () => {
    const acc = fakeAcc([KEY_A]);
    const r = await applyKeyPageOp(deps(acc), { op: 'drain-the-treasury' } as any, 1000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/unknown governance operation/);
    expect(acc.submitted).toHaveLength(0);
  });

  it('the transaction it signs is one IT built, against OUR page — the caller supplies no bytes and no URL', async () => {
    const acc = fakeAcc([KEY_A]);
    // add-key is accepted; the confirm poll then times out against our static fake page (that is fine —
    // what we are asserting is WHAT got signed, not that the fake network converged).
    await applyKeyPageOp(deps(acc), { op: 'add-key', keyHash: KEY_B }, 500);

    expect(acc.submitted).toHaveLength(1);
    const envelope = acc.submitted[0];
    const tx = envelope.transaction[0];
    expect(tx.header.principal).toBe(OUR_PAGE);          // our page, from config — never caller-supplied
    expect(tx.body.type).toBe('updateKeyPage');          // a key-page op, not an arbitrary transaction
    expect(envelope.signatures[0].signer).toBe(OUR_PAGE);
  });
});
