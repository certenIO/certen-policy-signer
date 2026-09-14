/**
 * The pending transaction's header reaches the policy engine, and a dead transaction is never signed.
 * Runbook Phase 2 tasks 2.5 (F23) and decision 0031.
 *
 * Live (spike S1), the firm's signer sent a PolicyRequest with no header at all, so a seat could not
 * check which parties the submitter had listed (A2). The header is the network's record, read for
 * EVERY body type: an acceptance WriteData (decision 0028) needs `authorities` as much as an intent.
 *
 * All identities below are FICTIONAL.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { extractTxHeader, headerDeadlinePassed } from '../src/accumulate/header.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import type { PolicyClient } from '../src/policy/policy.js';
import type { Decision, PolicyRequest } from '../src/types.js';

const silent = pino({ level: 'silent' });
const TX = 'e4'.repeat(32);
const PAGE = 'acc://fictional-firm.acme/book/1';
const PRINCIPAL = 'acc://fictional-customer.acme/acceptances';
const FIRM_BOOK = 'acc://fictional-firm.acme/book';
const NOW = Date.parse('2026-09-14T12:00:00.000Z');

/** A plain WriteData acceptance transaction (0028) — NOT a CERTEN intent — with a full header. */
const acceptanceBody = { type: 'writeData', entry: { type: 'doubleHash', data: ['7b7d'] } };
const rawWithHeader = (header: Record<string, unknown>) => ({
  header: { principal: PRINCIPAL, initiator: 'ab'.repeat(32), ...header },
  body: acceptanceBody,
});

function engine(decide: (r: PolicyRequest) => Decision = () => ({ decision: 'approve', reason: 'ok' })) {
  const seen: PolicyRequest[] = [];
  const client = { decide: async (r: PolicyRequest) => { seen.push(r); return decide(r); } } as unknown as PolicyClient;
  return { seen, client };
}

function rig(rawTransaction: unknown, decide?: (r: PolicyRequest) => Decision, clock?: { t: number }) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, { rawTransaction, body: acceptanceBody, principal: PRINCIPAL });
  const eng = engine(decide);
  const store = new MemoryStore();
  const c = clock ?? { t: NOW };
  const orchestrator = new Orchestrator({
    accumulate: acc,
    keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)), PAGE),
    policy: eng.client,
    store,
    resolver: new Resolver(acc),
    logger: silent,
    options: { submitRejectVote: true },
    now: () => c.t,
  });
  return { acc, eng, store, orchestrator, run: () => orchestrator.handle({ txHash: TX, signerUrl: PAGE }) };
}

describe('extractTxHeader', () => {
  it('reads principal, authorities, the on-chain deadline and the memo', () => {
    const { header, expiryUnreadable } = extractTxHeader(rawWithHeader({
      authorities: [FIRM_BOOK], expire: { atTime: '2026-09-14T12:10:00Z' }, memo: 'FICTIONAL acceptance',
      metadata: 'deadbeef', holdUntil: { minorBlock: 5 },
    }));
    expect(expiryUnreadable).toBeUndefined();
    expect(header).toEqual({
      principal: PRINCIPAL, authorities: [FIRM_BOOK], expiresAt: '2026-09-14T12:10:00.000Z', memo: 'FICTIONAL acceptance',
    });
  });

  it('absent means absent: no authorities, deadline or memo keys when the header sets none', () => {
    expect(extractTxHeader(rawWithHeader({})).header).toEqual({ principal: PRINCIPAL });
    expect(extractTxHeader(rawWithHeader({ authorities: [] })).header).toEqual({ principal: PRINCIPAL });
  });

  it('falls back to the reported principal when the record has none', () => {
    expect(extractTxHeader({ body: acceptanceBody }, PRINCIPAL).header.principal).toBe(PRINCIPAL);
  });

  it('flags an expiry it cannot read rather than treating it as no deadline', () => {
    expect(extractTxHeader(rawWithHeader({ expire: { atTime: 'not a time' } })).expiryUnreadable).toMatch(/not a readable/);
    // A bare number would need its unit guessed; a guessed deadline is an invented one.
    expect(extractTxHeader(rawWithHeader({ expire: { atTime: 1789400000 } })).expiryUnreadable).toBeDefined();
  });

  it('treats the deadline instant itself as passed', () => {
    const h = { principal: PRINCIPAL, expiresAt: new Date(NOW).toISOString() };
    expect(headerDeadlinePassed(h, NOW - 1)).toBe(false);
    expect(headerDeadlinePassed(h, NOW)).toBe(true);
    expect(headerDeadlinePassed({ principal: PRINCIPAL }, NOW)).toBe(false);
  });
});

describe('RawAccumulateClient reads the header off the v3 transaction record', () => {
  it('returns message.transaction.header from a pending record', async () => {
    const client = new RawAccumulateClient('http://127.0.0.1:1', silent);
    (client as unknown as { query: () => Promise<unknown> }).query = async () => ({
      recordType: 'message', status: 'pending',
      message: { type: 'transaction', transaction: rawWithHeader({ authorities: [FIRM_BOOK], expire: { atTime: '2026-09-14T12:10:00Z' } }) },
    });
    const p = await client.getPendingTx(TX, PAGE);
    expect(p.found).toBe(true);
    expect(p.header?.header).toEqual({ principal: PRINCIPAL, authorities: [FIRM_BOOK], expiresAt: '2026-09-14T12:10:00.000Z' });
  });
});

describe('every PolicyRequest carries the header', () => {
  it('for a plain WriteData acceptance transaction, not only for CERTEN intents (0028)', async () => {
    const r = rig(rawWithHeader({ authorities: [FIRM_BOOK], expire: { atTime: '2026-09-14T12:10:00Z' }, memo: 'FICTIONAL' }));
    await r.run();
    const req = r.eng.seen[0]!;
    expect(req.header).toEqual({
      principal: PRINCIPAL, authorities: [FIRM_BOOK], expiresAt: '2026-09-14T12:10:00.000Z', memo: 'FICTIONAL',
    });
    // The policy TTL is a different thing and is left exactly as it was.
    expect(req.expiresAt).toBe(new Date(NOW + 900_000).toISOString());
    // And it survives the wire: it is part of the JSON the HTTP client sends.
    expect(JSON.parse(JSON.stringify(req)).header.authorities).toEqual([FIRM_BOOK]);
  });

  it('with only the principal when the header names nothing else', async () => {
    const r = rig(undefined); // the mock builds { header: { principal }, body }
    await r.run();
    expect(r.eng.seen[0]!.header).toEqual({ principal: PRINCIPAL });
  });
});

describe('decision 0031: the signer refuses to sign after the header deadline', () => {
  it('a deadline already passed: the engine is not asked, nothing is signed, the refusal is recorded', async () => {
    const r = rig(rawWithHeader({ authorities: [FIRM_BOOK], expire: { atTime: '2026-09-14T11:59:00Z' } }));
    const out = await r.run();
    expect(r.eng.seen).toHaveLength(0);
    expect(r.acc.submissions).toHaveLength(0);
    expect(out.status).toBe('expired');
    expect(out.lastError).toBe('header_deadline_passed');
    const receipt = await r.store.getReceipt(TX);
    expect(receipt?.vote).toBeUndefined();
    expect(receipt?.reason).toMatch(/on-chain deadline 2026-09-14T11:59:00.000Z has passed/);
    expect(receipt?.policyEvidence).toMatchObject({ blockedBy: 'header_deadline_passed', headerExpiresAt: '2026-09-14T11:59:00.000Z' });
  });

  it('a deadline that passes while the engine decides: the approval does NOT become a late signature', async () => {
    const clock = { t: NOW };
    const r = rig(
      rawWithHeader({ expire: { atTime: '2026-09-14T12:01:00Z' } }),
      () => { clock.t = NOW + 120_000; return { decision: 'approve', reason: 'approved by FICTIONAL reviewer' }; },
      clock,
    );
    const out = await r.run();
    expect(r.eng.seen).toHaveLength(1);
    expect(r.acc.submissions).toHaveLength(0);
    expect(out.status).toBe('expired');
    const receipt = await r.store.getReceipt(TX);
    expect(receipt?.decision).toBe('approve');
    expect(receipt?.vote).toBeUndefined();
    expect(receipt?.policyEvidence).toMatchObject({ blockedBy: 'header_deadline_passed', engineReason: 'approved by FICTIONAL reviewer' });
  });

  it('a deny that lands after the deadline casts no reject vote either', async () => {
    const clock = { t: NOW };
    const r = rig(
      rawWithHeader({ expire: { atTime: '2026-09-14T12:01:00Z' } }),
      () => { clock.t = NOW + 120_000; return { decision: 'deny', reason: 'no' }; },
      clock,
    );
    const out = await r.run();
    expect(r.acc.submissions).toHaveLength(0);
    expect(out.status).toBe('expired');
  });

  it('an unreadable deadline is refused, not read as "no deadline"', async () => {
    const r = rig(rawWithHeader({ expire: { atTime: 'soon' } }));
    const out = await r.run();
    expect(r.eng.seen).toHaveLength(0);
    expect(r.acc.submissions).toHaveLength(0);
    expect(out.status).toBe('rejected');
    expect(out.lastError).toBe('header_expiry_unreadable');
  });

  it('a deadline still in the future signs normally', async () => {
    const r = rig(rawWithHeader({ authorities: [FIRM_BOOK], expire: { atTime: '2026-09-14T12:10:00Z' } }));
    const out = await r.run();
    expect(out.status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
  });
});
