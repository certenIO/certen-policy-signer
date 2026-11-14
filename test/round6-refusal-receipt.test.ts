/**
 * DAX-4S round 6, the refusal receipt (DE-97, DE-98, DE-103): a decision the binding check refuses is a `binding.refused` entry of the
 * verified journal, `{ requestHash, seat, reason }` and, where they could be read, the `nonce` of the refused decision and the `txHash`
 * (each a 32-byte hash or the empty string). It is attributable only when it names both the request and the nonce. The refusal signs
 * nothing, casts nothing and consumes no nonce. Also: the policy request forwards the leaf expiry and a raw call end to end.
 * FICTIONAL data, temp directories only.
 */
import { describe, expect, it } from 'vitest';
import { checkRefusalReceipt, isAttributable } from '../src/core/refusal-receipt.js';
import { verifyLog } from '../src/core/log.js';
import { parseWireBinding, authenticateExecution } from '../src/core/decision-wire.js';
import { ADDR, H, intentBody, leg, record } from './support/binding-fixtures.js';
import { NOW_S, TX, approveFor, requestHashOf, rig } from './support/binding-rig.js';
import type { PolicyRequest } from '../src/types.js';

const body = intentBody();
const refusals = (r: ReturnType<typeof rig>) => r.journal.entries().filter((e) => e.kind === 'binding.refused');

describe('the binding.refused receipt', () => {
  it('names the request the signer built, the nonce of the refused decision and the transaction (an attributable receipt)', async () => {
    const wrongRequest = H('some-other-request');
    const r = rig({ body, reply: approveFor(body, { requestHash: wrongRequest, nonce: H('n-1') }) });
    const out = await r.handle();
    expect(out.lastError).toBe('binding: request_mismatch');
    const e = refusals(r);
    expect(e).toHaveLength(1);
    expect(e[0]!.payload).toEqual({ requestHash: requestHashOf(body), seat: 'seat:fic-treasury', reason: 'request_mismatch', nonce: H('n-1'), txHash: '0x' + TX });
    const receipt = e[0]!.payload as never;
    expect(isAttributable(receipt)).toBe(true);
    expect(checkRefusalReceipt({ receipt })).toEqual({ ok: true, attributable: true });
    // it is in the verified chain, and the nonce it names was NOT consumed
    expect(verifyLog({ logId: 'fic-signer', entries: r.journal.entries(), expectedHead: r.journal.currentHead() })).toMatchObject({ ok: true });
    expect(r.nonces.has(H('n-1'))).toBe(false);
    expect(r.acc.submissions).toHaveLength(0);
  });

  it('the stored receipt of the audit trail carries the same attribution', async () => {
    const r = rig({ body, reply: approveFor(body, { requestHash: H('x'), nonce: H('n-2') }) });
    await r.handle();
    const rec = await r.store.getReceipt(r.tx);
    expect(rec?.policyEvidence).toMatchObject({ blockedBy: 'decision_binding', reason: 'request_mismatch', refusalReceipt: { requestHash: requestHashOf(body), nonce: H('n-2'), txHash: '0x' + TX } });
  });

  it('a reply with no record names the request but no nonce: not attributable, and the entry is still valid', async () => {
    const r = rig({ body, reply: () => ({ decision: 'approve', reason: 'FICTIONAL legacy reply' }) });
    await r.handle();
    const e = refusals(r);
    expect(e).toHaveLength(1);
    expect(e[0]!.payload).toMatchObject({ requestHash: requestHashOf(body), reason: 'decision_malformed', nonce: '', txHash: '0x' + TX });
    expect(isAttributable(e[0]!.payload as never)).toBe(false);
  });

  it('a transaction the signer cannot read as a request carries the empty request hash and the empty nonce (a nonce without a request names nothing)', async () => {
    const bad = intentBody({ legs: [leg({ payloadOverride: { callData: '0xA9059CBB' } })] });
    const r = rig({ body: bad, reply: approveFor(body, { nonce: H('n-3') }) });
    await r.handle();
    const e = refusals(r);
    expect(e).toHaveLength(1);
    expect(e[0]!.payload).toMatchObject({ requestHash: '', nonce: '', reason: 'presented_malformed', txHash: '0x' + TX });
    expect(checkRefusalReceipt({ receipt: e[0]!.payload })).toEqual({ ok: true, attributable: false });
  });

  it('a several-leg intent is refused by name and its receipt carries no request hash (no one request was read)', async () => {
    const two = intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })] });
    const r = rig({ body: two, reply: approveFor(body, { nonce: H('n-4') }) });
    await r.handle();
    expect(refusals(r)[0]!.payload).toMatchObject({ reason: 'multi_leg_unsupported', requestHash: '', nonce: '' });
  });

  it('is not repeated while the same refusal stands (a poll every few seconds), and a NEW decision refused for the same reason is a new receipt', async () => {
    let nonce = H('n-5');
    const r = rig({ body, reply: () => ({ decision: 'approve', reason: 'FICTIONAL', record: record({ requestHash: H('wrong'), issuedAt: NOW_S - 5, nonce }) }) as never });
    await r.handle();
    await r.handle();
    await r.handle();
    expect(refusals(r)).toHaveLength(1);
    nonce = H('n-6');
    await r.handle();
    expect(refusals(r).map((e) => e.payload['nonce'])).toEqual([H('n-5'), H('n-6')]);
  });

  it('a refusal NEVER releases anything: the receipt effect of the core names release false for an attributable one too', async () => {
    const r = rig({ body, reply: approveFor(body, { requestHash: H('x'), nonce: H('n-7') }) });
    await r.handle();
    const receipt = refusals(r)[0]!.payload as never;
    const res = { requestHash: requestHashOf(body), decisionNonce: H('n-7') };
    expect(checkRefusalReceipt({ receipt, reservation: res })).toMatchObject({ ok: true, release: false, attributable: true, reason: 'refusal_never_releases' });
  });

  it('writes no receipt for a decision that was accepted', async () => {
    const r = rig({ body, reply: approveFor(body) });
    await r.handle();
    expect(refusals(r)).toHaveLength(0);
  });
});

describe('the policy request carries the leaf expiry and the raw call (the Console and the signer read one request)', () => {
  const HEADER = '2027-02-01T12:00:00.000Z'; // after the rig clock (NOW_S is 2027-01-15), so the on-chain deadline has not passed
  const sent = async (b: ReturnType<typeof intentBody>, over: Parameters<typeof rig>[0]['rules'] = {}, header?: string): Promise<PolicyRequest> => {
    let seen: PolicyRequest | undefined;
    const r = rig({ body: b, reply: (q) => { seen = q; return { decision: 'pending' } as never; }, rules: over, ...(header ? { header } : {}) });
    await r.handle();
    return seen!;
  };

  it('sends leafExpiry in binding: the header deadline plus the one-hour horizon, parsed by the core reference parser', async () => {
    const q = await sent(body, {}, HEADER);
    const t = Date.parse(HEADER) / 1000;
    expect(q.binding).toMatchObject({ leafExpiry: t + 3600 });
    expect(parseWireBinding({ binding: q.binding, requestTxHash: '0x' + TX })).toMatchObject({ ok: true, leafExpiry: t + 3600 });
  });

  it('uses the seat horizon (never below the validator one hour)', async () => {
    const q = await sent(body, { settlementHorizonSeconds: 5400 }, HEADER);
    expect(q.binding).toMatchObject({ leafExpiry: Date.parse(HEADER) / 1000 + 5400 });
  });

  it('sends no leafExpiry when the transaction has no deadline at all', async () => {
    const q = await sent(body);
    expect(q.binding).toBeDefined();
    expect('leafExpiry' in q.binding!).toBe(false);
  });

  it('a raw call at a seat with allowRaw is sent as kind raw with its execution, and the reference authenticates both', async () => {
    const raw = intentBody({ legs: [leg({ payloadOverride: { callData: '0x12345678' + '00'.repeat(32), value: '3' }, legOverride: { amountWei: '3' } })] });
    const q = await sent(raw, { allowRaw: true });
    expect(q.binding).toMatchObject({ kind: 'raw', asset: 'native', amount: '3' });
    expect(q.binding!.beneficiary).toBe(q.binding!.target);
    expect(authenticateExecution(q.binding, q.execution)).toMatchObject({ ok: true });
  });

  it('the same call at a seat WITHOUT allowRaw sends no binding and is refused binding_absent: nothing is signed', async () => {
    const raw = intentBody({ legs: [leg({ payloadOverride: { callData: '0x12345678' + '00'.repeat(32), value: '3' }, legOverride: { amountWei: '3' } })] });
    const q = await sent(raw);
    expect(q.binding).toBeUndefined();
    const r = rig({ body: raw, reply: () => ({ decision: 'approve', reason: 'FICTIONAL', record: record({ requestHash: H('anything'), issuedAt: NOW_S - 5, nonce: H('n-8') }) }) as never });
    const out = await r.handle();
    expect(out.lastError).toBe('binding: binding_absent');
    expect(r.acc.submissions).toHaveLength(0);
    expect(refusals(r)[0]!.payload).toMatchObject({ reason: 'binding_absent', requestHash: '' });
  });
});
