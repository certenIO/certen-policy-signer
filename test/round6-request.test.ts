/**
 * DAX-4S round 6, the request the signer builds: (1) the STRICT reading of calldata through the core decoder and `mapDecoded`
 * (DE-91): upper case is refused, never normalised, and a call no typed kind describes is raw at a seat that allows it and NOT BOUND
 * (`binding_absent`) at every other; (2) the raw kind and its mapping (DE-90); (3) the leaf expiry bound the signer forwards (DE-87, DE-88).
 * FICTIONAL parties; the references are the core's own parser and the core's own bound function, never a second implementation.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { buildPresentedRequest, presentOptionsOf } from '../src/binding/request.js';
import { policyBindingOf } from '../src/binding/policy-binding.js';
import { bindDecision } from '../src/core/decision-binding.js';
import { authenticateExecution, parseWireBinding } from '../src/core/decision-wire.js';
import { reviewRaw } from '../src/core/raw-approval.js';
import { leafExpiryBound, VALIDATOR_HORIZON_SECONDS } from '../src/core/leaf-expiry.js';
import { hashRequest } from '../src/core/hashes.js';
import { ADDR, APPROVER, H, POLICY, SEAT, intentBody, leg, record } from './support/binding-fixtures.js';

const TX = 'ab'.repeat(32);
const NOW = 1_800_000_000;
type Body = ReturnType<typeof intentBody>;
type Tx = Parameters<typeof buildPresentedRequest>[0];
const tx = (body: Body, header?: { expiresAt?: string }): Tx => ({ txHash: TX, rawTransaction: { body }, summary: { action: 'x' } as never, ...(header ? { header } : {}) });
const build = (body: Body, opts?: Parameters<typeof buildPresentedRequest>[1], header?: { expiresAt?: string }) => buildPresentedRequest(tx(body, header), opts);
const ok = (body: Body, opts?: Parameters<typeof buildPresentedRequest>[1], header?: { expiresAt?: string }) => {
  const r = build(body, opts, header);
  if (!r.ok) throw new Error('expected a request, got ' + r.detail);
  return r.value;
};
const word = (v: string): string => v.replace(/^0x/, '').padStart(64, '0');
/** a leg whose call carries these exact calldata bytes (the commitment is the genuine one of them) */
const callLeg = (callData: string, value = '0', over: Record<string, unknown> = {}) => leg({ payloadOverride: { callData, value }, legOverride: { amountWei: value, ...over } });
const UNKNOWN_SELECTOR = '0x12345678' + word(ADDR.vendorA) + word('9');
const TRANSFER = (to: string, amt: string) => '0xa9059cbb' + word(to) + word(BigInt(amt).toString(16));

describe('strict calldata (DE-91): the core decoder reads the text, the signer never normalises it', () => {
  it('REFUSES upper-case hex digits at every seat, whole or mixed case, and never lower-cases them (golden v2 g15)', () => {
    const lower = TRANSFER(ADDR.vendorA, '300');
    const upper = '0x' + lower.slice(2).toUpperCase();
    const mixed = lower.slice(0, 8) + 'B' + lower.slice(9); // one upper-case digit inside the selector
    for (const allowRaw of [false, true]) {
      for (const cd of [upper, mixed]) {
        const r = build(intentBody({ legs: [leg({ payloadOverride: { callData: cd } })] }), { allowRaw });
        expect(r, `allowRaw ${allowRaw}`).toEqual({ ok: false, detail: 'calldata_hex_invalid' });
      }
    }
    // the same bytes in lower case are the ordinary transfer
    expect(ok(intentBody({ legs: [leg({ payloadOverride: { callData: lower } })] })).request).toMatchObject({ kind: 'erc20.transfer', beneficiary: ADDR.vendorA, amount: '300' });
  });

  it('names the other faults of the text by the decoder own reason, at every seat', () => {
    const cases: Array<[string, string]> = [
      ['0X' + TRANSFER(ADDR.vendorA, '1').slice(2), 'calldata_prefix_invalid'],
      [TRANSFER(ADDR.vendorA, '1').slice(2), 'calldata_prefix_invalid'],
      [TRANSFER(ADDR.vendorA, '1') + '0', 'calldata_odd_length'],
      ['0xa9059cbb zz', 'calldata_hex_invalid'],
    ];
    for (const allowRaw of [false, true]) for (const [cd, detail] of cases) expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: cd } })] }), { allowRaw }), cd).toEqual({ ok: false, detail });
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: 5 } })] }), { allowRaw: true })).toEqual({ ok: false, detail: 'calldata_not_text' });
  });

  it('maps through the core: request.ts reads calldata with the core decoder and mapDecoded, and no longer with the lenient signer decoder', () => {
    const src = readFileSync(new URL('../src/binding/request.ts', import.meta.url), 'utf8');
    expect(src).toMatch(/from '\.\.\/core\/raw-approval\.js'/);
    expect(src).toMatch(/\bmapDecoded\b/);
    expect(src).toMatch(/from '\.\.\/core\/calldata\.js'/);
    expect(src).not.toMatch(/decodeErc20Calldata/);
    expect(src).not.toMatch(/callData[^\n]*toLowerCase/); // the calldata is never lower-cased into the execution
  });
});

describe('what no typed kind describes (DE-91): raw at a seat that allows it, NOT BOUND at every other', () => {
  const noTyped: Array<[string, string, string]> = [
    ['an unknown selector', UNKNOWN_SELECTOR, '0'],
    ['transferFrom', '0x23b872dd' + word(ADDR.treasury) + word(ADDR.vendorA) + word('5'), '0'],
    ['a dirty address pad', '0xa9059cbb' + 'ff' + word(ADDR.vendorA).slice(2) + word('5'), '0'],
    ['trailing bytes after the arguments', TRANSFER(ADDR.vendorA, '5') + '00', '0'],
    ['a token call that forwards native value', TRANSFER(ADDR.vendorA, '5'), '7'],
    ['an execute wrapper', '0xb61d27f6' + word(ADDR.token) + word('0') + word('96') + word('0'), '0'],
  ];

  it.each(noTyped)('%s: NOT BOUND (binding_absent, nothing signed) at a seat without allowRaw, absent or false', (_n, cd, value) => {
    for (const opts of [undefined, {}, { allowRaw: false }]) {
      const r = build(intentBody({ legs: [callLeg(cd, value)] }), opts);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.reason).toBe('binding_absent');
        expect(r.detail).toMatch(/^[a-z_]+$/);
      }
    }
  });

  it.each(noTyped)('%s: bound as raw at a seat that allows it, mapped beneficiary = target, asset = native, amount = native value (DE-90)', (_n, cd, value) => {
    const v = ok(intentBody({ legs: [callLeg(cd, value)] }), { allowRaw: true });
    expect(v.request).toMatchObject({ kind: 'raw', beneficiary: v.request['target'], asset: 'native', amount: value });
    expect(v.execution).toMatchObject({ target: v.request['target'], value, calldata: cd });
    // the core's own reference: the binding parses, the execution is authenticated by the commitment, and the raw mapping holds
    const wire = policyBindingOf(v);
    expect(wire.kind).toBe('raw');
    const parsed = parseWireBinding({ binding: wire });
    expect(parsed.ok).toBe(true);
    expect(authenticateExecution(wire, v.execution)).toMatchObject({ ok: true });
    // a raw request with an execution that lies about its calldata is refused by the reference
    expect(authenticateExecution(wire, { ...v.execution!, calldata: cd + '00' })).toMatchObject({ ok: false, reason: 'request_execution_mismatch' });
  });

  it('the core review of a raw call (reviewRaw) accepts what the signer sends: target, native value, calldata hash and length, token effect unknown, the exception needed (DE-92)', () => {
    const v = ok(intentBody({ legs: [callLeg(UNKNOWN_SELECTOR, '3')] }), { allowRaw: true });
    const r = reviewRaw({ binding: policyBindingOf(v), execution: v.execution });
    expect(r).toMatchObject({ ok: true, kind: 'raw', tokenEffect: 'unknown', needsException: true, calldataBytes: 68 });
    if (r.ok) expect(r.members).toMatchObject({ target: v.request['target'], value: '3', calldata: UNKNOWN_SELECTOR });
    // the same request WITHOUT its execution is not reviewable: a raw call whose execution is absent is never approved (DE-90)
    expect(reviewRaw({ binding: policyBindingOf(v) })).toMatchObject({ ok: false, reason: 'execution_absent' });
  });

  it('a typed kind is bound whatever allowRaw says (the raw switch widens nothing a typed call already is)', () => {
    const body = intentBody({ legs: [leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300' })] });
    expect(ok(body, { allowRaw: true }).request).toEqual(ok(body, { allowRaw: false }).request);
    expect(ok(body, { allowRaw: true }).request['kind']).toBe('erc20.transfer');
    expect(ok(intentBody({ legs: [leg({ kind: 'native', to: ADDR.vendorA, amount: '7' })] }), { allowRaw: true }).request['kind']).toBe('native.transfer');
  });

  it('the core binds a raw request only at a seat whose allowRaw is the boolean true (raw_not_allowed otherwise)', () => {
    const v = ok(intentBody({ legs: [callLeg(UNKNOWN_SELECTOR, '3')] }), { allowRaw: true });
    const requestHash = hashRequest(v.request);
    const rec = record({ requestHash, issuedAt: NOW - 5, nonce: H('n-raw') });
    const state = { requireGrant: false, grantHeadHash: null, grantHeadSubject: null, expectedPolicyHash: POLICY, authorizedApprovers: [APPROVER], consumed: [] as string[], maxWindowSeconds: 7200 };
    const presented = { request: v.request, legCount: 1, grantRefHash: null, seat: SEAT, subject: null };
    expect(bindDecision({ state, now: NOW, decision: rec, presented })).toMatchObject({ ok: false, reason: 'raw_not_allowed' });
    expect(bindDecision({ state: { ...state, allowRaw: false }, now: NOW, decision: rec, presented })).toMatchObject({ ok: false, reason: 'raw_not_allowed' });
    expect(bindDecision({ state: { ...state, allowRaw: true }, now: NOW, decision: rec, presented })).toMatchObject({ ok: true, requestHash });
  });

  it('presentOptionsOf carries the seat settings into the builder, so the policy request and the check can never read a call differently', () => {
    expect(presentOptionsOf({ allowRaw: true, settlementHorizonSeconds: 7200 })).toEqual({ allowRaw: true, horizonSeconds: 7200 });
    expect(presentOptionsOf({})).toEqual({ allowRaw: false, horizonSeconds: VALIDATOR_HORIZON_SECONDS });
  });
});

describe('the leaf expiry bound the signer forwards (DE-87, DE-88)', () => {
  const HEADER = '2026-11-15T12:00:00.000Z';
  const H_SEC = Date.parse(HEADER) / 1000; // read by the platform, not by the core arithmetic under test
  const withDeadline = (d: unknown) => intentBody({ legs: [leg({ legOverride: { deadline_timestamp: d } })] });

  it('is the header deadline plus the horizon when no leg declares one', () => {
    expect(ok(intentBody(), undefined, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 3600);
    expect(ok(intentBody(), { horizonSeconds: 7200 }, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 7200);
  });

  it('is the leg deadline when no header deadline exists, and the smaller of the two when both exist (a tie too)', () => {
    expect(ok(withDeadline(NOW + 500)).leafExpiry).toBe(NOW + 500);
    expect(ok(withDeadline(H_SEC + 3599), undefined, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 3599);
    expect(ok(withDeadline(H_SEC + 3601), undefined, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 3600);
    expect(ok(withDeadline(H_SEC + 3600), undefined, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 3600);
    // a leg deadline of 0 or none declares nothing
    expect(ok(withDeadline(0), undefined, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 3600);
  });

  it('is absent (null, never a guess) when neither a leg deadline nor a header deadline exists, and the binding then omits the member', () => {
    const v = ok(intentBody());
    expect(v.leafExpiry).toBeNull();
    expect('leafExpiry' in policyBindingOf(v)).toBe(false);
    // blob 3 expires_at is the intent validity and is no carrier of the leaf expiry
    expect(ok(intentBody({ blob3: { expires_at: NOW + 99 } })).leafExpiry).toBeNull();
  });

  it('floors the seat horizon at the validator one hour: 3599 is refused, 3600 is the default and is accepted', () => {
    expect(VALIDATOR_HORIZON_SECONDS).toBe(3600);
    expect(build(intentBody(), { horizonSeconds: 3599 }, { expiresAt: HEADER })).toEqual({ ok: false, detail: 'leaf_horizon_below_minimum:3599' });
    expect(ok(intentBody(), { horizonSeconds: 3600 }, { expiresAt: HEADER }).leafExpiry).toBe(H_SEC + 3600);
  });

  it('refuses a leg deadline that is negative, fractional or not a number, and a header deadline that is not an exact UTC instant', () => {
    for (const d of [-1, 1.5, '1790003600', true, {}]) expect(build(withDeadline(d)), String(d)).toMatchObject({ ok: false, detail: expect.stringMatching(/^leaf_expiry_input_malformed/) });
    expect(build(intentBody(), undefined, { expiresAt: '2026-11-15T13:00:00+01:00' })).toEqual({ ok: false, detail: 'leaf_header_time_invalid' });
  });

  it('is claimed for ONE-leg transactions only: several legs carry none', () => {
    const two = intentBody({ legs: [leg({ legOverride: { deadline_timestamp: NOW + 10 } }), leg({ to: ADDR.vendorB })] });
    expect(ok(two, undefined, { expiresAt: HEADER }).leafExpiry).toBeNull();
  });

  it('equals the core bound function of the same inputs and is accepted by the core reference parser as the wire member', () => {
    const v = ok(withDeadline(H_SEC + 100), { horizonSeconds: 5400 }, { expiresAt: HEADER });
    expect(leafExpiryBound({ legDeadlines: [H_SEC + 100], headerExpiresAt: HEADER, horizonSeconds: 5400 })).toEqual({ ok: true, leafExpiry: H_SEC + 100, basis: 'leg_deadline' });
    expect(v.leafExpiry).toBe(H_SEC + 100);
    const wire = policyBindingOf(v);
    expect(wire.leafExpiry).toBe(H_SEC + 100);
    const parsed = parseWireBinding({ binding: wire });
    expect(parsed).toMatchObject({ ok: true, leafExpiry: H_SEC + 100, legCount: 1 });
  });
});
