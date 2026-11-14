/**
 * The request the signer builds from the transaction it is about to sign (src/binding/request.ts): the mapping from a pending
 * CERTEN intent to the ten members the core hashes, the refusals (named, never a guess), and the property DAX-4-A1 rests on:
 * a change of amount, beneficiary, source, chain, Accumulate transaction or execution commitment changes the request hash, so
 * a decision for the old request is `request_mismatch`.
 */
import { describe, expect, it } from 'vitest';
import { buildPresentedRequest } from '../src/binding/request.js';
import { policyBindingOf } from '../src/binding/policy-binding.js';
import { bindDecision } from '../src/core/decision-binding.js';
import { hashRequest } from '../src/core/hashes.js';
import { ADDR, APPROVER, GRANT_HASH, H, POLICY, SEAT, SUBJECT, commitmentOfLeg, intentBody, leg, record, subjectClaim } from './support/binding-fixtures.js';

const TX = 'ab'.repeat(32);
type Body = ReturnType<typeof intentBody>;
const build = (body: Body, txHash = TX, summary: Record<string, unknown> = { action: 'x' }) => buildPresentedRequest({ txHash, rawTransaction: { body }, summary: summary as never });
const ok = (body: Body, txHash = TX, summary: Record<string, unknown> = { action: 'x' }) => {
  const r = build(body, txHash, summary);
  if (!r.ok) throw new Error('expected a request, got ' + r.detail);
  return r.value;
};

describe('the request built from a pending intent', () => {
  it('maps an ERC-20 transfer leg: token as asset, recipient as beneficiary, decimal amount', () => {
    const v = ok(intentBody({ legs: [leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300' })] }));
    expect(v.request).toMatchObject({ chainId: 84532, kind: 'erc20.transfer', source: ADDR.treasury, target: ADDR.token, beneficiary: ADDR.vendorA, asset: ADDR.token, amount: '300', txHash: '0x' + TX });
    expect(v.request['executionCommitment']).toBe(commitmentOfLeg(leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300' })));
    expect(v.request['operationId']).toBe(v.operationId);
    expect(Object.keys(v.request).sort()).toEqual(['amount', 'asset', 'beneficiary', 'chainId', 'executionCommitment', 'kind', 'operationId', 'source', 'target', 'txHash']);
    expect(() => hashRequest(v.request)).not.toThrow();
  });

  it('maps an approve leg (spender is the beneficiary) and a native leg (target is the beneficiary, asset native)', () => {
    expect(ok(intentBody({ legs: [leg({ kind: 'erc20.approve', to: ADDR.vendorB, amount: '5' })] })).request).toMatchObject({ kind: 'erc20.approve', beneficiary: ADDR.vendorB, asset: ADDR.token, amount: '5' });
    expect(ok(intentBody({ legs: [leg({ kind: 'native', to: ADDR.vendorA, amount: '7' })] })).request).toMatchObject({ kind: 'native.transfer', target: ADDR.vendorA, beneficiary: ADDR.vendorA, asset: 'native', amount: '7' });
  });

  it('keeps the producer grantRef as a CLAIM and the asserted subject as an assertion', () => {
    const ref = { grantId: 'grant-one', version: 2, grantHash: H('grant-v2') };
    const v = ok(intentBody({ grantRef: ref, subject: subjectClaim() }), TX, { action: 'x', subject: subjectClaim() });
    expect(v.grantRef).toEqual(ref);
    expect(v.grantRefHash).toBe(ref.grantHash);
    expect(v.assertedSubject).toEqual(subjectClaim());
    const none = ok(intentBody());
    expect(none.grantRef).toBeNull();
    expect(none.grantRefHash).toBeNull();
    expect(none.assertedSubject).toBeNull();
  });

  it('lowercases the commitment and the transaction hash (with or without 0x); an address must already be canonical lower case', () => {
    const c = commitmentOfLeg(leg());
    const v = ok(intentBody({ legs: [leg({ commitment: c.toUpperCase().replace('0X', '0x') })] }), '0x' + TX.toUpperCase());
    expect(v.request['executionCommitment']).toBe(c);
    expect(v.request['txHash']).toBe('0x' + TX);
    // a checksum-case address is refused by name, as the strict decoder refuses it (DAX7A-F2): no second spelling of one address
    expect(build(intentBody({ legs: [leg({ from: '0x' + 'AB'.repeat(20) })] }))).toEqual({ ok: false, detail: 'source_address' });
    // hex digits of the CALLDATA are not normalised either (golden v2 g15, DE-91, DAXCORE2 R1): upper case is refused, never read as the same bytes
    expect(build(intentBody({ legs: [leg({ to: '0x' + 'CD'.repeat(20) })] }))).toEqual({ ok: false, detail: 'calldata_hex_invalid' });
  });

  it('reads the calldata text as strictly as the strict decoder: 0x required, a clean address word', () => {
    const word = (a: string) => a.replace('0x', '').padStart(64, '0');
    const calldata = (hi: string) => '0xa9059cbb' + hi + ADDR.vendorA.replace('0x', '') + word((300).toString(16));
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: calldata('0'.repeat(24)) } })] })).ok).toBe(true);
    // a dirty address word is no typed kind: NOT BOUND at a seat without allowRaw (binding_absent), the decoder reason as the detail (DE-91)
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: calldata('0'.repeat(23) + '1') } })] }))).toEqual({ ok: false, detail: 'address_pad_dirty', reason: 'binding_absent' });
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: calldata('0'.repeat(24)).slice(2) } })] }))).toEqual({ ok: false, detail: 'calldata_prefix_invalid' });
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: '0X' + calldata('0'.repeat(24)).slice(2) } })] }))).toEqual({ ok: false, detail: 'calldata_prefix_invalid' });
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: 5 } })] }))).toEqual({ ok: false, detail: 'calldata_not_text' });
  });
});

describe('legCount is derived from the legs and ALWAYS supplied (DE-76, DAX-4-A20)', () => {
  it('is 1 for one leg, the number of legs otherwise, and the core refuses a legCount other than 1 by name', () => {
    expect(ok(intentBody()).legCount).toBe(1);
    expect(ok(intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })] })).legCount).toBe(2);
    expect(ok(intentBody({ legs: [leg(), leg(), leg({ to: ADDR.vendorB })] })).legCount).toBe(3);
    const NOW = 1_800_000_000;
    const state = { requireGrant: false, grantHeadHash: null, grantHeadSubject: null, expectedPolicyHash: POLICY, authorizedApprovers: [APPROVER], consumed: [] as string[], maxWindowSeconds: 86400 };
    for (const legs of [[leg(), leg({ to: ADDR.vendorB })], [leg({ payloadOverride: { callData: '0xdeadbeef' } }), leg()]]) {
      const v = ok(intentBody({ legs }));
      const r = bindDecision({ state, now: NOW, decision: record({ requestHash: hashRequest(v.request), issuedAt: NOW - 1 }), presented: { request: v.request, legCount: v.legCount, grantRefHash: null, seat: SEAT, subject: null } });
      expect(r).toMatchObject({ ok: false, reason: 'multi_leg_unsupported' }); // even when the first leg cannot be mapped (a placeholder request stands in, never compared)
    }
    // one leg that cannot be mapped is still presented_malformed: nothing is guessed
    expect(build(intentBody({ legs: [leg({ payloadOverride: { callData: '0xdeadbeef' } })] }))).toEqual({ ok: false, detail: 'selector_unknown', reason: 'binding_absent' });
  });
  it('a single-leg request is what the Console is told (policyBindingOf: ten members, the validator id named validatorOperationId, and legCount; no grantRef when the intent names none)', () => {
    const v = ok(intentBody());
    expect(policyBindingOf(v)).toEqual({
      chainId: 84532, kind: 'erc20.transfer', source: ADDR.treasury, target: ADDR.token, beneficiary: ADDR.vendorA, asset: ADDR.token, amount: '300',
      executionCommitment: commitmentOfLeg(leg()), validatorOperationId: v.operationId, txHash: '0x' + TX, legCount: 1,
    });
  });
});

describe('what cannot be bound is refused by name, never guessed', () => {
  const refused = (body: Body, detail: string, summary?: Record<string, unknown>, reason?: 'binding_absent') => {
    const r = build(body, TX, summary);
    expect(r).toEqual({ ok: false, detail, ...(reason ? { reason } : {}) });
  };
  it('no leg, no payload', () => {
    refused(intentBody({ legs: [] }), 'no_leg');
    const l = leg() as Record<string, unknown>;
    delete l['executionPayload'];
    refused(intentBody({ legs: [l] }), 'no_execution_payload');
  });
  it('an unsupported action or calldata', () => {
    // no typed kind describes these (DE-91): NOT BOUND at a seat without allowRaw, by the decoder's own reason
    refused(intentBody({ legs: [leg({ kind: 'erc20.transferFrom' })] }), 'selector_unknown', undefined, 'binding_absent');
    refused(intentBody({ legs: [leg({ payloadOverride: { callData: '0xdeadbeef' } })] }), 'selector_unknown', undefined, 'binding_absent');
    refused(intentBody({ legs: [leg({ payloadOverride: { value: '5' }, legOverride: { amountWei: '5' } })] }), 'token_call_carries_value', undefined, 'binding_absent');
  });
  it('a missing or inconsistent chain, address, amount or commitment', () => {
    refused(intentBody({ legs: [leg({ payloadOverride: { chainId: undefined }, legOverride: { chainId: undefined, chain: 'base-sepolia' } })] }), 'chain_id');
    refused(intentBody({ legs: [leg({ legOverride: { chainId: 1 } })] }), 'chain_id');
    refused(intentBody({ legs: [leg({ from: '0x1234' })] }), 'source_address');
    refused(intentBody({ legs: [leg({ legOverride: { to: ADDR.other } })] }), 'target_disagrees');
    refused(intentBody({ legs: [leg({ payloadOverride: { executionCommitment: '0x12' } })] }), 'execution_commitment');
    refused(intentBody({ legs: [leg({ kind: 'native', payloadOverride: { value: '5' }, legOverride: { amountWei: '6' } })] }), 'value_disagrees');
    refused(intentBody({ legs: [leg({ kind: 'native', payloadOverride: { value: '-5' }, legOverride: { amountWei: '-5' } })] }), 'native_amount');
  });
  it('a body that is not a four-blob data entry, a malformed grantRef', () => {
    expect(build({ type: 'sendTokens' } as never)).toEqual({ ok: false, detail: 'not_write_data' });
    expect(build({ type: 'writeData', entry: { data: ['00'] } } as never)).toEqual({ ok: false, detail: 'entry_shape' });
    expect(build({ type: 'writeData', entry: { data: ['zz', '00', '00', '00'] } } as never)).toEqual({ ok: false, detail: 'entry_not_hex' });
    refused(intentBody({ grantRef: { grantId: 'g', version: 1, grantHash: 'nope' } }), 'grantref_malformed');
    refused(intentBody({ grantRef: 'g' }), 'grantref_malformed');
  });
});

describe('a mutated transaction is a different request (DAX-4-A1)', () => {
  const NOW = 1_800_000_000;
  const state = { requireGrant: false, grantHeadHash: null, grantHeadSubject: null, expectedPolicyHash: POLICY, authorizedApprovers: [APPROVER], consumed: [] as string[], maxWindowSeconds: 86400 };
  const base = intentBody();
  const decisionFor = (b: Body, tx = TX) => record({ requestHash: hashRequest(ok(b, tx).request), issuedAt: NOW - 1, nonce: H('n-' + Math.random()) });
  const bindAgainst = (decision: Record<string, unknown>, b: Body, tx = TX) => bindDecision({ state, now: NOW, decision, presented: { request: ok(b, tx).request, grantRefHash: null, seat: SEAT, subject: null } });

  it('the decision for the original passes against the original', () => {
    expect(bindAgainst(decisionFor(base), base)).toMatchObject({ ok: true });
  });

  const mutations: Array<[string, Body, string?]> = [
    ['amount', intentBody({ legs: [leg({ amount: '301' })] })],
    ['beneficiary', intentBody({ legs: [leg({ to: ADDR.vendorB })] })],
    ['source account', intentBody({ legs: [leg({ from: ADDR.other })] })],
    ['chain', intentBody({ legs: [leg({ chainId: 11155111 })] })],
    // the execution commitment cannot change ALONE any more: the signer recomputes it over the execution (DAX-4S round 5), so a changed
    // commitment with unchanged bytes is presented_malformed (test 'refuses a stated commitment that is not the one of the bytes'); a changed
    // execution is one of the rows below (amount, beneficiary, token, chain, source) and moves the commitment with it
    ['token (asset and target)', intentBody({ legs: [leg({ token: ADDR.other })] })],
    ['kind (native instead of token)', intentBody({ legs: [leg({ kind: 'native' })] })],
    ['another operation (a blob member changes the validator id)', intentBody({ extra0: { description: 'another payment' } })],
  ];
  for (const [name, body] of mutations) {
    it(`refuses a decision for the original when the ${name} changed`, () => {
      expect(bindAgainst(decisionFor(base), body)).toMatchObject({ ok: false, reason: 'request_mismatch' });
    });
  }
  it('refuses a decision for the original when the Accumulate transaction is another one', () => {
    expect(bindAgainst(decisionFor(base), base, 'cd'.repeat(32))).toMatchObject({ ok: false, reason: 'request_mismatch' });
  });
  it('carries the Grant and the subject through unchanged by the request hash (published goldens never move)', () => {
    const a = ok(intentBody());
    const b = ok(intentBody({ grantRef: { grantId: 'g-1', version: 1, grantHash: GRANT_HASH }, subject: subjectClaim() }));
    // the producer's extra blob-0 members change the validator operation id (they are inside the hash of the four blobs)
    expect(a.operationId).not.toBe(b.operationId);
    void SUBJECT;
  });
});

describe('the execution the Console needs to decode what runs (DAX7C-F1): chainId, source, target, value, calldata, authenticated by the commitment', () => {
  const calldataOf = (v: { execution: { calldata: string } | null }): string => v.execution!.calldata;

  it('an ERC-20 transfer: the bytes the leg executes, lower case, the token as target, a decimal value of 0', () => {
    const v = ok(intentBody({ legs: [leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300' })] }));
    expect(v.execution).toEqual({ chainId: 84532, source: ADDR.treasury, target: ADDR.token, value: '0', calldata: '0xa9059cbb' + '00'.repeat(12) + '33'.repeat(20) + (300).toString(16).padStart(64, '0') });
    expect(Object.keys(v.execution!).sort()).toEqual(['calldata', 'chainId', 'source', 'target', 'value']);
  });

  it('an approve and a native transfer (value in wei, empty calldata `0x`)', () => {
    expect(calldataOf(ok(intentBody({ legs: [leg({ kind: 'erc20.approve', to: ADDR.vendorA, amount: '5' })] })))).toMatch(/^0x095ea7b3[0-9a-f]{128}$/);
    const n = ok(intentBody({ legs: [leg({ kind: 'native', to: ADDR.vendorA, amount: '1500000000000000000' })] }));
    expect(n.execution).toEqual({ chainId: 84532, source: ADDR.treasury, target: ADDR.vendorA, value: '1500000000000000000', calldata: '0x' });
  });

  it('the calldata is the lower-case hex the intent states (upper case is REFUSED, never read as the same bytes), and value is always a decimal STRING', () => {
    const lower = leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300' });
    const cd = (lower['executionPayload'] as { callData: string }).callData;
    // a numeric `value` member (0) is still sent as the decimal STRING '0'
    const v = ok(intentBody({ legs: [leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300', commitment: commitmentOfLeg(lower), payloadOverride: { value: 0 } })] }));
    expect(calldataOf(v)).toBe(cd);
    expect(v.execution!.value).toBe('0');
    expect(typeof v.execution!.value).toBe('string');
    // the same bytes in upper case: refused by the decoder's reason (golden v2 g15), nothing is normalised and nothing is sent
    const upper = leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300', commitment: commitmentOfLeg(lower), payloadOverride: { callData: '0x' + cd.slice(2).toUpperCase(), value: 0 } });
    expect(build(intentBody({ legs: [upper] }))).toEqual({ ok: false, detail: 'calldata_hex_invalid' });
  });

  it('it is the execution of the SAME leg the ten members come from: chainId, source and target agree with the request, and the request commitment authenticates it', () => {
    const v = ok(intentBody({ legs: [leg({ kind: 'erc20.transfer', to: ADDR.vendorA, amount: '300', chainId: 11155111, from: ADDR.other })] }));
    expect(v.execution).toMatchObject({ chainId: v.request['chainId'], source: v.request['source'], target: v.request['target'] });
  });

  it('a several-leg intent carries NO execution (a batch commitment is another form), nor does an intent whose first leg cannot be mapped', () => {
    expect(ok(intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })] })).execution).toBeNull();
    expect(ok(intentBody({ legs: [leg({ kind: 'erc20.transferFrom' }), leg()] })).execution).toBeNull();
  });

  it('refuses a stated commitment that is not the one of the bytes: execution_commitment_mismatch, nothing is guessed', () => {
    const good = commitmentOfLeg(leg());
    expect(build(intentBody({ legs: [leg({ commitment: good.slice(0, -1) + (good.endsWith('0') ? '1' : '0') })] }))).toEqual({ ok: false, detail: 'execution_commitment_mismatch' });
    expect(build(intentBody({ legs: [leg({ commitment: H('commit-1') })] }))).toEqual({ ok: false, detail: 'execution_commitment_mismatch' });
    // the commitment of ANOTHER execution (a different amount) is not the commitment of these bytes
    const other = commitmentOfLeg(leg({ amount: '301' }));
    expect(build(intentBody({ legs: [leg({ commitment: other })] }))).toEqual({ ok: false, detail: 'execution_commitment_mismatch' });
    // and so is the commitment of the same bytes on another chain
    const otherChain = commitmentOfLeg(leg({ chainId: 11155111 }));
    expect(build(intentBody({ legs: [leg({ commitment: otherChain })] }))).toEqual({ ok: false, detail: 'execution_commitment_mismatch' });
    // an uppercase spelling of the TRUE commitment is the same commitment
    expect(build(intentBody({ legs: [leg({ commitment: good.toUpperCase().replace('0X', '0x') })] }))).toMatchObject({ ok: true });
  });

  it('a several-leg intent is not authenticated (its commitment is a batch form), so a stated commitment that is no single-call hash is not refused here', () => {
    expect(build(intentBody({ legs: [leg({ commitment: H('batch') }), leg({ to: ADDR.vendorB })] }))).toMatchObject({ ok: true });
  });
});
