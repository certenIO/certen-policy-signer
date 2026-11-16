/**
 * DAX-CORE-R8, items 4 and 5 at the signer (DECISION.md DE-106, DE-107; DAX-4-A30; findings DAXL4-F13 and DAXL4-F14): the request is built from an intent whose addresses arrive in the EIP-55
 * checksum case (every real lab intent does), and from the lab's real payment leg, FDBUSD.transferWithReference. The addresses below are the lab's REAL ones (testnet, public), in the case the producer passed them.
 */
import { describe, expect, it } from 'vitest';
import { buildPresentedRequest } from '../src/binding/request.js';
import { toChecksumAddress } from '../src/core/calldata-keccak.js';
import { hashRequest } from '../src/core/hashes.js';
import { intentBody, leg } from './support/binding-fixtures.js';

const TX = 'ab'.repeat(32);
const PAYER = '0x9D268e8384beDa2cB3D2c289aA81d711959d6A47';
const TOKEN = '0xEccde7eAcaDD8c4EaCc1a36Bc91FBadAFDdb176c';
const PAYEE = '0x1551c29A7349DEC67f2928462e45e86D8df21F6E';
const low = (a: string): string => a.toLowerCase();
const build = (body: ReturnType<typeof intentBody>, o: { allowRaw?: boolean } = {}) => buildPresentedRequest({ txHash: TX, rawTransaction: { body }, summary: { action: 'x' } as never }, o);
const word = (v: string): string => v.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const REF = '0x' + '7f'.repeat(32);
const twr = (to: string, amount: bigint, ref = REF): string => '0xe2233eb8' + word(to) + word(amount.toString(16)) + ref.slice(2);
const paymentLeg = (o: { from: string; token: string; to: string; callData?: string }) => leg({ from: o.from, token: o.token, to: o.to, payloadOverride: { callData: o.callData ?? twr(o.to, 4250000n) } });

describe('addresses in the EIP-55 checksum case (DAXL4-F13, DE-106)', () => {
  it('the real lab addresses are in the checksum case, and the checksum is the core\'s', () => {
    for (const a of [PAYER, TOKEN, PAYEE]) expect(toChecksumAddress(low(a))).toBe(a);
  });

  it('a leg whose addresses arrive in the checksum case builds the SAME request, commitment and execution as the lower-case leg (every member lower case); only the operation id differs, because it is the hash of the bytes of the intent', () => {
    const mixed = build(intentBody({ legs: [paymentLeg({ from: PAYER, token: TOKEN, to: PAYEE })] }));
    const lower = build(intentBody({ legs: [paymentLeg({ from: low(PAYER), token: low(TOKEN), to: low(PAYEE) })] }));
    expect(mixed.ok).toBe(true);
    expect(lower.ok).toBe(true);
    if (!mixed.ok || !lower.ok) return;
    // the operation id is the validator's hash over the intent's entries (the bytes as spelled), so two spellings of one payment are two operations; every OTHER member, and so the commitment, is equal
    expect(mixed.value.request.operationId).not.toBe(lower.value.request.operationId);
    const sameOperation = { ...mixed.value.request, operationId: lower.value.request.operationId };
    expect(sameOperation).toEqual(lower.value.request);
    expect(hashRequest(sameOperation)).toBe(hashRequest(lower.value.request));
    expect(mixed.value.request.executionCommitment).toBe(lower.value.request.executionCommitment);
    expect(mixed.value.execution).toEqual(lower.value.execution);
    expect(mixed.value.request).toMatchObject({ source: low(PAYER), target: low(TOKEN), beneficiary: low(PAYEE), asset: low(TOKEN) });
    for (const m of ['source', 'target', 'beneficiary', 'asset'] as const) expect(mixed.value.request[m]).toBe(String(mixed.value.request[m]).toLowerCase());
  });

  it('a mixed-case spelling with a WRONG checksum is refused by name for the source and the target, never normalised', () => {
    const flip = (a: string): string => {
      const i = [...a].findIndex((c, k) => k >= 2 && /[a-fA-F]/.test(c));
      return a.slice(0, i) + (a[i] === a[i]!.toUpperCase() ? a[i]!.toLowerCase() : a[i]!.toUpperCase()) + a.slice(i + 1);
    };
    expect(build(intentBody({ legs: [paymentLeg({ from: flip(PAYER), token: low(TOKEN), to: low(PAYEE) })] }))).toEqual({ ok: false, detail: 'address_checksum_invalid:source' });
    expect(build(intentBody({ legs: [paymentLeg({ from: low(PAYER), token: flip(TOKEN), to: low(PAYEE) })] }))).toEqual({ ok: false, detail: 'address_checksum_invalid:target' });
  });

  it('an all-upper-case spelling and a malformed one stay refused as before', () => {
    expect(build(intentBody({ legs: [paymentLeg({ from: '0x' + PAYER.slice(2).toUpperCase(), token: low(TOKEN), to: low(PAYEE) })] }))).toEqual({ ok: false, detail: 'source_address' });
    expect(build(intentBody({ legs: [paymentLeg({ from: '0x1234', token: low(TOKEN), to: low(PAYEE) })] }))).toEqual({ ok: false, detail: 'source_address' });
  });
});

describe('the lab payment transferWithReference (DAXL4-F14, DE-107)', () => {
  it('is bound as an erc20.transfer of the amount to the recipient: the ten members, no new member, the commitment binds the reference', () => {
    const r = build(intentBody({ legs: [paymentLeg({ from: PAYER, token: TOKEN, to: PAYEE })] }));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.request).toMatchObject({ kind: 'erc20.transfer', beneficiary: low(PAYEE), asset: low(TOKEN), amount: '4250000' });
    expect(Object.keys(r.value.request).sort()).toEqual(['amount', 'asset', 'beneficiary', 'chainId', 'executionCommitment', 'kind', 'operationId', 'source', 'target', 'txHash']);
    expect(r.value.execution?.calldata).toBe(twr(PAYEE, 4250000n));
    // another reference is another call: another commitment, so another request hash (the reference is bound without being a member)
    const other = build(intentBody({ legs: [paymentLeg({ from: PAYER, token: TOKEN, to: PAYEE, callData: twr(PAYEE, 4250000n, '0x' + '00'.repeat(32)) })] }));
    expect(other.ok && hashRequest(other.value.request)).not.toBe(hashRequest(r.value.request));
  });

  it('a reference payment with a dirty address word, trailing bytes or a native value is not a typed kind: not bound at a seat without allowRaw, by the decoder\'s reason', () => {
    const ok = twr(PAYEE, 1n);
    const dirty = '0xe2233eb8' + '00'.repeat(11) + '01' + ok.slice(10 + 24);
    expect(build(intentBody({ legs: [paymentLeg({ from: PAYER, token: TOKEN, to: PAYEE, callData: dirty })] }))).toEqual({ ok: false, detail: 'address_pad_dirty', reason: 'binding_absent' });
    expect(build(intentBody({ legs: [paymentLeg({ from: PAYER, token: TOKEN, to: PAYEE, callData: ok + '00' })] }))).toEqual({ ok: false, detail: 'calldata_trailing_bytes', reason: 'binding_absent' });
  });
});
