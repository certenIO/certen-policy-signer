/**
 * DAX-F176 (DECISION.md DE-114, DAX-4-A31): the bank registry account's declared holder registration, FDBUSD.setHolderStatus(holder, status), is BOUND as the
 * request kind holder.status at a seat WITHOUT allowRaw, exactly as a declared payment is bound (the ten request members, their hash, the commitment of the
 * call). Live it was NOT BOUND (`request_unbindable: binding_absent`): the decoder knew no typed kind for the call, so the bank-compliance seat could not
 * decide the registration and its officer was refused "no bound request". Any other unknown call stays not bound, and a malformed registration keeps its
 * decoder reason.
 */
import { describe, expect, it } from 'vitest';
import { buildPresentedRequest } from '../src/binding/request.js';
import { hashRequest } from '../src/core/hashes.js';
import { intentBody, leg } from './support/binding-fixtures.js';

const TX = 'd3f22d35a863ad08f5eaf7ccde8a07af69364e6d95052458322524461ba946c7';
// the live case (testnet, public): the FDBUSD token, the bank registry account's V7 and the large payer's V7 being registered Active
const TOKEN = '0x5b392Bf9E57fCF2afCF5C807eA954FB4B4b59ca4';
const REGISTRY = '0x2230c5Be48612D45553A1E71C8092313d02Ed7AF'.toLowerCase();
const HOLDER = '0x42Af67fE9d82bfA9dA4710F324abf11A97100F50';
const low = (a: string): string => a.toLowerCase();
const word = (v: string): string => v.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const shs = (holder: string, status: number): string => '0x72370319' + word(holder) + word(status.toString(16));
const build = (callData: string, o: { allowRaw?: boolean; value?: string } = {}) =>
  buildPresentedRequest({ txHash: TX, rawTransaction: { body: intentBody({ legs: [leg({ from: REGISTRY, token: TOKEN, to: HOLDER, payloadOverride: { callData, ...(o.value ? { value: o.value } : {}) } })] }) }, summary: { action: 'x' } as never }, { allowRaw: o.allowRaw ?? false });

describe('DAX-F176 the declared holder registration is bound at a seat without allowRaw', () => {
  it('setHolderStatus(holder, Active) is the request kind holder.status: the holder, the token, the status code, and the commitment of the call', () => {
    const r = build(shs(HOLDER, 1));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.request).toMatchObject({ kind: 'holder.status', source: REGISTRY, target: low(TOKEN), beneficiary: low(HOLDER), asset: low(TOKEN), amount: '1', txHash: '0x' + TX });
    expect(Object.keys(r.value.request).sort()).toEqual(['amount', 'asset', 'beneficiary', 'chainId', 'executionCommitment', 'kind', 'operationId', 'source', 'target', 'txHash']);
    expect(r.value.execution?.calldata).toBe(shs(HOLDER, 1));
    // another status is another request: Suspended is never bound by an Active decision
    const suspended = build(shs(HOLDER, 2));
    expect(suspended.ok && hashRequest(suspended.value.request)).not.toBe(hashRequest(r.value.request));
  });
  it('a malformed registration keeps its decoder reason and stays not bound; any other unknown call stays not bound', () => {
    expect(build(shs(HOLDER, 4))).toEqual({ ok: false, detail: 'holder_status_invalid', reason: 'binding_absent' });
    expect(build(shs(HOLDER, 1) + '00')).toEqual({ ok: false, detail: 'calldata_trailing_bytes', reason: 'binding_absent' });
    expect(build('0x72370318' + shs(HOLDER, 1).slice(10))).toEqual({ ok: false, detail: 'selector_unknown', reason: 'binding_absent' });
  });
});
