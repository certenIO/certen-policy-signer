/**
 * Token value must reach the policy engine.
 *
 * A leg's `amountWei` is the native value forwarded with a call. An ERC-20 transfer forwards none, so
 * before the decoder read calldata a `transfer(to, 1_000_000 USDC)` leg reached the engine as a
 * zero-value leg and passed every ceiling. These tests pin that the token amount is in `values`, that a
 * bridge-built token leg is not counted twice, that unknown calldata is reported but not refused, and
 * that a leg with neither amount is still unpriced.
 */
import { describe, it, expect } from 'vitest';
import { certenIntentDecoder, decodeErc20Calldata } from '../src/decode/decoders/certen-intent.js';

const CTX = { principal: 'acc://org.acme/data' };
const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
const word = (n: bigint | string) => BigInt(n).toString(16).padStart(64, '0');
const addr = (a: string) => a.replace(/^0x/, '').toLowerCase().padStart(64, '0');

const TOKEN = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'; // USDC on sepolia
const TO = '0xBe0043000000000000000000000000000000cafe';
const transferCalldata = (amount: bigint) => '0xa9059cbb' + addr(TO) + word(amount);
const approveCalldata = (amount: bigint) => '0x095ea7b3' + addr(TO) + word(amount);
const transferFromCalldata = (amount: bigint) => '0x23b872dd' + addr(TO) + addr(TOKEN) + word(amount);

function body(legs: Array<Record<string, unknown>>) {
  const blobs = [
    { intent_id: 'int-1', description: 'Pay Northwind', subject: undefined },
    { protocol: 'CERTEN', version: '2.0', legs },
    { governance: true },
    { replay: 1 },
  ];
  return { type: 'writeData', entry: { type: 'doubleHash', data: blobs.map(toHex) } };
}
const leg = (o: Record<string, unknown>) => ({ legId: 'l0', chain: 'ethereum-sepolia', asset: { symbol: 'ETH', decimals: 18 }, to: TO, ...o });

describe('decodeErc20Calldata', () => {
  it('decodes transfer, transferFrom and approve', () => {
    expect(decodeErc20Calldata(transferCalldata(1_000_000n))).toMatchObject({ fn: 'transfer', amount: '1000000', args: { to: TO.toLowerCase() } });
    expect(decodeErc20Calldata(transferFromCalldata(5n))).toMatchObject({ fn: 'transferFrom', amount: '5' });
    expect(decodeErc20Calldata(approveCalldata(2n ** 255n))).toMatchObject({ fn: 'approve', amount: (2n ** 255n).toString() });
  });
  it('declines native calldata, unknown selectors and malformed word counts', () => {
    expect(decodeErc20Calldata('0x')).toBeUndefined();
    expect(decodeErc20Calldata(undefined)).toBeUndefined();
    expect(decodeErc20Calldata('0x12345678' + word(1n))).toBeUndefined();
    expect(decodeErc20Calldata('0xa9059cbb' + addr(TO))).toBeUndefined(); // one word short
    expect(decodeErc20Calldata('0xa9059cbb' + addr(TO) + word(1n) + word(2n))).toBeUndefined(); // one word long
  });
});

describe('certen-intent decoder with ERC-20 calldata', () => {
  it('a contract-call leg moving tokens puts the TOKEN amount in values, not the zero native value', () => {
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '0', executionPayload: { target: TOKEN, value: '0', callData: transferCalldata(1_000_000n) },
    })]), CTX)!;
    expect(out.summary.values).toEqual(['1000000']);
    expect(out.summary.unpricedLegs).toBeUndefined();
    expect(out.summary.calldataDecoded).toMatch(/^transfer\(to = 0x/);
    expect(out.summary.action).toContain('transfer 1000000 token units on ' + TOKEN);
  });

  it('a bridge-built token leg (amountWei == token amount) is listed once', () => {
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '1000000', asset: { symbol: 'USDC', decimals: 6, native: false, contract_address: TOKEN },
      executionPayload: { target: TOKEN, value: '0', callData: transferCalldata(1_000_000n) },
    })]), CTX)!;
    expect(out.summary.values).toEqual(['1000000']);
  });

  it('a call that forwards native value AND moves tokens lists both amounts', () => {
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '4000', executionPayload: { target: TOKEN, value: '4000', callData: transferCalldata(7n) },
    })]), CTX)!;
    expect(out.summary.values).toEqual(['7', '4000']);
  });

  it('an escrow call with undecoded calldata keeps its native value and is reported, not refused', () => {
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '1500000000000000',
      executionPayload: { target: TO, value: '1500000000000000', callData: '0x12345678' + word(1n) },
    })]), CTX)!;
    expect(out.summary.values).toEqual(['1500000000000000']);
    expect(out.summary.unpricedLegs).toBeUndefined();
    expect(out.summary.raw?.opaqueCallLegs).toBe(1);
    expect(out.summary.action).toContain('1 contract call with undecoded calldata');
  });

  it('a leg with no native amount and no token amount is still unpriced', () => {
    const out = certenIntentDecoder.decode(body([leg({ amountWei: '10' }), leg({ legId: 'l1' })]), CTX)!;
    expect(out.summary.values).toEqual(['10']);
    expect(out.summary.unpricedLegs).toBe(1);
  });

  it('a plain native leg is unchanged', () => {
    const out = certenIntentDecoder.decode(body([leg({ amountWei: '4000', executionPayload: { target: TO, value: '4000', callData: '0x' } })]), CTX)!;
    expect(out.summary.values).toEqual(['4000']);
    expect(out.summary.calldataDecoded).toBeUndefined();
    expect(out.summary.raw?.opaqueCallLegs).toBeUndefined();
  });
});
