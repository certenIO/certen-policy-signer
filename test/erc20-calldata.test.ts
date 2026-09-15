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

/**
 * What a call GRANTS, which is not what it moves. T18/T21.
 *
 * An `approve` forwards no value and hands somebody standing authority to move a balance later. Every
 * number this decoder emitted answered "how much moves", so a gate reading `values` saw `0` and a rule
 * meaning "small enough to approve automatically" matched an UNLIMITED spending approval. It was found
 * in the approval console's own demo data by an unbriefed reviewer in under four minutes.
 *
 * The console has been able to EXPRESS that bound for some time (`maxAllowance`), and the wire carried
 * nothing to evaluate it against — so the rule could be written and could never fire. This is the wire.
 */
describe('what a call grants', () => {
  const UNLIMITED = 2n ** 256n - 1n;

  it('emits the spender and the allowance for an approve', () => {
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '0',
      asset: { symbol: 'USDC', decimals: 6, contract_address: TOKEN },
      executionPayload: { target: TOKEN, value: '0', callData: approveCalldata(5_000_000n) },
    })]), CTX)!;

    expect(out.summary.grant).toEqual({
      spender: TO.toLowerCase(),
      allowance: '5000000',
      asset: { symbol: 'USDC', decimals: 6 },
    });
  });

  it('carries an UNLIMITED approval through as the full integer', () => {
    // The headline case. A gate cannot recognise unlimited if the wire rounds, truncates or omits it,
    // and 2^256 - 1 is unlimited at every precision — so this is the one bound that still works when
    // the payload names no decimals at all.
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '0',
      asset: { symbol: 'USDC' },
      executionPayload: { target: TOKEN, value: '0', callData: approveCalldata(UNLIMITED) },
    })]), CTX)!;

    expect(out.summary.grant?.allowance).toBe(UNLIMITED.toString());
    expect(out.summary.grant?.asset).toEqual({ symbol: 'USDC' });
  });

  it('does NOT describe a transfer as a grant', () => {
    // `transfer` and `transferFrom` move a balance and are already bounded by `values`. Calling them
    // grants would put one number under two names and invite a rule set to bound it twice while
    // believing it had covered two different risks.
    for (const callData of [transferCalldata(10n), transferFromCalldata(10n)]) {
      const out = certenIntentDecoder.decode(body([leg({
        amountWei: '0', executionPayload: { target: TOKEN, value: '0', callData },
      })]), CTX)!;
      expect(out.summary.grant).toBeUndefined();
    }
  });

  it('omits decimals rather than guessing when the payload does not state them', () => {
    // A guessed precision is a WRONG bound, not a missing one: it silently rescales the number a
    // control is measured against. Absent must stay absent so an engine can refuse to match.
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '0',
      asset: { symbol: 'WEIRD' },
      executionPayload: { target: TOKEN, value: '0', callData: approveCalldata(1n) },
    })]), CTX)!;
    expect(out.summary.grant?.asset).toEqual({ symbol: 'WEIRD' });
    expect(out.summary.grant?.asset).not.toHaveProperty('decimals');
  });

  it('ignores a decimals the payload states nonsensically', () => {
    for (const decimals of [-1, 1.5, 999, 'six']) {
      const out = certenIntentDecoder.decode(body([leg({
        amountWei: '0',
        asset: { symbol: 'ODD', decimals },
        executionPayload: { target: TOKEN, value: '0', callData: approveCalldata(1n) },
      })]), CTX)!;
      expect(out.summary.grant?.asset, String(decimals)).toEqual({ symbol: 'ODD' });
    }
  });

  it('says nothing about a call it could not decode', () => {
    // Absent `grant` means "no grant this decoder could read", NOT "grants nothing" — which is exactly
    // why a rule set should also route on `calldataDecoded` being present.
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '4000', executionPayload: { target: TOKEN, value: '4000', callData: '0xdeadbeef' + word(1n) },
    })]), CTX)!;
    expect(out.summary.grant).toBeUndefined();
    // Phase 6.1: the leg is still listed (so "calldata present" is visible), with no function read.
    expect(out.summary.calldataDecoded).toEqual([{ legIndex: 0, chainId: 11155111, target: TOKEN.toLowerCase(), abi: '', function: '', signature: '0xdeadbeef', args: {} }]);
    expect(out.summary.targetKnown).toBe(false);
  });
});

describe('certen-intent decoder with ERC-20 calldata', () => {
  it('a contract-call leg moving tokens puts the TOKEN amount in values, not the zero native value', () => {
    const out = certenIntentDecoder.decode(body([leg({
      amountWei: '0', executionPayload: { target: TOKEN, value: '0', callData: transferCalldata(1_000_000n) },
    })]), CTX)!;
    expect(out.summary.values).toEqual(['1000000']);
    expect(out.summary.unpricedLegs).toBeUndefined();
    expect(out.summary.calldataDecoded).toEqual([{
      legIndex: 0, chainId: 11155111, target: TOKEN.toLowerCase(), abi: '', function: 'transfer', signature: 'transfer(address,uint256)',
      args: { to: TO.toLowerCase(), amount: '1000000' },
    }]);
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
