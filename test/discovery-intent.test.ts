import { describe, it, expect } from 'vitest';
import { extractSignatureRequestTxIds, splitTxId } from '../src/accumulate/raw-client.js';
import { decodeCertenIntent, decodeSummary } from '../src/resolver.js';

/** Real record shape captured from Kermit for the Stage-A spike's O book signature chain. */
const LIVE_SIGCHAIN_RECORD = {
  recordType: 'chainEntry',
  name: 'signature',
  value: {
    recordType: 'message',
    message: {
      type: 'signatureRequest',
      authority: 'acc://o-1783668289868.acme/book',
      txID: 'acc://14263d236a9f530096c7c6ed71bec24ec1fa9556c85b06c691eefc8bd3da561f@a-1783668289868.acme/data',
    },
    produced: {
      recordType: 'range',
      records: [
        { recordType: 'txID', value: 'acc://14263d236a9f530096c7c6ed71bec24ec1fa9556c85b06c691eefc8bd3da561f@a-1783668289868.acme/data' },
      ],
    },
  },
};

describe('Phase 3 signature-chain parsing', () => {
  it('extracts produced txIDs from a real signatureRequest record', () => {
    const ids = extractSignatureRequestTxIds([LIVE_SIGCHAIN_RECORD]);
    expect(ids).toContain('acc://14263d236a9f530096c7c6ed71bec24ec1fa9556c85b06c691eefc8bd3da561f@a-1783668289868.acme/data');
  });

  it('ignores non-signatureRequest records', () => {
    const ids = extractSignatureRequestTxIds([{ value: { message: { type: 'transaction' } } }]);
    expect(ids).toEqual([]);
  });

  it('dedups the message.txID against produced records', () => {
    // produced + message.txID both point at the same tx → one entry
    expect(extractSignatureRequestTxIds([LIVE_SIGCHAIN_RECORD])).toHaveLength(1);
  });

  it('splitTxId separates hash and principal', () => {
    const { hash, principal } = splitTxId('acc://ABCD@a-1.acme/data');
    expect(hash).toBe('abcd');
    expect(principal).toBe('a-1.acme/data');
  });
});

/** Build a writeData body in the reference 4-blob intent format, exactly as a real producer emits it. */
function certenWriteDataBody(amountWei: string) {
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const blobs = [
    { kind: 'CERTEN_INTENT', version: '2.0', intentType: 'single_leg_cross_chain_transfer', intent_id: 'intent-abc', description: 'Transfer test' },
    { protocol: 'CERTEN', version: '2.0', legs: [{ legId: 'leg-1', chain: 'ethereum-sepolia', asset: { symbol: 'ETH', decimals: 18 }, to: '0xBe0043', amountWei, amountEth: '0.000000000000004000' }] },
    { organizationAdi: 'acc://o.acme', authorization: { required_key_book: 'acc://o.acme/book', signature_threshold: 1 } },
    { nonce: 'certen_1', expires_at: 1748200000 },
  ];
  return { type: 'writeData', entry: { type: 'doubleHash', data: blobs.map(toHex) } };
}

describe('Certen intent decode (4-blob)', () => {
  it('decodes the 4 blobs and pulls amountWei from leg 0', () => {
    const intent = decodeCertenIntent(certenWriteDataBody('4000'));
    expect(intent?.intent?.kind).toBe('CERTEN_INTENT');
    expect(intent?.crossChain?.legs?.[0].amountWei).toBe('4000');
    expect(intent?.governance?.authorization?.signature_threshold).toBe(1);
  });

  it('resolver surfaces amountWei as `value` for the policy engine (even case)', () => {
    const { summary } = decodeSummary(certenWriteDataBody('4000'), 'acc://a.acme/data');
    expect(summary.value).toBe('4000'); // even → engine approves
    expect(summary.chain).toBe('ethereum-sepolia');
    expect(summary.action).toContain('Transfer test');
  });

  it('resolver surfaces an odd amountWei (reject case)', () => {
    const { summary } = decodeSummary(certenWriteDataBody('4001'), 'acc://a.acme/data');
    expect(summary.value).toBe('4001'); // odd → engine denies
  });

  it('returns undefined for a non-intent writeData (falls back gracefully)', () => {
    expect(decodeCertenIntent({ type: 'writeData', entry: { data: ['not-hex-json'] } })).toBeUndefined();
  });
});

/** Build a multi-leg CERTEN intent (amounts per leg). */
function multiLegBody(amounts: string[]) {
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const blobs = [
    { kind: 'CERTEN_INTENT', intent_id: 'ml', description: 'Multi-leg' },
    { protocol: 'CERTEN', legs: amounts.map((amountWei, i) => ({ legId: `l${i}`, chain: 'ethereum-sepolia', asset: { symbol: 'ETH' }, to: `0x${i}`, amountWei })) },
    { authorization: { signature_threshold: 1 } },
    { nonce: 'n' },
  ];
  return { type: 'writeData', entry: { type: 'doubleHash', data: blobs.map(toHex) } };
}

describe('multi-leg intent → all leg amounts surfaced (edge case 8)', () => {
  it('surfaces EVERY leg amount in `values` (all-or-nothing feed)', () => {
    const { summary } = decodeSummary(multiLegBody(['4000', '4001', '4002']), 'acc://a.acme/data');
    expect(summary.values).toEqual(['4000', '4001', '4002']);
  });
  it('keeps `value` = leg[0] for display/back-compat', () => {
    const { summary } = decodeSummary(multiLegBody(['4001', '4000']), 'acc://a.acme/data');
    expect(summary.value).toBe('4001');
    expect(summary.values).toEqual(['4001', '4000']);
  });
  it('single leg → single-element values', () => {
    const { summary } = decodeSummary(multiLegBody(['4000']), 'acc://a.acme/data');
    expect(summary.values).toEqual(['4000']);
  });
  it('surfaces the leg count and notes extra legs in the action text', () => {
    const { summary } = decodeSummary(multiLegBody(['2', '4', '6']), 'acc://a.acme/data');
    expect((summary.raw as any)?.legCount).toBe(3);
    expect(summary.action).toContain('more leg');
  });
});

describe('non-CERTEN / malformed writeData fallback (edge case 6)', () => {
  it('writeData with no memo/blobs → no value (engine will fail-closed)', () => {
    const { summary } = decodeSummary({ type: 'writeData', entry: { type: 'doubleHash', data: [] } }, 'acc://a.acme/data');
    expect(summary.value).toBeUndefined();
    expect(summary.action).toContain('data write');
  });
  it('writeData with non-hex garbage blobs → falls back, no value', () => {
    const { summary } = decodeSummary({ type: 'writeData', entry: { data: ['zzzz', 'not-json'] } }, 'acc://a.acme/data');
    expect(summary.value).toBeUndefined();
  });
  it('legacy body-level crossChain shape still surfaces value', () => {
    const { summary } = decodeSummary({ type: 'writeData', crossChain: { value: '77', chain: 'eth', action: 'X' } }, 'acc://a.acme/data');
    expect(summary.value).toBe('77');
  });
});
