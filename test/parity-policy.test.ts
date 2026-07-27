import { describe, it, expect } from 'vitest';
// @ts-expect-error — plain .mjs helper, no type declarations
import { decideByParity, parseAmount } from '../scripts/parity-policy-engine.mjs';

describe('parity policy engine', () => {
  it('approves even amounts (from structured value)', () => {
    const d = decideByParity({ value: '4000', actionSummary: 'Transfer 4000 to acc://x' });
    expect(d.decision).toBe('approve');
    expect(d.evidence.parity).toBe('even');
  });

  it('denies odd amounts (from structured value)', () => {
    const d = decideByParity({ value: '4001', actionSummary: 'Transfer 4001 to acc://x' });
    expect(d.decision).toBe('deny');
    expect(d.evidence.parity).toBe('odd');
  });

  it('falls back to parsing the actionSummary when value is absent', () => {
    expect(decideByParity({ actionSummary: 'Transfer 5,000 to acc://x' }).decision).toBe('approve');
    expect(decideByParity({ actionSummary: 'Transfer 4,999 to acc://x' }).decision).toBe('deny');
  });

  it('decides parity on the integer part, ignoring separators and fractions', () => {
    expect(parseAmount({ value: '1,000,000' })).toBe(1_000_000n);
    expect(decideByParity({ value: '12.50' }).evidence.parity).toBe('even');
    expect(decideByParity({ value: '13.99' }).evidence.parity).toBe('odd');
  });

  it('handles amounts beyond Number.MAX_SAFE_INTEGER with BigInt', () => {
    expect(decideByParity({ value: '90071992547409910' }).decision).toBe('approve'); // even
    expect(decideByParity({ value: '90071992547409911' }).decision).toBe('deny');    // odd
  });

  it('fails closed (deny) when no amount can be parsed', () => {
    const d = decideByParity({ actionSummary: 'writeData on acc://x' });
    expect(d.decision).toBe('deny');
    expect(d.evidence.parity).toBe('unknown');
  });

  describe('multi-leg all-or-nothing gate (req.values)', () => {
    it('approves only when EVERY leg is even', () => {
      const d = decideByParity({ values: ['4000', '4002', '6'] });
      expect(d.decision).toBe('approve');
      expect(d.evidence.gate).toBe('all-or-nothing');
    });
    it('denies the whole intent if ANY leg is odd (names the offending leg)', () => {
      const d = decideByParity({ values: ['4000', '4001', '4002'] }); // leg 1 odd
      expect(d.decision).toBe('deny');
      expect(d.evidence.deny_leg).toBe(1);
    });
    it('denies if any leg amount is unparseable (fail-closed)', () => {
      const d = decideByParity({ values: ['4000', 'not-a-number'] });
      expect(d.decision).toBe('deny');
      expect(d.evidence.deny_leg).toBe(1);
    });
    it('a single-leg values array behaves like the scalar gate', () => {
      expect(decideByParity({ values: ['4000'] }).decision).toBe('approve');
      expect(decideByParity({ values: ['4001'] }).decision).toBe('deny');
    });
  });
});
