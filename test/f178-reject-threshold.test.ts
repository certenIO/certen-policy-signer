// DAX-F178: a governance proposal may set a page's REJECT threshold (Accumulate UpdateKeyPage setRejectThreshold). The large payer's page gets a machine
// initiation key and an accept threshold of 3 (the machine plus two officers); without an explicit reject threshold of 2, refusals would default to the accept
// threshold, and the officers alone (the machine never refuses) could no longer refuse a payment. All three operations travel in ONE updateKeyPage, so no
// moment exists in which fewer than two officers suffice or the officers cannot refuse.
/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it, vi } from 'vitest';
import { applyKeyPageOp } from '../src/ops/keypage.js';
import { LocalSigner } from '../src/signer/signer.js';
import { logger } from '../src/logger.js';
import { toKeyPageOp } from '../src/relay-clients.js';
import { buildProposalDisplay, proposalOperations } from '../src/display.js';
import { operationsFromKeyPageOps, validateKeyPageChange, type SimPage } from '../src/ops/keypage-guard.js';

const MACHINE = 'ab'.repeat(32);
const D1 = 'acc://elias-brandt-tcl98.acme/book';
const D2 = 'acc://ines-varga-tcl98.acme/book';
const D3 = 'acc://tobias-nilsen-tcl98.acme/book';
const LARGE_P1 = 'acc://harbor-mfg-large-tcl98.acme/book/1';
const page = (entries: Array<string | { delegate: string }>, accept: number, reject = 0): SimPage => ({
  entries: entries.map((e) => (typeof e === 'string' ? { keyHash: e, delegate: null } : { keyHash: null, delegate: e.delegate })),
  acceptThreshold: accept, rejectThreshold: reject, responseThreshold: 0,
});

describe('DAX-F178: set-reject-threshold on the signer\'s own page (the admin path)', () => {
  const silent = logger.child({ level: 'silent' });
  const acc = (keys: string[]) => {
    const submitted: any[] = [];
    return {
      submitted,
      query: vi.fn(async () => ({ account: { version: 1, threshold: 1, keys: keys.map((h) => ({ publicKeyHash: h })) } })),
      getSignerInfo: vi.fn(async () => ({ version: 1, lastUsedOn: 0, creditBalance: 100 })),
      submit: vi.fn(async (env: any) => { submitted.push(env); return { ok: true }; }),
    } as any;
  };
  const deps = (a: any) => ({ accumulate: a, signer: new LocalSigner(new Uint8Array(32).fill(7)), logger: silent, page: 'acc://org.acme/book/1' });

  it('a reject threshold above the entries is refused before anything is signed', async () => {
    const a = acc(['aa'.repeat(32), 'bb'.repeat(32)]);
    const r = await applyKeyPageOp(deps(a), { op: 'set-reject-threshold', threshold: 3 }, 500);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/reject threshold 3 exceeds the 2 entr/);
    expect(a.submitted).toHaveLength(0);
  });

  it('a valid one is submitted as one updateKeyPage setRejectThreshold', async () => {
    const a = acc(['aa'.repeat(32), 'bb'.repeat(32)]);
    await applyKeyPageOp(deps(a), { op: 'set-reject-threshold', threshold: 1 }, 50);
    expect(JSON.stringify(a.submitted)).toMatch(/setRejectThreshold/);
  });
});

describe('DAX-F178: set-reject-threshold is a governance operation', () => {
  it('the relay accepts set-reject-threshold with a positive integer and refuses anything else by name', () => {
    expect(toKeyPageOp({ type: 'set-reject-threshold', threshold: 2 })).toEqual({ op: 'set-reject-threshold', threshold: 2 });
    for (const bad of [0, -1, 1.5, '2', undefined]) expect(toKeyPageOp({ type: 'set-reject-threshold', threshold: bad })).toMatch(/set-reject-threshold: threshold must be a positive integer/);
  });

  it('it builds the typed setRejectThreshold operation, and the proposal display shows it', () => {
    const ops = [{ op: 'add-key' as const, keyHash: MACHINE }, { op: 'set-threshold' as const, threshold: 3 }, { op: 'set-reject-threshold' as const, threshold: 2 }];
    expect(proposalOperations(ops)).toEqual([
      { type: 'add', entry: { keyHash: MACHINE } }, { type: 'setThreshold', threshold: 3 }, { type: 'setRejectThreshold', threshold: 2 },
    ]);
    const shown = buildProposalDisplay(LARGE_P1, ops).map(([k, v]) => `${k}=${v}`);
    expect(shown).toContain('Operation=setRejectThreshold');
    expect(shown.filter((s) => s === 'Threshold=2')).toHaveLength(1);
  });

  it('the guard runs it in order: the large payer composite lands at accept 3 / reject 2; a reject threshold above the entries is refused', () => {
    const before = page([{ delegate: D1 }, { delegate: D2 }, { delegate: D3 }], 2);
    const composite = operationsFromKeyPageOps([{ op: 'add-key', keyHash: MACHINE }, { op: 'set-threshold', threshold: 3 }, { op: 'set-reject-threshold', threshold: 2 }]);
    expect(composite).toEqual([{ type: 'add', keyHash: MACHINE }, { type: 'setThreshold', threshold: 3 }, { type: 'setRejectThreshold', threshold: 2 }]);
    expect(validateKeyPageChange(before, composite)).toMatchObject({ ok: true, after: { acceptThreshold: 3, rejectThreshold: 2, entryCount: 4 } });
    expect(validateKeyPageChange(before, operationsFromKeyPageOps([{ op: 'set-reject-threshold', threshold: 4 }]))).toMatchObject({ ok: false, refusal: { reason: 'reject_threshold_exceeds_entries' } });
  });
});
