/**
 * Receipts are append-only records (DAX-4S, DE-48; src/store/store.ts:76 overwrote them): a second receipt for one unit of work
 * is a second record, nothing replaces or removes one, the store stamps a contiguous `seq`, and a file with a gap, a duplicate or
 * a mix refuses to start (a dropped receipt is visible, not silently a shorter trail).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileStore, MemoryStore } from '../src/store/store.js';
import type { Receipt } from '../src/types.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-s-')); dirs.push(d); return d; };
const A = 'aa'.repeat(32);
const B = 'bb'.repeat(32);

describe('receipts append', () => {
  it('keeps both receipts of one key (the first is not overwritten); getReceipt is the latest', async () => {
    const s = new MemoryStore();
    await s.saveReceipt({ txHash: A, decision: 'approve', reason: 'first' });
    await s.saveReceipt({ txHash: A, decision: 'deny', reason: 'second' });
    await s.saveReceipt({ txHash: B, decision: 'approve', reason: 'other' });
    expect((await s.getReceipt(A))?.reason).toBe('second');
    expect((await s.getReceipts(A)).map((r) => [r.reason, r.seq])).toEqual([['first', 1], ['second', 2]]);
    expect((await s.getReceipts(B)).map((r) => r.seq)).toEqual([3]);
    expect((await s.getReceipts(A))[0]!.recordedAt).toBeGreaterThan(0);
  });

  it('survives a restart with every receipt, and the sequence goes on', async () => {
    const f = join(tmp(), 'state.json');
    const a = new FileStore(f);
    await a.saveReceipt({ txHash: A, reason: 'one' });
    await a.saveReceipt({ txHash: A, reason: 'two' });
    const b = new FileStore(f);
    expect((await b.getReceipts(A)).map((r) => r.reason)).toEqual(['one', 'two']);
    await b.saveReceipt({ txHash: B, reason: 'three' });
    expect((await b.getReceipts(B))[0]!.seq).toBe(3);
  });

  it('stays readable by the previous release (one receipt per key, the last wins) and reads a file that predates seq', async () => {
    const f = join(tmp(), 'state.json');
    const a = new FileStore(f);
    await a.saveReceipt({ txHash: A, reason: 'one' });
    await a.saveReceipt({ txHash: A, reason: 'two' });
    const onDisk = JSON.parse(readFileSync(f, 'utf8')) as { receipts: Receipt[] };
    const previous = new Map<string, Receipt>();
    for (const r of onDisk.receipts) previous.set(r.workKey ?? r.txHash, r); // what the previous release's load did
    expect(previous.get(A)?.reason).toBe('two');
    // a legacy file: no seq anywhere
    const legacy = join(tmp(), 'legacy.json');
    writeFileSync(legacy, JSON.stringify({ requests: [], receipts: [{ txHash: A, reason: 'old-a' }, { txHash: B, reason: 'old-b' }], policyRequests: [] }));
    const s = new FileStore(legacy);
    expect((await s.getReceipt(A))?.seq).toBe(1);
    expect((await s.getReceipt(B))?.seq).toBe(2);
  });

  it('refuses to start on a gap, a duplicate or a mix (a dropped receipt is visible)', () => {
    const write = (receipts: unknown[]): string => { const f = join(tmp(), 's.json'); writeFileSync(f, JSON.stringify({ requests: [], receipts, policyRequests: [] })); return f; };
    expect(() => new FileStore(write([{ txHash: A, seq: 1 }, { txHash: B, seq: 3 }]))).toThrow(/not contiguous/);
    expect(() => new FileStore(write([{ txHash: A, seq: 1 }, { txHash: B, seq: 1 }]))).toThrow(/not contiguous/);
    expect(() => new FileStore(write([{ txHash: A, seq: 2 }]))).toThrow(/not contiguous/);
    expect(() => new FileStore(write([{ txHash: A, seq: 1 }, { txHash: B }]))).toThrow(/with and without/);
  });

  it('an append that cannot be made durable is not an append (rolled back, the retry takes the same seq)', async () => {
    const d = tmp();
    const s = new FileStore(join(d, 'sub', 'state.json'));
    await s.saveReceipt({ txHash: A, reason: 'one' });
    rmSync(join(d, 'sub'), { recursive: true, force: true });
    await expect(s.saveReceipt({ txHash: A, reason: 'lost' })).rejects.toThrow();
    expect((await s.getReceipts(A)).map((r) => r.reason)).toEqual(['one']);
    expect((await s.getReceipt(A))?.reason).toBe('one');
  });
});
