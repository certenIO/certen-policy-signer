// AGT scene-verify-9: the destination transaction of an approved operation is the ONE transaction in which the request's source account emitted
// LeafConsumed with data = the request's operationId, and whose receipt succeeded. FICTIONAL addresses; the event shape is world 2 A-01's
// (Base Sepolia 0x1d83890a...2d93, 2026-11-21).
import { describe, expect, it } from 'vitest';
import { ExecutionInputError, LEAF_CONSUMED_TOPIC, findExecution, type Rpc } from '../src/binding/evm-execution.js';

const ACCOUNT = '0x' + 'de'.repeat(20);
const OP = '0x' + '66'.repeat(32);
const TX = '0x' + '1d'.repeat(32);
const hex = (n: number) => '0x' + n.toString(16);
const log = (o: Partial<{ address: string; data: string; tx: string; block: number; topic: string; removed: boolean }> = {}) => ({
  address: o.address ?? ACCOUNT, topics: [o.topic ?? LEAF_CONSUMED_TOPIC, '0x' + 'aa'.repeat(32), '0x' + 'bb'.repeat(32)], data: o.data ?? OP,
  transactionHash: o.tx ?? TX, blockNumber: hex(o.block ?? 1050), ...(o.removed ? { removed: true } : {}),
});

function chain(opts: { head?: number; logs?: ReturnType<typeof log>[]; status?: string | null }) {
  const calls: Array<{ method: string; params: any[] }> = [];
  const rpc: Rpc = async (method, params) => {
    calls.push({ method, params: params as any[] });
    if (method === 'eth_blockNumber') return hex(opts.head ?? 2000);
    if (method === 'eth_getLogs') {
      const f = (params as any[])[0];
      const a = Number.parseInt(f.fromBlock, 16), b = Number.parseInt(f.toBlock, 16);
      return (opts.logs ?? []).filter((l) => { const n = Number.parseInt(l.blockNumber, 16); return n >= a && n <= b; });
    }
    if (method === 'eth_getTransactionReceipt') return opts.status === null ? null : { status: opts.status ?? '0x1' };
    // block n was made at 1_000_000 + 2n (a 2-second chain like Base Sepolia)
    if (method === 'eth_getBlockByNumber') return { timestamp: hex(1_000_000 + 2 * Number.parseInt((params as any[])[0], 16)) };
    throw new Error(`unexpected ${method}`);
  };
  return { rpc, calls };
}

describe('findExecution', () => {
  it('finds the transaction whose LeafConsumed data is the operation id, on the account, and checks its receipt', async () => {
    const c = chain({ logs: [log({ data: '0x' + '77'.repeat(32), tx: '0x' + '99'.repeat(32), block: 1040 }), log()] });
    const a = await findExecution(c.rpc, { account: ACCOUNT.toUpperCase().replace('0X', '0x'), operationId: OP, fromBlock: 1000 });
    expect(a).toEqual({ found: true, txHash: TX, blockNumber: 1050, scannedFrom: 1000, scannedTo: 2000 });
    const getLogs = c.calls.filter((x) => x.method === 'eth_getLogs');
    expect(getLogs[0]!.params[0]).toEqual({ address: ACCOUNT, topics: [LEAF_CONSUMED_TOPIC], fromBlock: hex(1000), toBlock: hex(1189) });
    for (const g of getLogs) expect(Number.parseInt(g.params[0].toBlock, 16) - Number.parseInt(g.params[0].fromBlock, 16)).toBeLessThan(200);
    expect(c.calls.at(-1)).toEqual({ method: 'eth_getTransactionReceipt', params: [TX] });
  });

  it('not found: says how far it looked (at most maxWindows windows) so the caller resumes there', async () => {
    const c = chain({ head: 5000, logs: [] });
    expect(await findExecution(c.rpc, { account: ACCOUNT, operationId: OP, fromBlock: 1000 }, { maxWindows: 3 })).toEqual({ found: false, scannedFrom: 1000, scannedTo: 1569, head: 5000 });
    // fromTime: the last block at or before it (block 1500 was made at 1_003_000; 1_003_001 is still block 1500)
    expect(await findExecution(chain({ head: 5000 }).rpc, { account: ACCOUNT, operationId: OP, fromTime: 1_003_001 }, { maxWindows: 1 })).toMatchObject({ found: false, scannedFrom: 1500 });
    expect(await findExecution(chain({ head: 5000 }).rpc, { account: ACCOUNT, operationId: OP, fromTime: 999 }, { maxWindows: 1 })).toMatchObject({ scannedFrom: 0 });
    expect(await findExecution(chain({ head: 5000 }).rpc, { account: ACCOUNT, operationId: OP, fromTime: 2_000_000 }, { maxWindows: 1 })).toMatchObject({ scannedFrom: 5000 });
  });

  it('a log on another address, with another topic, another operation or removed by a reorg is not the execution', async () => {
    const c = chain({ logs: [log({ address: '0x' + 'ee'.repeat(20) }), log({ topic: '0x' + 'cc'.repeat(32) }), log({ data: '0x' + '00'.repeat(32) }), log({ removed: true })] });
    expect(await findExecution(c.rpc, { account: ACCOUNT, operationId: OP, fromBlock: 1000 })).toMatchObject({ found: false });
  });

  it('two transactions consuming the same operation are refused by name, never picked from', async () => {
    const c = chain({ logs: [log({ block: 1010 }), log({ tx: '0x' + '2e'.repeat(32), block: 1500 })] });
    expect(await findExecution(c.rpc, { account: ACCOUNT, operationId: OP, fromBlock: 1000 })).toMatchObject({ found: false, refusal: 'execution_ambiguous' });
  });

  it('a failed receipt is not an execution; an absent receipt is unreadable (thrown, asked again)', async () => {
    expect(await findExecution(chain({ logs: [log()], status: '0x0' }).rpc, { account: ACCOUNT, operationId: OP, fromBlock: 1000 })).toMatchObject({ found: false, refusal: 'execution_receipt_failed' });
    await expect(findExecution(chain({ logs: [log()], status: null }).rpc, { account: ACCOUNT, operationId: OP, fromBlock: 1000 })).rejects.toThrow(/no receipt/);
  });

  it('malformed input is an input error before any call', async () => {
    const c = chain({});
    for (const q of [{ account: 'nope', operationId: OP, fromBlock: 1 }, { account: ACCOUNT, operationId: '0x12', fromBlock: 1 }, { account: ACCOUNT, operationId: OP, fromBlock: -1 }, { account: ACCOUNT, operationId: OP, fromBlock: 1.5 },
      // never a guessed start: exactly one of fromBlock and fromTime (AGT world 2, 2026-11-21: a lookback below the head stepped past an older execution)
      { account: ACCOUNT, operationId: OP }, { account: ACCOUNT, operationId: OP, fromBlock: 1, fromTime: 1 }, { account: ACCOUNT, operationId: OP, fromTime: 0 }]) {
      await expect(findExecution(c.rpc, q as any)).rejects.toBeInstanceOf(ExecutionInputError);
    }
    expect(c.calls).toEqual([]);
  });

  it('fromTime reads only recent blocks: a node that prunes old history (Base Sepolia public) still answers', async () => {
    const read: number[] = [];
    const rpc: Rpc = async (method, params) => {
      if (method === 'eth_blockNumber') return hex(60_000_000);
      if (method === 'eth_getBlockByNumber') {
        const n = Number.parseInt((params as any[])[0], 16);
        read.push(n);
        if (n < 48_000_000) throw new Error('pruned history unavailable');
        return { timestamp: hex(1_000_000 + 2 * n) };
      }
      if (method === 'eth_getLogs') return [];
      throw new Error(method);
    };
    // block 59_990_000 was made at 1_000_000 + 119_980_000
    const a = await findExecution(rpc, { account: ACCOUNT, operationId: OP, fromTime: 1_000_000 + 2 * 59_990_000 }, { maxWindows: 1 });
    expect(a).toMatchObject({ found: false, scannedFrom: 59_990_000 });
    expect(Math.min(...read)).toBeGreaterThanOrEqual(59_990_000 - 20_000); // the gallop stays near the answer
    expect(read.length).toBeLessThan(60);
  });

  it('the topic is keccak256 of LeafConsumed(bytes32,bytes32,bytes32) (the live event of 2026-11-21)', () => {
    expect(LEAF_CONSUMED_TOPIC).toBe('0xf65d46899882fe56bab13370dcd464db22e179625c161992c07d962286f7ea73');
  });
});
