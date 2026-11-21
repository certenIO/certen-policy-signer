/**
 * AGT scene-verify-9 (2026-11-21), EVIDENCE-AGT.md section 1: an agent-payment record's `outcome.destinationTx` is the destination-chain
 * transaction that executed the approved operation. The Console never learned it (it wrote ''), so every agent record named no destination.
 *
 * WHAT BINDS IT, EXACTLY. A CertenAccount executes an operation only against an anchored leaf and, in that same transaction, emits
 *   LeafConsumed(bytes32 indexed anchorId, bytes32 indexed leaf, bytes32 operationID)
 * from the account itself, where operationID is the validator's operation id (CertenIntent.OperationID) - the very `operationId` member of the
 * request the seat decided (its request hash binds it; DECISION.md section 2). Verified live: world 2 A-01, Base Sepolia
 * 0x1d83890a...2d93, the payer account 0xde7a...023e emits LeafConsumed with data = the request's operationId 0x66561a77...2e1c.
 * So the destination transaction is the ONE transaction holding a LeafConsumed log, emitted by the request's source account, whose data is the
 * request's operationId - and whose receipt succeeded. Nothing is inferred from amounts or recipients.
 *
 * HOW IT IS FOUND. eth_getLogs on the account and the event topic, in windows of at most `windowBlocks` (Base Sepolia's public endpoints refuse
 * more than 200 blocks per call), from `fromBlock` forward, at most `maxWindows` windows per call; the answer says how far it looked so the
 * caller resumes there. WHERE IT STARTS is never guessed: the caller gives `fromBlock` (where it stopped) or `fromTime` (the approval's relay time:
 * an operation cannot execute before it was approved), and `fromTime` is turned into the last block at or before it by binary search over block
 * timestamps. (A fixed lookback below the head - the first version - started AFTER an execution older than the lookback and stepped past it
 * for good: found live on world 2, 2026-11-21.) Two matching logs are a named refusal (an operation executes once), never a pick. A receipt that is absent or failed
 * is not an execution.
 */

export const LEAF_CONSUMED_TOPIC = '0xf65d46899882fe56bab13370dcd464db22e179625c161992c07d962286f7ea73'; // keccak256("LeafConsumed(bytes32,bytes32,bytes32)")

export type Rpc = (method: string, params: unknown[]) => Promise<unknown>;

export interface ExecutionQuery {
  account: string;
  operationId: string;
  /** first block to look at (where the previous ask stopped) */
  fromBlock?: number;
  /** or: a Unix time at or before the execution (the approval's relay time); the search starts at the last block at or before it */
  fromTime?: number;
}

export type ExecutionAnswer =
  | { found: true; txHash: string; blockNumber: number; scannedFrom: number; scannedTo: number }
  | { found: false; scannedFrom: number; scannedTo: number; head: number }
  | { found: false; refusal: 'execution_ambiguous' | 'execution_receipt_failed'; detail: string };

const ADDR = /^0x[0-9a-fA-F]{40}$/;
const H32 = /^0x[0-9a-fA-F]{64}$/;

export class ExecutionInputError extends Error {}

const hexNum = (v: unknown, what: string): number => {
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]+$/.test(v)) throw new Error(`${what} is not a hex quantity`);
  const n = Number.parseInt(v, 16);
  if (!Number.isSafeInteger(n)) throw new Error(`${what} is out of range`);
  return n;
};

export async function findExecution(
  rpc: Rpc,
  q: ExecutionQuery,
  o: { windowBlocks?: number; maxWindows?: number } = {},
): Promise<ExecutionAnswer> {
  if (typeof q.account !== 'string' || !ADDR.test(q.account)) throw new ExecutionInputError('account must be a 0x 20-byte address');
  if (typeof q.operationId !== 'string' || !H32.test(q.operationId)) throw new ExecutionInputError('operationId must be 0x plus 64 hex');
  if (q.fromBlock !== undefined && (!Number.isSafeInteger(q.fromBlock) || q.fromBlock < 0)) throw new ExecutionInputError('fromBlock must be a non-negative integer');
  if (q.fromTime !== undefined && (!Number.isSafeInteger(q.fromTime) || q.fromTime <= 0)) throw new ExecutionInputError('fromTime must be a positive Unix time in seconds');
  if ((q.fromBlock === undefined) === (q.fromTime === undefined)) throw new ExecutionInputError('give exactly one of fromBlock and fromTime');
  const windowBlocks = o.windowBlocks ?? 190;
  const maxWindows = o.maxWindows ?? 10;
  const account = q.account.toLowerCase();
  const op = q.operationId.toLowerCase();

  const head = hexNum(await rpc('eth_blockNumber', []), 'eth_blockNumber');
  const from = q.fromBlock ?? (await blockAtOrBefore(rpc, q.fromTime!, head));
  const matches: Array<{ tx: string; block: number }> = [];
  let to = from - 1;
  for (let i = 0; i < maxWindows && to < head; i++) {
    const a = to + 1;
    const b = Math.min(head, a + windowBlocks - 1);
    const logs = await rpc('eth_getLogs', [{ address: account, topics: [LEAF_CONSUMED_TOPIC], fromBlock: '0x' + a.toString(16), toBlock: '0x' + b.toString(16) }]);
    if (!Array.isArray(logs)) throw new Error('eth_getLogs returned no list');
    for (const l of logs as Array<Record<string, unknown>>) {
      if (String(l['address'] ?? '').toLowerCase() !== account) continue; // a node that ignores the filter is not believed
      const topics = l['topics'];
      if (!Array.isArray(topics) || String(topics[0] ?? '').toLowerCase() !== LEAF_CONSUMED_TOPIC) continue;
      if (String(l['data'] ?? '').toLowerCase() !== op) continue;
      if (l['removed'] === true) continue;
      matches.push({ tx: String(l['transactionHash']).toLowerCase(), block: hexNum(l['blockNumber'], 'log blockNumber') });
    }
    to = b;
  }
  const distinct = [...new Map(matches.map((m) => [m.tx, m])).values()];
  if (distinct.length > 1) return { found: false, refusal: 'execution_ambiguous', detail: `${distinct.length} transactions consumed operation ${op}: ${distinct.map((m) => m.tx).join(', ')}` };
  if (distinct.length === 0) return { found: false, scannedFrom: from, scannedTo: to, head };
  const hit = distinct[0]!;
  if (!H32.test(hit.tx)) throw new Error('log transactionHash is malformed');
  const receipt = (await rpc('eth_getTransactionReceipt', [hit.tx])) as Record<string, unknown> | null;
  if (!receipt) throw new Error(`no receipt for ${hit.tx}`); // the node knows the log but not the receipt: unreadable, ask again
  if (receipt['status'] !== '0x1') return { found: false, refusal: 'execution_receipt_failed', detail: `${hit.tx} status ${String(receipt['status'])}` };
  return { found: true, txHash: hit.tx, blockNumber: hit.block, scannedFrom: from, scannedTo: to };
}

const blockTime = async (rpc: Rpc, n: number): Promise<number> => {
  const b = (await rpc('eth_getBlockByNumber', ['0x' + n.toString(16), false])) as Record<string, unknown> | null;
  if (!b) throw new Error(`block ${n} is unreadable`);
  return hexNum(b['timestamp'], `block ${n} timestamp`);
};

/**
 * the last block whose timestamp is at or before `t`: gallop back from the head (doubling the step) to a block at or before `t`, then binary search
 * between it and the last block found after `t`. Only blocks between that point and the head are read (about 2 log2 of the distance), so a node that
 * prunes old history (Base Sepolia public: nothing below 48,000,000 on 2026-11-21) still answers; a block it cannot serve is an error, never a guess.
 */
export async function blockAtOrBefore(rpc: Rpc, t: number, head: number): Promise<number> {
  if ((await blockTime(rpc, head)) <= t) return head;
  let hi = head; // time(hi) > t
  let lo = -1;
  for (let step = 1; ; step *= 2) {
    const cand = Math.max(0, head - step);
    if ((await blockTime(rpc, cand)) <= t) { lo = cand; break; }
    hi = cand;
    if (cand === 0) return 0; // every block is after t
  }
  while (hi - lo > 1) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if ((await blockTime(rpc, mid)) <= t) lo = mid;
    else hi = mid;
  }
  return lo;
}
