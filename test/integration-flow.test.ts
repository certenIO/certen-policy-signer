import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { HttpPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator, OrchestratorOptions } from '../src/orchestrator.js';
// @ts-expect-error — plain .mjs engine, no type declarations
import { decideByParity } from '../scripts/parity-policy-engine.mjs';

/**
 * End-to-end pipeline WITHOUT a live chain: real Resolver (CERTEN 4-blob decode) → real HttpPolicyClient
 * over HTTP → the real even-odd engine logic → real Orchestrator + signer → MockAccumulate.
 * Deterministic, runs in CI, exercises everything the live daemon does except the network.
 */
const silent = pino({ level: 'silent' });
const SIGNER = 'acc://o.acme/book/1';

/** Build a CERTEN_INTENT writeData body with the given wei amount(s) (or omit legs entirely). */
function certenBody(...amountsWei: (string | undefined)[]) {
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const amts = amountsWei.filter((a): a is string => a != null);
  const legs = amts.map((amountWei, i) => ({ legId: `l${i}`, chain: 'ethereum-sepolia', asset: { symbol: 'ETH' }, to: `0x${i}`, amountWei }));
  const blobs = [
    { kind: 'CERTEN_INTENT', intent_id: 'i1', description: 'Transfer test' },
    { protocol: 'CERTEN', legs },
    { authorization: { signature_threshold: 1 } },
    { nonce: 'n1' },
  ];
  return { type: 'writeData', entry: { type: 'doubleHash', data: blobs.map(toHex) } };
}

let engine: http.Server;
let engineUrl = '';
beforeAll(async () => {
  engine = http.createServer((req, res) => {
    const ch: Buffer[] = []; req.on('data', (c) => ch.push(c));
    req.on('end', () => { let b: any = {}; try { b = JSON.parse(Buffer.concat(ch).toString()); } catch {}
      const d = decideByParity(b); res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d)); });
  });
  await new Promise<void>((r) => engine.listen(0, '127.0.0.1', r));
  engineUrl = `http://127.0.0.1:${(engine.address() as any).port}/decision`;
});
afterAll(() => engine.close());

function pipeline(txHash: string, body: any, options?: OrchestratorOptions) {
  const acc = new MockAccumulateClient();
  acc.addPending(txHash, { body, principal: 'acc://a.acme/data' });
  const orch = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))),
    policy: new HttpPolicyClient({ url: engineUrl, timeoutMs: 3000 }),
    store: new MemoryStore(), resolver: new Resolver(acc), logger: silent, options,
  });
  return { acc, orch };
}
const H = (n: number) => n.toString(16).padStart(2, '0').repeat(32);

describe('full pipeline: CERTEN intent → HTTP even-odd engine → vote', () => {
  it('EVEN amountWei → engine approve → Accept vote submitted', async () => {
    const { acc, orch } = pipeline(H(1), certenBody('4000'), { submitRejectVote: true });
    const r = await orch.handle({ txHash: H(1), signerUrl: SIGNER });
    expect(r.status).toBe('signed');
    expect(acc.submissions).toHaveLength(1);
    expect((acc.submissions[0] as any).signatures[0].vote).toBeUndefined(); // accept omits vote
  });

  it('ODD amountWei → engine deny → Reject vote submitted', async () => {
    const { acc, orch } = pipeline(H(2), certenBody('4001'), { submitRejectVote: true });
    const r = await orch.handle({ txHash: H(2), signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect((acc.submissions[0] as any).signatures[0].vote).toBe('reject');
  });

  it('intent with NO parseable amount → engine fail-closed deny → no accept', async () => {
    const { acc, orch } = pipeline(H(3), certenBody(undefined)); // no submitRejectVote → withhold
    const r = await orch.handle({ txHash: H(3), signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect(acc.submissions).toHaveLength(0);
  });

  it('the decoded amountWei is what the engine actually gated on', async () => {
    // huge even wei beyond Number.MAX_SAFE_INTEGER must still approve (BigInt parity end-to-end)
    const { orch } = pipeline(H(4), certenBody('90071992547409910'), { submitRejectVote: true });
    expect((await orch.handle({ txHash: H(4), signerUrl: SIGNER })).status).toBe('signed');
    const { orch: orch2 } = pipeline(H(5), certenBody('90071992547409911'), { submitRejectVote: true });
    expect((await orch2.handle({ txHash: H(5), signerUrl: SIGNER })).status).toBe('rejected');
  });

  it('multi-leg ALL even → approve (all-or-nothing)', async () => {
    const { orch } = pipeline(H(7), certenBody('4000', '4002', '6'), { submitRejectVote: true });
    expect((await orch.handle({ txHash: H(7), signerUrl: SIGNER })).status).toBe('signed');
  });

  it('multi-leg with ONE odd leg → whole intent rejected (all-or-nothing)', async () => {
    const { acc, orch } = pipeline(H(8), certenBody('4000', '4001'), { submitRejectVote: true }); // leg1 odd
    const r = await orch.handle({ txHash: H(8), signerUrl: SIGNER });
    expect(r.status).toBe('rejected');
    expect((acc.submissions[0] as any).signatures[0].vote).toBe('reject');
  });

  it('SR8 pause → withholds signature even when the engine approves', async () => {
    let paused = true;
    const { acc, orch } = pipeline(H(6), certenBody('4000'), { isPaused: () => paused });
    const r = await orch.handle({ txHash: H(6), signerUrl: SIGNER });
    expect(r.status).toBe('awaiting_policy');
    expect(r.lastError).toBe('paused');
    expect(acc.submissions).toHaveLength(0);
    // resume → now it signs
    paused = false;
    const r2 = await orch.handle({ txHash: H(6), signerUrl: SIGNER });
    expect(r2.status).toBe('signed');
    expect(acc.submissions).toHaveLength(1);
  });
});
