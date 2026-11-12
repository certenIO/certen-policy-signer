/**
 * DAX-4-A1 at the real channel: a captured, HMAC-authenticated reply is replayed inside the old 300-second window (src/policy/
 * policy.ts:194-198 accepts any reply whose timestamp is that recent). The signer's HttpPolicyClient ACCEPTS the replayed bytes as
 * authentic; the binding refuses to sign. The control shows the base behaviour on a seat without binding: the replayed approval
 * signs a second time (the gap DECISION.md section 1 names).
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { DecisionJournal } from '../src/binding/journal.js';
import { NonceStore } from '../src/binding/nonces.js';
import { buildPresentedRequest } from '../src/binding/request.js';
import { hashRequest } from '../src/core/hashes.js';
import { Orchestrator } from '../src/orchestrator.js';
import { HttpPolicyClient } from '../src/policy/policy.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { MemoryStore } from '../src/store/store.js';
import { APPROVER, H, PRINCIPAL, POLICY, SEAT, intentBody, record } from './support/binding-fixtures.js';

const silent = pino({ level: 'silent' });
const SIGNER = 'acc://o.acme/book/1';
const TX = 'ab'.repeat(32);
const SECRET = 'fic-hmac-secret-not-a-real-secret';
const BODY = intentBody();
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

let engine: http.Server;
let url = '';
let captured: { body: string; header: string } | undefined;
let served = 0;
beforeAll(async () => {
  // The engine signs its reply ONCE (a real Console would sign each reply with a fresh timestamp); every later request is answered
  // with the SAME captured bytes and the SAME signature header, which is what a replaying party can do.
  engine = http.createServer((req, res) => {
    req.on('data', () => undefined);
    req.on('end', () => {
      if (captured === undefined) {
        const built = buildPresentedRequest({ txHash: TX, rawTransaction: { body: BODY }, summary: { action: 'x' } });
        if (!built.ok) throw new Error(built.detail);
        const nowS = Math.floor(Date.now() / 1000);
        const body = JSON.stringify({ decision: 'approve', reason: 'FICTIONAL approval', record: record({ requestHash: hashRequest(built.value.request), issuedAt: nowS - 5, nonce: H('nonce-http') }) });
        const ts = String(Date.now() - 120_000); // captured two minutes ago: inside the 300-second bound
        captured = { body, header: `t=${ts},v1=${createHmac('sha256', SECRET).update(`${ts}.${body}`).digest('hex')}` };
      }
      served++;
      res.writeHead(200, { 'content-type': 'application/json', 'x-signer-signature': captured.header });
      res.end(captured.body);
    });
  });
  await new Promise<void>((r) => engine.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${(engine.address() as { port: number }).port}/decision`;
});
afterAll(() => engine.close());

function service(dir: string, bound: boolean) {
  const journal = new DecisionJournal({ path: join(dir, 'decision-journal.jsonl'), logId: 'fic-signer' });
  const nowS = () => Math.floor(Date.now() / 1000);
  const acc = new MockAccumulateClient();
  acc.addPending(TX, { body: BODY, principal: `${PRINCIPAL}/tokens` });
  const orch = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))), store: new MemoryStore(), resolver: new Resolver(acc), logger: silent,
    policy: new HttpPolicyClient({ url, hmacSecret: SECRET, timeoutMs: 5000 }),
    seats: new Map([[SIGNER.toLowerCase(), { seat: SEAT, ...(bound ? { binding: { seat: SEAT, authorizedApprovers: [APPROVER], maxWindowSeconds: 7200, policyHash: POLICY, requireGrant: false } } : {}) }]]),
    binding: { nonces: new NonceStore(journal, nowS), nowSeconds: nowS },
  });
  return { acc, handle: () => orch.handle({ txHash: TX, signerUrl: SIGNER }) };
}

describe('a replayed reply inside the old 300-second window (DAX-4-A1)', () => {
  it('CONTROL, a seat without binding: the replayed reply is authentic to the channel and signs again (the gap)', async () => {
    captured = undefined;
    const dir = mkdtempSync(join(tmpdir(), 'dax4s-h-')); dirs.push(dir);
    const first = service(dir, false);
    const second = service(dir, false); // the same captured reply, a new process
    expect((await first.handle()).status).toBe('signed');
    expect((await second.handle()).status).toBe('signed');
    expect(first.acc.submissions.length + second.acc.submissions.length).toBe(2);
  });

  it('a bound seat: the same captured bytes are accepted by the channel and REFUSED by the binding; one signature in total', async () => {
    captured = undefined;
    served = 0;
    const dir = mkdtempSync(join(tmpdir(), 'dax4s-h-')); dirs.push(dir);
    const first = service(dir, true);
    expect((await first.handle()).status).toBe('signed');
    const second = service(dir, true); // a restart: nothing in memory, the journal on disk
    const row = await second.handle();
    expect(served).toBe(2); // the replay reached the signer and passed the HMAC and the 300-second bound
    expect(row.status).toBe('awaiting_policy');
    expect(row.lastError).toBe('binding: decision_replayed');
    expect(second.acc.submissions).toHaveLength(0);
    expect(first.acc.submissions).toHaveLength(1);
  });
});
