/**
 * One process, several key pages, each with its own key — and every vote signed by the RIGHT key.
 *
 * A single signer can watch multiple key pages (`wallet.scopes`), each with its own key and its own
 * custody. The risk in that design is mis-routing: signing page B's transaction with page A's key.
 *
 * This proves it does not happen, and the proof is the network's, not ours. Accumulate rejects a
 * signature produced by a key that is not on the page being signed for. So if the keyring mis-routed,
 * that transaction would be rejected on chain rather than executed. Both executing means each was
 * signed by the correct key.
 *
 *   npx tsx scripts/verify/multi-page.ts
 */
import http from 'node:http';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fundLite, createOrg, createPrincipal, writeIntent, txState, spawnDaemon, kill, sleep, ENDPOINT } from './_lib.js';

const ENGINE_PORT = 9097;
const HEALTH_PORT = 18097;
const line = (s = '') => console.log(s);

/** Provision with a retry that lengthens the name by one char — rides out the accumulate.js 64-byte-body
 * quirk (see bootstrap.ts) and genuine testnet hiccups. */
async function withRetry<T>(label: string, fn: (i: number) => Promise<T>): Promise<T> {
  let last: unknown;
  for (let i = 1; i <= 6; i++) {
    try { return await fn(i); }
    catch (e) { last = e; console.log(`      (${label}: attempt ${i} retry)`); await sleep(Math.min(15000, 3000 * i)); }
  }
  throw last;
}

async function main() {
  const ts = Date.now();
  line('\n════════════════════════════════════════════════════════════════════');
  line('  MULTI-SCOPE LIVE PROOF — one signer, TWO key pages, TWO keys, on the test network');
  line('════════════════════════════════════════════════════════════════════\n');

  line('[1/6] Funding a temporary test account…');
  const f = await fundLite();

  line('[2/6] Creating SCOPE A  (its own ADI, key page, and key)…');
  const A = await withRetry('scope A', (i) => createOrg(f, `acc://msa${ts}${'x'.repeat(i - 1)}.acme`, 0x61, '90000'));
  line('[3/6] Creating SCOPE B  (a DIFFERENT ADI, key page, and key)…');
  const B = await withRetry('scope B', (i) => createOrg(f, `acc://msb${ts}${'x'.repeat(i - 1)}.acme`, 0x62, '90000'));
  line('[4/6] Creating the AGENT (submits the intents)…');
  const agent = await withRetry('agent', (i) => createPrincipal(f, `acc://mag${ts}${'x'.repeat(i - 1)}.acme`, 0x63, '90000'));

  const khA = createHash('sha256').update(A.key.pub).digest('hex');
  const khB = createHash('sha256').update(B.key.pub).digest('hex');
  line('');
  line(`   SCOPE A  page ${A.page}`);
  line(`            key  ${khA.slice(0, 24)}…`);
  line(`   SCOPE B  page ${B.page}`);
  line(`            key  ${khB.slice(0, 24)}…`);
  line(`   the two keys are different: ${khA !== khB}\n`);

  // The multi-scope config: ONE signer, TWO scopes, each with its own page + key.
  const dir = mkdtempSync(join(tmpdir(), 'certen-multiscope-'));
  const store = join(dir, 'state.json').replace(/\\/g, '/');
  const cfgPath = join(dir, 'multi-scope.yaml');
  writeFileSync(cfgPath,
`signer:
  org_id: "multi-scope-demo-${ts}"
  network: "the test network"
  accumulate_endpoints: ["${ENDPOINT}"]
  attachment_model: "per_tx"
  scopes:
    - page: "${A.page}"
      book: "${A.book}"
      key: { provider: "local", local: { seed_hex: "${Buffer.from(A.key.seed).toString('hex')}" } }
    - page: "${B.page}"
      book: "${B.book}"
      key: { provider: "local", local: { seed_hex: "${Buffer.from(B.key.seed).toString('hex')}" } }
policy: { url: "http://127.0.0.1:${ENGINE_PORT}/decision", mode: "sync", auth: "none", timeout_ms: 4000 }
trigger: { webhook: { enabled: false, bind: "127.0.0.1:${HEALTH_PORT}" }, poller: { enabled: true, interval_seconds: 8 } }
behavior: { submit_reject_vote: true }
store: { path: "${store}" }
health: { bind: "127.0.0.1:${HEALTH_PORT}" }
observability: { log_level: "info" }
`);

  // your policy engine stand-in: approve everything (this proof is about key routing, not the decision).
  const engine = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
      const r = JSON.parse(b || '{}');
      console.log(`    [policy] APPROVE tx=${String(r.txHash).slice(0, 12)} "${r.actionSummary}"`);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'approve', reason: 'multi-scope live proof' }));
    });
  });
  await new Promise<void>((r) => engine.listen(ENGINE_PORT, '127.0.0.1', () => r()));

  line('[5/6] Starting the MULTI-SCOPE signer — expect SR6 OK for BOTH pages, then pollers:2…\n');
  const log: string[] = [];
  const daemon = spawnDaemon(cfgPath, log);
  let up = false;
  for (let i = 0; i < 45; i++) {
    await sleep(1000);
    const j = log.join('');
    if (/fatal startup error/i.test(j)) break;
    if (/poller started/i.test(j) && /http server listening/i.test(j)) { up = true; break; }
  }
  if (!up) {
    console.error('\n❌ signer did not start:\n' + log.join('').split('\n').filter((l) => /fatal|error|refus|SR6/i.test(l)).slice(0, 5).join('\n'));
    kill(daemon); engine.close(); process.exit(1);
  }
  const twoPollers = /"pollers":2/.test(log.join(''));
  line(`\n   ✓ signer up. two pollers running: ${twoPollers}\n`);

  line('[6/6] Agent submits TWO intents — one naming page A as authority, one naming page B…\n');
  const iA = await writeIntent(agent, { authorities: [A.book], amountWei: '7001' });
  const iB = await writeIntent(agent, { authorities: [B.book], amountWei: '7002' });
  line(`   intent A ${iA.hash.slice(0, 16)}…  needs page A's signature`);
  line(`   intent B ${iB.hash.slice(0, 16)}…  needs page B's signature`);
  line('\n   Watching each poller discover ITS tx and sign it with ITS key…\n');

  const settle = async (h: string) => {
    for (let i = 0; i < 45; i++) { await sleep(4000); const s = await txState(h, agent.dataPrincipal); if (s === 'delivered' || s === 'rejected') return s; }
    return 'pending';
  };
  const [sA, sB] = await Promise.all([settle(iA.hash), settle(iB.hash)]);

  const votedA = log.join('').split('\n').some((l) => /vote submitted/i.test(l) && l.includes(iA.hash));
  const votedB = log.join('').split('\n').some((l) => /vote submitted/i.test(l) && l.includes(iB.hash));

  line('\n════════════════════════════════════════════════════════════════════');
  line('  RESULT');
  line('════════════════════════════════════════════════════════════════════');
  line(`  SCOPE A  ${A.page}`);
  line(`     intent A  →  ${sA === 'delivered' ? '✅ DELIVERED — signed by key A on page A' : `❌ ${sA}`}`);
  line(`  SCOPE B  ${B.page}`);
  line(`     intent B  →  ${sB === 'delivered' ? '✅ DELIVERED — signed by key B on page B' : `❌ ${sB}`}`);
  line('');
  line(`  one signer process cast BOTH votes:  page-A tx voted=${votedA}   page-B tx voted=${votedB}`);
  line('  Accumulate rejects a signature from a key not on the page, so both DELIVERED proves the keyring');
  line('  routed each intent to the CORRECT key for its page.\n');

  kill(daemon); engine.close();
  await sleep(500);
  process.exit(sA === 'delivered' && sB === 'delivered' && votedA && votedB ? 0 : 1);
}
main().catch((e) => { console.error('\n❌ error:', (e as Error).message); process.exit(1); });
