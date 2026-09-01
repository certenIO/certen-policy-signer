/**
 * WHO a transaction is about, proved end to end on the live test network.
 *
 * One signer, one policy engine holding a per-user roster, and four intents that differ ONLY in what
 * blob 0 says about the subject. If the field works, the four outcomes are different; if it does not,
 * they are all the same, and no unit test in either repo would notice — the producer would keep writing
 * a valid blob, the decoder would keep returning a valid summary, and the engine would simply never be
 * told whose re-authentication it is deciding.
 *
 *   A  enrolled subject      acc://alice.acme     → engine approves  → DELIVERED
 *   B  unknown subject       acc://mallory.acme   → engine denies    → REJECTED
 *   C  NO subject            (key absent)         → engine denies    → REJECTED   ← fail-closed, LOUDLY
 *   D  malformed subject     a bare string        → decoder drops it → REJECTED, exactly like C
 *
 * Then C is run again against a SUBJECT-AGNOSTIC engine, which must APPROVE it and let it execute. That
 * second half is the one that matters most: it is the proof that every deployment which existed before
 * this field still works unchanged.
 *
 * ── What C is really testing ──────────────────────────────────────────────────────────────────────
 *
 * An engine that requires a subject and does not get one has two ways to refuse. `deny` casts a reject
 * vote and the transaction reaches a TERMINAL state. A throw, a timeout or a 4xx WITHHOLD: nothing is
 * signed — which is safe — but the transaction stays alive on chain until it expires and nobody is told
 * why, which from outside is indistinguishable from the engine being down. A transaction still sitting
 * pending at the end of this run is therefore a FAILED gate, not a slow network.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/subject-routing.ts
 *
 * Kermit only. Throwaway identities, funded from the faucet; there is nothing to roll back.
 */
import http from 'node:http';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fundLite, createOrg, createPrincipal, writeIntent, txState, spawnDaemon, writeConfig, kill, sleep } from './_lib.js';

const ENGINE_PORT = 9094;
const HEALTH_PORT = 18094;
const line = (s = '') => console.log(s);

const ALICE = 'acc://alice.acme';
const MALLORY = 'acc://mallory.acme';

/** Who the engine has enrolled. In production this is a biometric template store. */
const ENROLLED = new Map([[ALICE, { customerId: 'cust-99213' }]]);

/** Every decision request the engine was asked, verbatim — this is the evidence the run produces. */
interface Seen { txHash: string; body: any }

/** Provision with a retry that lengthens the name by one char — rides out testnet hiccups. */
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
  line('  SUBJECT ROUTING — live on the test network');
  line('════════════════════════════════════════════════════════════════════\n');

  line('[1/5] Funding a temporary test account…');
  const f = await fundLite();

  line('[2/5] Creating the ORG (its book is the authority the signer holds)…');
  const O = await withRetry('org', (i) => createOrg(f, `acc://sro${ts}${'x'.repeat(i - 1)}.acme`, 0x71, '120000'));
  line('[3/5] Creating the AGENT (writes the intents)…');
  const agent = await withRetry('agent', (i) => createPrincipal(f, `acc://sra${ts}${'x'.repeat(i - 1)}.acme`, 0x72, '120000'));
  line(`\n   org book   ${O.book}`);
  line(`   agent data ${agent.dataAccount}\n`);

  // ── The policy engine. `requireSubject` is flipped for the second half of case C. ───────────────
  const seen: Seen[] = [];
  let requireSubject = true;

  const engine = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      const r = JSON.parse(b || '{}');
      seen.push({ txHash: String(r.txHash), body: r });

      let decision: { decision: string; reason: string };
      if (!requireSubject) {
        // A pre-change engine: it has never heard of `subject` and answers on the amount alone.
        decision = { decision: 'approve', reason: 'subject-agnostic policy' };
      } else if (!r.subject?.adi) {
        // EXPLICIT deny, not a throw. A throw would withhold and leave this transaction alive on chain
        // until it expired, with nobody told why.
        decision = { decision: 'deny', reason: 'no subject on the request' };
      } else if (!ENROLLED.has(r.subject.adi)) {
        decision = { decision: 'deny', reason: `no enrolled biometric for ${r.subject.adi}` };
      } else {
        decision = { decision: 'approve', reason: `re-authenticated ${r.subject.adi}` };
      }

      console.log(`    [policy] ${decision.decision.toUpperCase().padEnd(7)} tx=${String(r.txHash).slice(0, 12)} `
        + `subject=${r.subject?.adi ?? '(none)'}  "${decision.reason}"`);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(decision));
    });
  });
  await new Promise<void>((r) => engine.listen(ENGINE_PORT, '127.0.0.1', () => r()));

  // ── The signer. ────────────────────────────────────────────────────────────────────────────────
  const dir = mkdtempSync(join(tmpdir(), 'certen-subject-'));
  const store = join(dir, 'state.json').replace(/\\/g, '/');
  const cfgPath = join(dir, 'subject.yaml');
  writeConfig(cfgPath, {
    orgId: `subject-routing-${ts}`,
    oPage: O.page,
    oSeedHex: Buffer.from(O.key.seed).toString('hex'),
    enginePort: ENGINE_PORT,
    healthPort: HEALTH_PORT,
    interval: 8,
    storePath: store,
  });

  line('[4/5] Starting the signer…');
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
    console.error('\n❌ signer did not start:\n' + log.join('').split('\n').filter((l) => /fatal|error|refus/i.test(l)).slice(0, 5).join('\n'));
    kill(daemon); engine.close(); process.exit(1);
  }
  line('   ✓ signer up\n');

  // ── The four intents. Only blob 0's subject differs. ───────────────────────────────────────────
  line('[5/5] Writing four intents that differ only in what blob 0 says about the subject…\n');

  const A = await writeIntent(agent, { authorities: [O.book], amountWei: '8100', subject: { adi: ALICE, keyBook: `${ALICE}/book` } });
  const B = await writeIntent(agent, { authorities: [O.book], amountWei: '8102', subject: { adi: MALLORY, keyBook: `${MALLORY}/book` } });
  const C = await writeIntent(agent, { authorities: [O.book], amountWei: '8104' });   // no subject at all
  // D: a bare string where an object belongs. Written by hand, because `writeIntent` will not build a
  // malformed claim — which is itself the point: only a third party could produce this shape.
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const D = await writeIntent(agent, {
    authorities: [O.book],
    data: [
      { kind: 'CERTEN_INTENT', version: '2.0', intent_id: 'i-8106', description: 'Transfer 8106 wei', subject: ALICE },
      { protocol: 'CERTEN', version: '2.0', legs: [{ legId: 'l1', chain: 'ethereum-sepolia', asset: { symbol: 'ETH', decimals: 18 }, to: '0xBe0043', amountWei: '8106', amountEth: '0.0' }] },
      { organizationAdi: 'acc://o.acme', authorization: { signature_threshold: 1 } },
      { nonce: 'n-8106', expires_at: 1999999999 },
    ].map(toHex),
  });

  line(`   A  ${A.hash.slice(0, 16)}…  subject = ${ALICE}     (enrolled)`);
  line(`   B  ${B.hash.slice(0, 16)}…  subject = ${MALLORY}   (not enrolled)`);
  line(`   C  ${C.hash.slice(0, 16)}…  NO subject key`);
  line(`   D  ${D.hash.slice(0, 16)}…  subject = a bare string  (malformed)`);
  line('\n   Watching the signer discover each one and ask the engine…\n');

  const settle = async (h: string) => {
    for (let i = 0; i < 45; i++) {
      await sleep(4000);
      const s = await txState(h, agent.dataPrincipal);
      if (s === 'delivered' || s === 'rejected') return s;
    }
    return 'pending';
  };
  const [sA, sB, sC, sD] = await Promise.all([settle(A.hash), settle(B.hash), settle(C.hash), settle(D.hash)]);

  // ── Case C, second half: the SAME shape of intent, against an engine that never heard of subjects. ──
  line('\n   Now the backward-compatibility half: a subject-LESS intent against a SUBJECT-AGNOSTIC engine.');
  line('   This is the proof that every deployment that existed before this field still works.\n');
  requireSubject = false;
  const C2 = await writeIntent(agent, { authorities: [O.book], amountWei: '8108' });
  line(`   C2 ${C2.hash.slice(0, 16)}…  NO subject key, engine ignores the field entirely`);
  const sC2 = await settle(C2.hash);

  // ── What the engine actually received. ─────────────────────────────────────────────────────────
  const reqFor = (h: string) => seen.find((s) => s.txHash === h)?.body;
  const subjOf = (h: string) => {
    const r = reqFor(h);
    if (!r) return '(never asked)';
    return 'subject' in r ? JSON.stringify(r.subject) : '(key absent)';
  };

  line('\n════════════════════════════════════════════════════════════════════');
  line('  WHAT THE ENGINE WAS ASKED');
  line('════════════════════════════════════════════════════════════════════');
  for (const [name, h] of [['A', A.hash], ['B', B.hash], ['C', C.hash], ['D', D.hash], ['C2', C2.hash]] as const) {
    line(`  ${name.padEnd(3)} ${h}`);
    line(`      subject on the request : ${subjOf(h)}`);
  }

  line('\n════════════════════════════════════════════════════════════════════');
  line('  ONE FULL REQUEST BODY (case A), verbatim');
  line('════════════════════════════════════════════════════════════════════');
  line(JSON.stringify(reqFor(A.hash), null, 2));

  // ── The gate. ──────────────────────────────────────────────────────────────────────────────────
  const checks: Array<[string, boolean, string]> = [
    ['A  enrolled subject → DELIVERED', sA === 'delivered', sA],
    ['A  the engine saw alice', reqFor(A.hash)?.subject?.adi === ALICE, String(reqFor(A.hash)?.subject?.adi)],
    ['A  the key book hint carried', reqFor(A.hash)?.subject?.keyBook === `${ALICE}/book`, String(reqFor(A.hash)?.subject?.keyBook)],
    ['B  unknown subject → REJECTED', sB === 'rejected', sB],
    ['B  the engine saw mallory', reqFor(B.hash)?.subject?.adi === MALLORY, String(reqFor(B.hash)?.subject?.adi)],
    ['C  no subject → REJECTED, not left pending', sC === 'rejected', sC],
    ['C  the request carried NO subject KEY', !!reqFor(C.hash) && !('subject' in reqFor(C.hash)), subjOf(C.hash)],
    ['D  malformed subject → REJECTED', sD === 'rejected', sD],
    ['D  the malformed claim was DROPPED, not half-read', !!reqFor(D.hash) && !('subject' in reqFor(D.hash)), subjOf(D.hash)],
    ['C2 subject-less intent + agnostic engine → DELIVERED', sC2 === 'delivered', sC2],
    ['no transaction was left pending', [sA, sB, sC, sD, sC2].every((s) => s !== 'pending'), [sA, sB, sC, sD, sC2].join(',')],
  ];

  line('\n════════════════════════════════════════════════════════════════════');
  line('  RESULT');
  line('════════════════════════════════════════════════════════════════════');
  let ok = true;
  for (const [name, pass, got] of checks) {
    line(`  ${pass ? '✅' : '❌'} ${name.padEnd(56)} ${pass ? '' : `got: ${got}`}`);
    ok &&= pass;
  }
  line('');
  line('  A transaction still PENDING at the end of this run is a FAILED gate, not a slow network:');
  line('  it is exactly the stall an explicit `deny` exists to prevent.');
  line('');

  kill(daemon);
  engine.close();
  await sleep(500);
  process.exit(ok ? 0 : 1);
}
main().catch((e) => { console.error('\n❌ error:', (e as Error).message); process.exit(1); });
