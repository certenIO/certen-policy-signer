/**
 * THE LOOP, CLOSED, ON A REAL NETWORK: a person approves in the console, and THEIR CERTIFICATE signs.
 *
 * Every part of this has been proven separately. This is the first time all of them run at once:
 *
 *   REAL  Kermit, and a key page founded on an employee's certificate and holding nothing else
 *   REAL  the certificate — in the Windows certificate store, non-exportable, reached through the agent
 *   REAL  the approval console: its decision service, its Postgres, its ReviewStore.recordVote
 *   REAL  the signer daemon: its poller, its HMAC policy client, its vote path
 *
 * The only thing simulated is the browser. A click on Approve is an HTTP POST that ends in
 * `ReviewStore.recordVote`, and that is the call the console side of this makes.
 *
 * ── WHAT IT PROVES THAT NOTHING ELSE DOES ─────────────────────────────────────────────────────────
 *
 * That a human decision recorded in the console becomes a signature made by THAT PERSON'S certificate,
 * on a public network, with no key material anywhere in this process or in the signer's configuration.
 *
 * ── AND WHAT IT DELIBERATELY LEAVES TO OTHER RUNS ─────────────────────────────────────────────────
 *
 * The two-approver case. Seating a second certificate has to be signed by a key already ON the page,
 * and this script signs through accumulate.js with in-process keys — it cannot reach a key in the
 * certificate store, which is the whole point of that key. Both halves of the two-approver case are
 * measured elsewhere: a threshold-2 page holding two certificates held a transaction pending on one
 * signature and executed it on the second (docs/PLAN-PKI-E2E.md, shape 2), and a decision naming two
 * approvers casts two votes (test/votes-per-approver.test.ts).
 *
 *   npx tsx scripts/verify/pki-console-loop.ts
 *
 * Windows only. Needs the agent built and a Postgres for the console:
 *   dotnet build agent/windows-cert-store/certen-cert-agent.csproj -c Release
 *   set CERTEN_CONSOLE_REPO / APPROVAL_CONSOLE_DATABASE_URL
 */
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import {
  fundLite, createPrincipal, writeIntent, spawnDaemon, kill, sleep, submit,
  waitForAccount, waitForCredits, query, ENDPOINT, S, core,
} from './_lib.js';

const HEALTH_PORT = 18098;
const CONSOLE_PORT = 9098;
const HMAC = 'pki-console-loop-secret';
const ALICE = 'alice@bank.example';
const BOB = 'bob@bank.example';
const AGENT = resolve('agent/windows-cert-store/bin/Release/net9.0/certen-cert-agent.exe');
const CONSOLE_REPO = process.env['CERTEN_CONSOLE_REPO']
  ? resolve(process.env['CERTEN_CONSOLE_REPO'])
  : resolve('..', 'certen-approval-console');

const line = (s = '') => console.log(s);

function makeCert(subject: string): string {
  const ps = [
    `$c = New-SelfSignedCertificate -Type Custom -Subject '${subject}'`,
    `-CertStoreLocation Cert:\\CurrentUser\\My -KeyAlgorithm ECDSA_nistP256 -KeyUsage DigitalSignature`,
    `-Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy NonExportable`,
    `-NotAfter (Get-Date).AddDays(1); $c.Thumbprint`,
  ].join(' ');
  return execFileSync('powershell', ['-NoProfile', '-Command', ps], { encoding: 'utf8' }).trim();
}
const removeCert = (t: string) => {
  try {
    execFileSync('powershell', ['-NoProfile', '-Command',
      `Remove-Item "Cert:\\CurrentUser\\My\\${t}" -Force -ErrorAction SilentlyContinue`]);
  } catch { /* expires in a day anyway */ }
};
const agent = (thumb: string, ...a: string[]) =>
  execFileSync(AGENT, ['--thumbprint', thumb, ...a], { encoding: 'utf8' }).trim();

async function main() {
  if (process.platform !== 'win32') { line('SKIP: Windows only.'); return; }
  if (!existsSync(AGENT)) { line('SKIP: build agent/windows-cert-store first.'); return; }
  if (!process.env['APPROVAL_CONSOLE_DATABASE_URL']) { line('SKIP: set APPROVAL_CONSOLE_DATABASE_URL.'); return; }
  if (!existsSync(join(CONSOLE_REPO, 'package.json'))) { line(`SKIP: no console repo at ${CONSOLE_REPO}`); return; }

  const ts = Date.now();
  line('\n════════════════════════════════════════════════════════════════════');
  line('  A person approves in the console. Their certificate signs on chain.');
  line('════════════════════════════════════════════════════════════════════\n');

  const thumbs = { alice: makeCert('CN=Alice Okonkwo'), bob: makeCert('CN=Bob Lindqvist') };
  const procs: ChildProcess[] = [];
  try {
    line('[1/7] Two certificates in the Windows certificate store…');
    const spkiA = Buffer.from(agent(thumbs.alice, '--public-key'), 'hex');
    const spkiB = Buffer.from(agent(thumbs.bob, '--public-key'), 'hex');
    const hashA = createHash('sha256').update(spkiA).digest('hex');
    const hashB = createHash('sha256').update(spkiB).digest('hex');
    line(`      Alice ${thumbs.alice}  entry ${hashA.slice(0, 20)}…`);
    line(`      Bob   ${thumbs.bob}  entry ${hashB.slice(0, 20)}…\n`);

    line('[2/7] Funding a throwaway account, and an ordinary submitter…');
    const f = await fundLite();
    const A = await createPrincipal(f, `acc://loopa${ts}.acme`, 0x73, '90000');

    // ── ONE approver on this page, deliberately.
    //
    // The page is FOUNDED on Alice's certificate and holds nothing else, which is the shape the
    // product needs. Seating a second certificate would have to be signed by a key ON that page —
    // Alice's — and this script cannot do that: it signs through accumulate.js with in-process keys,
    // and Alice's key is in the certificate store where nothing here can reach it. Reaching it needs
    // the agent, which is the signer's job and not this script's.
    //
    // The two-approver case is not skipped, it is proven elsewhere and separately: a threshold-2 page
    // holding two certificates held a transaction pending on one signature and executed it on the
    // second (docs/PLAN-PKI-E2E.md, shape 2), and a decision naming two approvers casts two votes
    // (test/votes-per-approver.test.ts). What has never been joined is the CONSOLE to a real
    // certificate on a real network, and that is what this run is for.
    line("[3/7] The team page: founded on Alice's certificate, and holding nothing else…");
    const adi = `acc://loopb${ts}.acme`;
    const book = `${adi}/book`, page = `${book}/1`;
    await submit(new core.Transaction({
      header: { principal: f.fLite },
      body: { type: 'createIdentity', url: adi, keyHash: hashA, keyBookUrl: book },
    }), S.Signer.forLite(f.funding.key), `adi ${adi}`);
    await waitForAccount(page, 'team page');
    await submit(new core.Transaction({
      header: { principal: f.fLta },
      body: { type: 'addCredits', recipient: page, amount: '120000', oracle: f.oracle },
    }), S.Signer.forLite(f.funding.key), 'credits');
    await waitForCredits(page, 'team page');

    const pageRec: any = await query(page);
    const onPage: string[] = (pageRec?.account?.keys ?? []).map((k: any) => String(k?.publicKeyHash ?? '').toLowerCase());
    line(`      ${page}`);
    line(`      keys on page: ${onPage.length}   only Alice's certificate: ${onPage.length === 1 && onPage[0] === hashA}\n`);

    line('[4/7] Starting the console: real decision service, real Postgres…');
    // node + tsx's own CLI rather than `npx`: on Windows, spawning a .cmd shim without a shell is
    // EINVAL, and turning the shell on to work around it would put this command through cmd quoting.
    const tsxCli = join(CONSOLE_REPO, 'node_modules', 'tsx', 'dist', 'cli.mjs');
    if (!existsSync(tsxCli)) { line(`SKIP: no tsx in ${CONSOLE_REPO} (npm install there first)`); return; }
    const consoleProc = spawn(
      process.execPath,
      [tsxCli, 'scripts/e2e-console.ts', String(CONSOLE_PORT), HMAC, page, ALICE],
      { cwd: CONSOLE_REPO, env: { ...process.env }, stdio: ['ignore', 'inherit', 'inherit'] },
    );
    procs.push(consoleProc);

    // Wait for it to actually listen rather than guessing. On a fresh database the console migrates
    // first, which takes longer than any fixed sleep worth writing — and a daemon that starts polling
    // into a closed port just fills the log with ECONNREFUSED and hides the real state.
    let consoleUp = false;
    for (let i = 0; i < 120 && !consoleUp; i++) {
      await sleep(1000);
      consoleUp = await fetch(`http://127.0.0.1:${CONSOLE_PORT}/policy`, { method: 'POST' })
        .then(() => true)
        .catch(() => false);
    }
    line(`      console listening: ${consoleUp ? 'YES' : 'NO'}`);
    if (!consoleUp) { line('      giving up: the console never came up'); return; }

    line('\n[5/7] The signer: one seat per approver, both windows-cert-store…');
    const dir = mkdtempSync(join(tmpdir(), 'certen-loop-'));
    const cfgPath = join(dir, 'loop.yaml');
    const a = AGENT.replace(/\\/g, '/');
    writeFileSync(cfgPath,
`wallet:
  org_id: "loop-${ts}"
  accumulate_endpoints: ["${ENDPOINT}"]
  attachment_model: "per_tx"
  scopes:
    - page: "${page}"
      key: { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.alice}", agent_path: "${a}" } }
      keys:
        "${ALICE}": { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.alice}", agent_path: "${a}" } }
policy: { url: "http://127.0.0.1:${CONSOLE_PORT}/policy", mode: "sync", auth: "hmac", hmac_secret: "${HMAC}", timeout_ms: 8000 }
trigger: { webhook: { enabled: false, bind: "127.0.0.1:${HEALTH_PORT}" }, poller: { enabled: true, interval_seconds: 6 } }
store: { path: "${join(dir, 'state.json').replace(/\\/g, '/')}" }
health: { bind: "127.0.0.1:${HEALTH_PORT}" }
observability: { log_level: "info" }
`);
    const log: string[] = [];
    const daemon = spawnDaemon(cfgPath, log);
    procs.push(daemon);
    let booted = false;
    for (let i = 0; i < 60 && !booted; i++) {
      await sleep(1000);
      booted = /SR6 self-check OK/i.test(log.join(''));
      if (/fatal startup error/i.test(log.join(''))) break;
    }
    line(`      signer booted: ${booted ? 'YES' : 'NO'}`);
    if (!booted) { line(log.join('').split('\n').slice(-8).join('\n')); return; }

    line('\n[6/7] A transaction that needs the team page…');
    const intent = await writeIntent(A, { authorities: [book], amountWei: '4200' });
    line(`      ${intent.txid}`);
    line('      waiting for the console to be asked, both people to approve, and the signer to sign…\n');

    // Query by the intent's OWN txid. Its principal is the submitter's data account, not the team
    // page — composing one from the team ADI reads a transaction that does not exist and reports
    // "unknown", which looks exactly like a transaction that never executed.
    let rec: any = null;
    for (let i = 0; i < 60; i++) {
      await sleep(5000);
      rec = await query(intent.txid).catch(() => null);
      if (rec?.status === 'delivered') break;
    }

    line('[7/7] What the chain recorded…');
    const sigs: string[] = [];
    const walk = (o: any): void => {
      if (!o || typeof o !== 'object') return;
      if (o.type === 'ecdsaSha256' && typeof o.publicKey === 'string') {
        sigs.push(createHash('sha256').update(Buffer.from(o.publicKey, 'hex')).digest('hex'));
      }
      for (const v of Object.values(o)) walk(v);
    };
    walk(rec);
    const uniq = [...new Set(sigs)];

    line(`      status                : ${rec?.status ?? 'unknown'}`);
    line(`      ecdsaSha256 signatures: ${uniq.length}`);
    for (const s of uniq) line(`        ${s}  ${s === hashA ? "<- Alice's certificate" : s === hashB ? "<- Bob's certificate" : '<- unknown'}`);

    const pass = rec?.status === 'delivered' && uniq.includes(hashA);
    line(`\n  ${pass ? 'PASS' : 'INCOMPLETE'}  ${intent.txid}\n`);
    process.exitCode = pass ? 0 : 1;
  } finally {
    for (const p of procs) { try { kill(p); } catch { try { p.kill(); } catch { /* gone */ } } }
    removeCert(thumbs.alice);
    removeCert(thumbs.bob);
    line('  cleanup   certificates removed, processes stopped');
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
