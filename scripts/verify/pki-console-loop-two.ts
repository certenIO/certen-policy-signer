/**
 * TWO people approve in the console, and TWO CERTIFICATES sign — the whole thing, at once.
 *
 * `pki-console-loop.ts` closed the loop for one approver. It could not do two, because seating a
 * second certificate has to be signed by a key already ON the page, and that script signs through
 * accumulate.js with in-process keys — which is precisely what a key in the certificate store is not.
 *
 * This one reaches it. `applyKeyPageOp` takes a `KeySigner`, and `WindowsCertStoreSigner` is one, so
 * ALICE'S CERTIFICATE seats Bob's and raises the threshold. No Ed25519 key ever acts on the team page.
 *
 *   REAL  Kermit, threshold 2 of 2, both keys certificates in the Windows certificate store
 *   REAL  the approval console: decision service, Postgres, enrolments, ReviewStore.recordVote
 *   REAL  the signer daemon: poller, HMAC policy client, ONE VOTE PER APPROVER
 *
 * ── WHAT ONLY THIS RUN CAN SHOW ───────────────────────────────────────────────────────────────────
 *
 * That a single console decision naming two approvers becomes two signatures from two different
 * people's keys, and that the transaction executes when the page's own threshold is met and not
 * before. The halves were each measured; this is them joined.
 *
 *   npx tsx scripts/verify/pki-console-loop-two.ts
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
import pino from 'pino';
import { applyKeyPageOp } from '../../src/ops/keypage.js';
import { WindowsCertStoreSigner } from '../../src/signer/windows-cert-store.js';
import {
  fundLite, createPrincipal, writeIntent, spawnDaemon, kill, sleep, submit,
  waitForAccount, waitForCredits, query, raw, ENDPOINT, S, core,
} from './_lib.js';

const HEALTH_PORT = 18099;
const CONSOLE_PORT = 9099;
const HMAC = 'pki-console-loop-two-secret';
const ALICE = 'alice@bank.example';
const BOB = 'bob@bank.example';
const AGENT = resolve('agent/windows-cert-store/bin/Release/net9.0/certen-cert-agent.exe');
const CONSOLE_REPO = process.env['CERTEN_CONSOLE_REPO']
  ? resolve(process.env['CERTEN_CONSOLE_REPO'])
  : resolve('..', 'certen-approval-console');

const line = (s = '') => console.log(s);
const logger = pino({ level: 'warn' });

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

async function main() {
  if (process.platform !== 'win32') { line('SKIP: Windows only.'); return; }
  if (!existsSync(AGENT)) { line('SKIP: build agent/windows-cert-store first.'); return; }
  if (!process.env['APPROVAL_CONSOLE_DATABASE_URL']) { line('SKIP: set APPROVAL_CONSOLE_DATABASE_URL.'); return; }
  const tsxCli = join(CONSOLE_REPO, 'node_modules', 'tsx', 'dist', 'cli.mjs');
  if (!existsSync(tsxCli)) { line(`SKIP: no tsx in ${CONSOLE_REPO}`); return; }

  const ts = Date.now();
  line('\n════════════════════════════════════════════════════════════════════');
  line('  Two approvals in the console. Two certificates on chain.');
  line('════════════════════════════════════════════════════════════════════\n');

  const thumbs = { alice: makeCert('CN=Alice Okonkwo'), bob: makeCert('CN=Bob Lindqvist') };
  const procs: ChildProcess[] = [];
  try {
    // The same signer objects the daemon will build, used here to prepare the page. Nothing in this
    // process ever holds either private key.
    const aliceKey = new WindowsCertStoreSigner({ thumbprint: thumbs.alice, agentPath: AGENT });
    const bobKey = new WindowsCertStoreSigner({ thumbprint: thumbs.bob, agentPath: AGENT });
    const hashA = createHash('sha256').update(await aliceKey.publicKey()).digest('hex');
    const hashB = createHash('sha256').update(await bobKey.publicKey()).digest('hex');

    line('[1/8] Two certificates in the Windows certificate store…');
    line(`      Alice ${thumbs.alice}  entry ${hashA.slice(0, 20)}…`);
    line(`      Bob   ${thumbs.bob}  entry ${hashB.slice(0, 20)}…\n`);

    line('[2/8] Funding a throwaway account, and an ordinary submitter…');
    const f = await fundLite();
    const A = await createPrincipal(f, `acc://twoa${ts}.acme`, 0x75, '90000');

    line("[3/8] The team page, FOUNDED on Alice's certificate…");
    const adi = `acc://twob${ts}.acme`;
    const book = `${adi}/book`, page = `${book}/1`;
    await submit(new core.Transaction({
      header: { principal: f.fLite },
      body: { type: 'createIdentity', url: adi, keyHash: hashA, keyBookUrl: book },
    }), S.Signer.forLite(f.funding.key), `adi ${adi}`);
    await waitForAccount(page, 'team page');
    await submit(new core.Transaction({
      header: { principal: f.fLta },
      body: { type: 'addCredits', recipient: page, amount: '150000', oracle: f.oracle },
    }), S.Signer.forLite(f.funding.key), 'credits');
    await waitForCredits(page, 'team page');
    line(`      ${page}  version 1, one key: hers\n`);

    // ── The part the one-approver run could not do.
    line("[4/8] ALICE'S CERTIFICATE seats Bob's, and raises the threshold to 2…");
    const asAlice = { accumulate: raw as never, signer: aliceKey, logger, page };
    const seat = await applyKeyPageOp(asAlice, { op: 'add-key', keyHash: hashB }, 90_000);
    line(`      seat Bob   ${seat.ok ? 'OK' : 'FAILED: ' + seat.error}`);
    if (!seat.ok) return;
    await sleep(6000);

    const thresh = await applyKeyPageOp(asAlice, { op: 'set-threshold', threshold: 2 }, 90_000);
    line(`      threshold  ${thresh.ok ? 'OK' : 'FAILED: ' + thresh.error}`);
    if (!thresh.ok) return;
    await sleep(7000);

    const pageRec: { account?: { keys?: { publicKeyHash?: string }[]; acceptThreshold?: number } } = await query(page);
    const keys = (pageRec?.account?.keys ?? []).map((k) => String(k?.publicKeyHash ?? '').toLowerCase());
    const onlyCerts = keys.length === 2 && keys.includes(hashA) && keys.includes(hashB);
    line(`      page: ${keys.length} keys, threshold ${pageRec?.account?.acceptThreshold}, only the two certificates: ${onlyCerts}\n`);

    line('[5/8] The console: both approvers enrolled, two approvals required…');
    const consoleProc = spawn(process.execPath,
      [tsxCli, 'scripts/e2e-console.ts', String(CONSOLE_PORT), HMAC, page, ALICE, BOB],
      { cwd: CONSOLE_REPO, env: { ...process.env }, stdio: ['ignore', 'inherit', 'inherit'] });
    procs.push(consoleProc);
    let up = false;
    for (let i = 0; i < 120 && !up; i++) {
      await sleep(1000);
      up = await fetch(`http://127.0.0.1:${CONSOLE_PORT}/policy`, { method: 'POST' }).then(() => true).catch(() => false);
    }
    line(`      console listening: ${up ? 'YES' : 'NO'}`);
    if (!up) return;

    line('\n[6/8] The signer: a seat per approver, both windows-cert-store…');
    const dir = mkdtempSync(join(tmpdir(), 'certen-two-'));
    const cfgPath = join(dir, 'two.yaml');
    const a = AGENT.replace(/\\/g, '/');
    writeFileSync(cfgPath,
`wallet:
  org_id: "two-${ts}"
  accumulate_endpoints: ["${ENDPOINT}"]
  attachment_model: "per_tx"
  scopes:
    - page: "${page}"
      key: { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.alice}", agent_path: "${a}" } }
      keys:
        "${ALICE}": { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.alice}", agent_path: "${a}" } }
        "${BOB}":   { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.bob}", agent_path: "${a}" } }
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
    if (!booted) { line(log.join('').split('\n').slice(-6).join('\n')); return; }

    line('\n[7/8] A transaction that needs the team page…');
    const intent = await writeIntent(A, { authorities: [book], amountWei: '8400' });
    line(`      ${intent.txid}`);
    line('      waiting for both approvals and both signatures…\n');

    let rec: { status?: string } | null = null;
    for (let i = 0; i < 72; i++) {
      await sleep(5000);
      rec = await query(intent.txid).catch(() => null);
      if (rec?.status === 'delivered') break;
    }

    line('[8/8] What the chain recorded…');
    const sigs: string[] = [];
    const walk = (o: unknown): void => {
      if (!o || typeof o !== 'object') return;
      const r = o as Record<string, unknown>;
      if (r['type'] === 'ecdsaSha256' && typeof r['publicKey'] === 'string') {
        sigs.push(createHash('sha256').update(Buffer.from(r['publicKey'], 'hex')).digest('hex'));
      }
      for (const v of Object.values(r)) walk(v);
    };
    walk(rec);
    const uniq = [...new Set(sigs)];

    line(`      status                : ${rec?.status ?? 'unknown'}`);
    line(`      ecdsaSha256 signatures: ${uniq.length}`);
    for (const s of uniq) line(`        ${s}  ${s === hashA ? "<- Alice" : s === hashB ? '<- Bob' : '<- UNKNOWN'}`);

    const pass = onlyCerts && rec?.status === 'delivered' && uniq.includes(hashA) && uniq.includes(hashB);
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
