/**
 * THE ACCEPTANCE TEST — the shipped artifact signs, live, end to end.
 *
 * Running the daemon from source under tsx proves the code works. It does not prove the thing you
 * actually deploy works. This brings up the real `deploy/docker-compose.yml` stack — the built image,
 * with the key supplied the way a pilot supplies it: a mounted Docker secret at /run/secrets/signer_seed,
 * read through the config's `seed_file` — and proves the container discovers, decides, and votes on its
 * own, with nothing handed to it.
 *
 *   provision a submitter and an authority-holding org; generate a config pointing at the org's page
 *   docker compose up --build         (the signer image + a policy engine)
 *   the submitter writes two transactions naming the org as a required authority
 *   assert: the container boots, the self-check passes, the poller finds both unaided,
 *           one is approved and executes, the other is denied and is rejected
 *
 *   npx tsx scripts/verify/deployed-container.ts
 */
import { execFileSync, execFile } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import { promisify } from 'node:util';
import { ENDPOINT, raw, sleep, fundLite, createOrg, createPrincipal, writeIntent, txState } from './_lib.js';

const pexec = promisify(execFile);
const COMPOSE = ['compose', '-f', 'deploy/docker-compose.yml'];
const CONFIG = 'deploy/config.generated.yaml';
const SEED_FILE = 'deploy/signer-seed.txt';   // mounted as a docker secret — the recommended key path
const BASE = 'http://127.0.0.1:8080';
const ADMIN_KEY = 'stage-d-admin-key';

/** The env the pilot's .env supplies. The KEY is not here — it is a mounted secret file. */
const denv = (_seedHex?: string) => ({
  ...process.env,
  ADMIN_API_KEY: ADMIN_KEY,
  SIGNER_CONFIG: './config.generated.yaml',
});

function docker(args: string[], seedHex: string, opts: { quiet?: boolean } = {}) {
  return execFileSync('docker', args, {
    env: denv(seedHex),
    encoding: 'utf8',
    stdio: opts.quiet ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'pipe', 'inherit'],
  });
}
async function walletLogs(seedHex: string): Promise<string> {
  const { stdout, stderr } = await pexec('docker', [...COMPOSE, 'logs', '--no-color', 'signer'], {
    env: denv(seedHex), maxBuffer: 10 * 1024 * 1024,
  });
  return stdout + stderr;
}
/** Read the durable store out of the container's volume. */
async function readState(seedHex: string): Promise<{ requests: any[]; receipts: any[] }> {
  const { stdout } = await pexec('docker', [...COMPOSE, 'exec', '-T', 'signer', 'cat', '/data/signer-state.json'], {
    env: denv(seedHex), maxBuffer: 10 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}
async function waitForBoot(seedHex: string, sinceMarker = ''): Promise<string> {
  for (let i = 0; i < 40; i++) {
    await sleep(1500);
    const logs = await walletLogs(seedHex).catch(() => '');
    const tail = sinceMarker ? logs.slice(logs.lastIndexOf(sinceMarker)) : logs;
    if (/fatal startup error/i.test(tail)) throw new Error(`signer refused to boot:\n${tail.slice(-800)}`);
    if (/http server listening/i.test(tail)) return logs;
  }
  throw new Error('signer never booted');
}

async function main() {
  const ts = Date.now();
  console.log('=== ACCEPTANCE: the shipped container signs, live on', ENDPOINT, '===\n');

  console.log('[1] provision funding lite + O (the signing org) + A (the initiator)');
  const f = await fundLite();
  const O = await createOrg(f, `acc://o-${ts}.acme`, 0x33, '400000000');
  const A = await createPrincipal(f, `acc://a-${ts}.acme`, 0x22);
  const seedHex = Buffer.from(O.key.seed).toString('hex');
  console.log(`  O page: ${O.page}\n  A data: ${A.dataAccount}`);

  console.log('\n[2] write the pilot config + the key as a mounted secret FILE (not an env var)');
  writeFileSync(SEED_FILE, seedHex, { mode: 0o600 });
  writeFileSync(CONFIG,
`signer: { org_id: "o-${ts}", network: "the test network", accumulate_endpoints: ["${ENDPOINT}"], signer_url: "${O.page}", attachment_model: "per_tx" }
signer: { provider: "local", local: { seed_file: "/run/secrets/signer_seed" } }
policy: { url: "http://policy:9099/decision", mode: "sync", auth: "none", timeout_ms: 10000 }
trigger: { webhook: { enabled: false, bind: "0.0.0.0:8080" }, poller: { enabled: true, interval_seconds: 15 } }
behavior: { submit_reject_vote: true }
store: { path: "/data/signer-state.json" }
admin: { api_key: "env:ADMIN_API_KEY" }
health: { bind: "0.0.0.0:8080" }
observability: { log_level: "info" }
`);
  console.log('  wrote', CONFIG);

  let pass = false;
  try {
    console.log('\n[3] docker compose up --build (signer image + the org policy engine)');
    docker([...COMPOSE, 'up', '-d', '--build'], seedHex);

    console.log('\n[4] wait for the container to boot + pass SR6 (fail-closed)');
    const boot = await waitForBoot(seedHex);
    const sr6 = /SR6 self-check OK/i.test(boot);
    const poller = /poller started/i.test(boot);
    const healthRes = await fetch(`${BASE}/healthz`).then(async (r) => ({ status: r.status, body: await r.json() as any })).catch(() => ({ status: 0, body: {} as any }));
    console.log(`  booted: true | /healthz: ${healthRes.status} | SR6 OK: ${sr6} | poller started: ${poller}`);

    console.log('\n[5] the admin gate (SR8 pause must not be open to anonymous callers)');
    const anon = await fetch(`${BASE}/v1/admin/pubkey`).then((r) => r.status).catch(() => 0);
    const authed = await fetch(`${BASE}/v1/admin/pubkey`, { headers: { 'x-api-key': ADMIN_KEY } }).then((r) => r.status).catch(() => 0);
    const wrongKey = await fetch(`${BASE}/v1/admin/pubkey`, { headers: { 'x-api-key': 'nope' } }).then((r) => r.status).catch(() => 0);
    console.log(`  no key -> ${anon} (expect 401/403) | wrong key -> ${wrongKey} (expect 401) | correct key -> ${authed} (expect 200)`);
    const adminOk = (anon === 401 || anon === 403) && wrongKey === 401 && authed === 200;

    console.log('\n[6] A writes an EVEN (4000) and an ODD (4001) intent, both tagging O — nothing tells the signer');
    const even = await writeIntent(A, { authorities: [O.book], amountWei: '4000' });
    const odd = await writeIntent(A, { authorities: [O.book], amountWei: '4001' });
    console.log(`  EVEN ${even.hash} (ok:${even.ok})\n  ODD  ${odd.hash} (ok:${odd.ok})`);

    console.log('\n[7] waiting for the containerized poller to discover, decide, and vote (up to ~200s)...');
    let evenState = 'pending', oddState = 'pending';
    for (let i = 0; i < 50; i++) {
      await sleep(4000);
      evenState = await txState(even.hash, A.dataPrincipal);
      oddState = await txState(odd.hash, A.dataPrincipal);
      if (evenState === 'delivered' && oddState === 'rejected') break;
    }
    const logs = await walletLogs(seedHex);
    const votes = (logs.match(/vote submitted/gi) ?? []).length;
    console.log(`  votes submitted: ${votes} | EVEN -> ${evenState} | ODD -> ${oddState}`);

    console.log('\n[8] durability: the receipts must survive a restart (they ARE the audit trail)');
    const state = await readState(seedHex);
    const receiptFor = (h: string) => state.receipts.find((r) => r.txHash === h);
    const evenReceipt = receiptFor(even.hash), oddReceipt = receiptFor(odd.hash);
    console.log(`  on-disk receipts: ${state.receipts.length} | EVEN decision=${evenReceipt?.decision} vote=${evenReceipt?.vote} | ODD decision=${oddReceipt?.decision} vote=${oddReceipt?.vote}`);

    docker([...COMPOSE, 'restart', 'signer'], seedHex, { quiet: true });
    const RESTART_MARK = 'starting certen-signing-signer';
    const afterBootLogs = await waitForBoot(seedHex, RESTART_MARK);
    const afterRestart = afterBootLogs.slice(afterBootLogs.lastIndexOf(RESTART_MARK));
    await sleep(20_000);                                   // let at least one poll cycle run post-restart
    const finalLogs = await walletLogs(seedHex);
    const post = finalLogs.slice(finalLogs.lastIndexOf(RESTART_MARK));
    const revotes = (post.match(/vote submitted/gi) ?? []).length;
    const stateAfter = await readState(seedHex);
    const historyKept = stateAfter.receipts.length === state.receipts.length && stateAfter.requests.length === state.requests.length;
    console.log(`  restarted; history kept: ${historyKept} (${stateAfter.receipts.length} receipts) | re-votes after restart: ${revotes} (expect 0)`);

    console.log('\n[9] results');
    const results: Array<[string, boolean]> = [
      ['container boots, /healthz 200, poller reported healthy', healthRes.status === 200 && healthRes.body?.poller?.healthy === true],
      ['SR6 self-check verified our key against the page', sr6],
      ['poller auto-discovery (nothing handed it the hashes)', poller],
      ['admin routes authenticated (anon + wrong key rejected)', adminOk],
      ['EVEN 4000 approved -> delivered', evenState === 'delivered'],
      ['ODD 4001 denied -> rejected', oddState === 'rejected'],
      ['exactly 2 votes submitted', votes === 2],
      ['receipts persisted to the volume with the right decisions', evenReceipt?.decision === 'approve' && oddReceipt?.decision === 'deny'],
      ['restart preserved the full history', historyKept],
      ['no double-voting after restart', revotes === 0],
    ];
    for (const [label, ok] of results) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
    pass = results.every(([, ok]) => ok);
    if (!pass) {
      console.log('\n--- signer container log (tail) ---');
      console.log(finalLogs.split('\n').slice(-40).join('\n'));
    }
  } finally {
    console.log('\n[10] teardown');
    try { docker([...COMPOSE, 'down', '-v'], seedHex, { quiet: true }); } catch {}
    rmSync(CONFIG, { force: true });
    rmSync(SEED_FILE, { force: true });
  }

  console.log('\n=== ACCEPTANCE:', pass
    ? 'PASS ✅ — the shipped container, reading the org key from a mounted secret file, autonomously approved the even intent and rejected the odd one on live the test network; its admin surface is authenticated, and its receipts survived a restart without re-voting.'
    : 'INCOMPLETE — see results above.', '===');
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL', e.message);
  try { execFileSync('docker', [...COMPOSE, 'down', '-v'], { stdio: 'ignore', env: denv() }); } catch {}
  rmSync(CONFIG, { force: true });
  rmSync(SEED_FILE, { force: true });
  process.exit(1);
});
