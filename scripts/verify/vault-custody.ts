/**
 * The production key posture casts a live vote — and the signer never holds a private key.
 *
 * deployed-container.ts proves the pilot posture, where the key sits in the signer's memory. This proves
 * the posture actually recommended for production: the Ed25519 key is generated inside Vault and never
 * leaves it. The signer sends Vault a 32-byte preimage and receives a signature. That is the entirety of
 * its access to the key.
 *
 * The chain of custody is verified on chain, not asserted:
 *
 *   Vault generates the key       ->  only its PUBLIC key is ever read
 *   the Accumulate key page is created carrying sha256(that public key)
 *   the signer boots and compares its Vault public key against the page  ->  "SR6 self-check OK"
 *   a pending transaction is discovered, the policy engine decides, and VAULT signs the vote
 *   the network accepts it
 *
 * If the key on the page were not Vault's, the self-check would refuse to boot and the votes would be
 * rejected. Neither happening is the proof.
 *
 *   npx tsx scripts/verify/vault-custody.ts        # requires a reachable Vault; see docs/OPERATIONS.md
 */
import { execFileSync, execFile } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import { promisify } from 'node:util';
import { VaultTransitSigner } from '../../src/signer/vault-transit.js';
import {
  ENDPOINT, raw, core, S, sha, sleep, submit, fundLite, createPrincipal, writeIntent, txState,
  waitForAccount, waitForCredits,
} from './_lib.js';

const pexec = promisify(execFile);
const COMPOSE = ['compose', '-f', 'deploy/docker-compose.vault.yml'];
const CONFIG = 'deploy/config.generated.yaml';
const BASE = 'http://127.0.0.1:8080';
const VAULT_ADDR = 'http://127.0.0.1:8200';
const VAULT_TOKEN = 'root';
const KEY_NAME = 'org-accum';
const ADMIN_KEY = 'stage-e-admin-key';

const env = { ...process.env, VAULT_TOKEN, ADMIN_API_KEY: ADMIN_KEY, SIGNER_CONFIG: './config.generated.yaml' };
const docker = (args: string[], quiet = false) =>
  execFileSync('docker', args, { env, encoding: 'utf8', stdio: quiet ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'pipe', 'inherit'] });

async function walletLogs(): Promise<string> {
  const { stdout, stderr } = await pexec('docker', [...COMPOSE, 'logs', '--no-color', 'signer'], { env, maxBuffer: 10 * 1024 * 1024 });
  return stdout + stderr;
}

async function main() {
  const ts = Date.now();
  const adiO = `acc://ov-${ts}.acme`;
  const oBook = `${adiO}/book`, oPage = `${oBook}/1`;
  let pass = false;

  console.log('=== VAULT CUSTODY: Vault holds the key; the signer never sees it. Live on', ENDPOINT, '===\n');

  try {
    console.log('[1] start Vault + create the org\'s ed25519 transit key (the key is BORN in Vault)');
    docker([...COMPOSE, 'up', '-d', 'vault'], true);
    for (let i = 0; i < 60; i++) {
      const up = await fetch(`${VAULT_ADDR}/v1/sys/health`).then((r) => r.status < 500).catch(() => false);
      if (up) break;
      await sleep(500);
    }
    docker([...COMPOSE, 'exec', '-T', '-e', `VAULT_ADDR=http://127.0.0.1:8200`, '-e', `VAULT_TOKEN=${VAULT_TOKEN}`, 'vault',
      'sh', '-c', `vault secrets enable transit || true; vault write -f transit/keys/${KEY_NAME} type=ed25519`], true);

    // We can read the PUBLIC key. There is no API that gives us the private one — that is the point.
    const vault = new VaultTransitSigner({ addr: VAULT_ADDR, keyName: KEY_NAME, token: VAULT_TOKEN });
    const pub = await vault.publicKey();
    const keyHash = Buffer.from(sha(pub)).toString('hex');
    console.log(`  vault pubkey: ${Buffer.from(pub).toString('hex')}\n  key hash (goes on the page): ${keyHash}`);

    console.log('\n[2] provision on the test network: O\'s key page carries VAULT\'s key hash (we hold no private key for O)');
    const f = await fundLite();
    await submit(new core.Transaction({
      header: { principal: f.fLite },
      body: { type: 'createIdentity', url: adiO, keyHash: sha(pub), keyBookUrl: oBook },
    }), S.Signer.forLite(f.funding.key), `adi ${adiO}`);
    await waitForAccount(oPage, 'O page');
    await submit(new core.Transaction({
      header: { principal: f.fLta },
      body: { type: 'addCredits', recipient: oPage, amount: '400000000', oracle: f.oracle },
    }), S.Signer.forLite(f.funding.key), 'credits-O');
    await waitForCredits(oPage, 'O page');

    const A = await createPrincipal(f, `acc://av-${ts}.acme`, 0x22);
    console.log(`  O page: ${oPage} (key = Vault's)\n  A data: ${A.dataAccount}`);

    console.log('\n[3] config the signer for vault-transit — it gets a Vault TOKEN, never a key');
    writeFileSync(CONFIG,
`signer: { org_id: "ov-${ts}", network: "the test network", accumulate_endpoints: ["${ENDPOINT}"], signer_url: "${oPage}", attachment_model: "per_tx" }
signer: { provider: "vault-transit", vault: { addr: "http://vault:8200", key_name: "${KEY_NAME}", token: "env:VAULT_TOKEN" } }
policy: { url: "http://policy:9099/decision", mode: "sync", auth: "none", timeout_ms: 10000 }
trigger: { webhook: { enabled: false, bind: "0.0.0.0:8080" }, poller: { enabled: true, interval_seconds: 15 } }
behavior: { submit_reject_vote: true }
store: { path: "/data/signer-state.json" }
admin: { api_key: "env:ADMIN_API_KEY" }
health: { bind: "0.0.0.0:8080" }
observability: { log_level: "info" }
`);

    console.log('\n[4] bring up the signer + policy engine');
    docker([...COMPOSE, 'up', '-d', '--build']);
    let boot = '';
    for (let i = 0; i < 40; i++) {
      await sleep(1500);
      boot = await walletLogs().catch(() => '');
      if (/fatal startup error/i.test(boot)) throw new Error(`signer refused to boot:\n${boot.slice(-800)}`);
      if (/http server listening/i.test(boot)) break;
    }
    const sr6 = /SR6 self-check OK/i.test(boot);
    const usesVault = /"provider":"vault-transit"/.test(boot) || /vault/i.test(boot);
    const health = await fetch(`${BASE}/healthz`).then((r) => r.status).catch(() => 0);
    console.log(`  /healthz: ${health} | SR6 (our Vault pubkey IS on the page): ${sr6} | provider=vault-transit: ${usesVault}`);

    console.log('\n[5] A writes an EVEN (4000) and an ODD (4001) intent naming O');
    const even = await writeIntent(A, { authorities: [oBook], amountWei: '4000' });
    const odd = await writeIntent(A, { authorities: [oBook], amountWei: '4001' });
    console.log(`  EVEN ${even.hash}\n  ODD  ${odd.hash}`);

    console.log('\n[6] waiting — every signature below is produced INSIDE Vault (up to ~200s)...');
    let evenState = 'pending', oddState = 'pending';
    for (let i = 0; i < 50; i++) {
      await sleep(4000);
      evenState = await txState(even.hash, A.dataPrincipal);
      oddState = await txState(odd.hash, A.dataPrincipal);
      if (evenState === 'delivered' && oddState === 'rejected') break;
    }
    const logs = await walletLogs();
    const votes = (logs.match(/vote submitted/gi) ?? []).length;

    // The network only accepts a signature made by a key on the page. The page carries Vault's key hash
    // and the signer has no private key, so a delivered tx proves Vault produced a network-valid signature.
    const results: Array<[string, boolean]> = [
      ['signer booted against Vault, /healthz 200', health === 200],
      ['SR6: the key on O\'s page is VAULT\'s public key', sr6],
      ['EVEN 4000 approved -> delivered (network accepted a Vault-made signature)', evenState === 'delivered'],
      ['ODD 4001 denied -> rejected (Vault signed the Reject vote)', oddState === 'rejected'],
      ['exactly 2 votes submitted', votes === 2],
    ];
    console.log('\n[7] results');
    for (const [label, ok] of results) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
    pass = results.every(([, ok]) => ok);
    if (!pass) console.log('\n--- signer log (tail) ---\n' + logs.split('\n').slice(-30).join('\n'));
  } finally {
    console.log('\n[8] teardown');
    try { docker([...COMPOSE, 'down', '-v'], true); } catch {}
    rmSync(CONFIG, { force: true });
  }

  console.log('\n=== VAULT CUSTODY:', pass
    ? 'PASS ✅ — the org\'s key was generated in Vault, never left it, and the network accepted the votes Vault signed. The signer never held a private key.'
    : 'INCOMPLETE — see results above.', '===');
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL', e.message);
  try { execFileSync('docker', [...COMPOSE, 'down', '-v'], { stdio: 'ignore', env }); } catch {}
  rmSync(CONFIG, { force: true });
  process.exit(1);
});
