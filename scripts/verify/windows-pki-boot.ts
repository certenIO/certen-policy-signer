/**
 * Can the signer boot against a real key page using a certificate it cannot read?
 *
 * Every other PKI run so far has held the private key in the signer's own process. This one does not:
 * the key lives in the Windows certificate store, non-exportable, and the signer reaches it through
 * `agent/windows-cert-store`. The question is whether the parts fit at startup —
 *
 *   * a `scopes[]` config with one seat per approver, each a `windows-cert-store` key
 *   * SR6, the self-check that refuses to start unless the configured key is ON the page
 *   * the agent being invoked at all, from inside the daemon, for a public key it does not hold
 *
 * SR6 is the interesting one. It reads the page from the network and compares it against the key it
 * was configured with — so it only passes if the agent returned the right PKIX DER, we hashed it the
 * way the protocol does, and the seat was created with that same hash. Three encodings agreeing, and
 * a refusal to start if any of them does not.
 *
 *   npx tsx scripts/verify/windows-pki-boot.ts
 *
 * Windows only. Build the agent first:
 *   dotnet build agent/windows-cert-store/certen-cert-agent.csproj -c Release
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import {
  fundLite, submit, waitForAccount, waitForCredits, spawnDaemon, kill, sleep, query,
  ENDPOINT, S, core,
} from './_lib.js';

const HEALTH_PORT = 18097;
const ENGINE_PORT = 9097;
const AGENT = resolve('agent/windows-cert-store/bin/Release/net9.0/certen-cert-agent.exe');
const line = (s = '') => console.log(s);

/** A stand-in for a certificate a corporate CA issued. Non-exportable, in the CNG software KSP. */
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
  } catch { /* it expires in a day regardless */ }
};

/** The agent's answer for a certificate — the same call the signer makes. */
const agent = (thumb: string, ...args: string[]) =>
  execFileSync(AGENT, ['--thumbprint', thumb, ...args], { encoding: 'utf8' }).trim();

async function main() {
  if (process.platform !== 'win32') { line('SKIP: Windows only.'); return; }
  if (!existsSync(AGENT)) {
    line(`SKIP: agent not built. dotnet build agent/windows-cert-store/certen-cert-agent.csproj -c Release`);
    return;
  }

  const ts = Date.now();
  line('\n════════════════════════════════════════════════════════════════════');
  line('  The signer boots on a key it cannot read — a Windows certificate');
  line('════════════════════════════════════════════════════════════════════\n');
  line(`  network: ${ENDPOINT}\n`);

  const thumbs = { alice: makeCert('CN=Alice Okonkwo'), bob: makeCert('CN=Bob Lindqvist') };
  try {
    line('[1/5] Two certificates in the Windows certificate store…');
    const spki = {
      alice: Buffer.from(agent(thumbs.alice, '--public-key'), 'hex'),
      bob: Buffer.from(agent(thumbs.bob, '--public-key'), 'hex'),
    };
    const hash = {
      alice: createHash('sha256').update(spki.alice).digest('hex'),
      bob: createHash('sha256').update(spki.bob).digest('hex'),
    };
    line(`      Alice  ${thumbs.alice}  ${agent(thumbs.alice, '--describe')}`);
    line(`             page entry ${hash.alice.slice(0, 24)}…`);
    line(`      Bob    ${thumbs.bob}  ${agent(thumbs.bob, '--describe')}`);
    line(`             page entry ${hash.bob.slice(0, 24)}…\n`);

    line('[2/5] Funding a throwaway account…');
    const f = await fundLite();

    line("[3/5] Creating the team identity — founded on ALICE'S CERTIFICATE, nothing else…");
    const adi = `acc://wpki${ts}.acme`;
    const book = `${adi}/book`, page = `${book}/1`;
    await submit(new core.Transaction({
      header: { principal: f.fLite },
      body: { type: 'createIdentity', url: adi, keyHash: hash.alice, keyBookUrl: book },
    }), S.Signer.forLite(f.funding.key), `adi ${adi}`);
    await waitForAccount(page, 'team page');
    await submit(new core.Transaction({
      header: { principal: f.fLta },
      body: { type: 'addCredits', recipient: page, amount: '90000', oracle: f.oracle },
    }), S.Signer.forLite(f.funding.key), 'credits');
    await waitForCredits(page, 'team page');

    const rec: any = await query(page);
    const keys: string[] = (rec?.account?.keys ?? []).map((k: any) => String(k?.publicKeyHash ?? '').toLowerCase());
    line(`      ${page}`);
    line(`      keys on page: ${keys.length}   only Alice's certificate: ${keys.length === 1 && keys[0] === hash.alice}\n`);

    line('[4/5] A scopes[] config with one seat per approver, both windows-cert-store…');
    const dir = mkdtempSync(join(tmpdir(), 'certen-wpki-'));
    const cfgPath = join(dir, 'wpki.yaml');
    const a = AGENT.replace(/\\/g, '/');
    writeFileSync(cfgPath,
`wallet:
  org_id: "wpki-${ts}"
  accumulate_endpoints: ["${ENDPOINT}"]
  attachment_model: "per_tx"
  scopes:
    - page: "${page}"
      key: { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.alice}", agent_path: "${a}" } }
      keys:
        "alice@bank.example": { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.alice}", agent_path: "${a}" } }
        "bob@bank.example":   { provider: "windows-cert-store", windows: { thumbprint: "${thumbs.bob}", agent_path: "${a}" } }
policy: { url: "http://127.0.0.1:${ENGINE_PORT}/decision", mode: "sync", auth: "none", timeout_ms: 4000 }
trigger: { webhook: { enabled: false, bind: "127.0.0.1:${HEALTH_PORT}" }, poller: { enabled: true, interval_seconds: 8 } }
store: { path: "${join(dir, 'state.json').replace(/\\/g, '/')}" }
health: { bind: "127.0.0.1:${HEALTH_PORT}" }
observability: { log_level: "info" }
`);
    line(`      ${cfgPath}   NO key material in it — two thumbprints and an agent path\n`);

    line('[5/5] Starting the signer. SR6 must find the certificate on the page or refuse to boot…\n');
    const log: string[] = [];
    const daemon = spawnDaemon(cfgPath, log);
    let ok = false, fatal = false;
    for (let i = 0; i < 60; i++) {
      await sleep(1000);
      const j = log.join('');
      if (/SR6 self-check OK/i.test(j)) { ok = true; break; }
      if (/fatal startup error/i.test(j)) { fatal = true; break; }
    }
    for (const l of log.join('').split('\n').filter(Boolean).slice(0, 14)) line(`      ${l}`);
    kill(daemon);

    line();
    line(`  signer booted on a key it cannot read : ${ok ? 'YES' : fatal ? 'NO (fatal startup error)' : 'NO (timed out)'}`);
    line(`\n  ${ok ? 'PASS' : 'FAIL'}  ${page}\n`);
    process.exitCode = ok ? 0 : 1;
  } finally {
    removeCert(thumbs.alice);
    removeCert(thumbs.bob);
    line('  cleanup   certificates removed from the store');
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
