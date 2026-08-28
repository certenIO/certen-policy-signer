/**
 * A vote cast with a PKI key, by the signer itself, on a real network.
 *
 * Everything else about this signer assumes Ed25519. This proves the assumption was never load-bearing:
 * the same process, the same poller, the same policy call and the same vote path sign with an ECDSA
 * P-256 key — the key type a corporate certificate actually is — and Accumulate executes the
 * transaction. The proof is the network's, not ours: a signature the protocol did not accept would leave
 * the transaction pending, and the recorded signature type is read back off the chain afterwards rather
 * than reported from this program's own memory.
 *
 * The shape:
 *
 *   ADI A  (Ed25519)      submits an intent naming B's key book as a transaction-header authority,
 *                         so the network holds it pending until B signs
 *   ADI B  (P-256 only)   the key page whose ONLY entry is sha256(certificate public key DER)
 *   signer                configured for B's page with provider: local-ecdsa-p256
 *
 * B's page never holds an Ed25519 key at all, so nothing but the P-256 key can have produced the
 * signature that executed the transaction.
 *
 *   npx tsx scripts/verify/pki-ecdsa-vote.ts
 *
 * The generated P-256 key is written to pki-ecdsa-state.json BEFORE it is used for anything. Losing a
 * key that is already on a page is how a key page gets locked permanently; the file is gitignored.
 */
import http from 'node:http';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  fundLite, createPrincipal, writeIntent, txState, spawnDaemon, kill, sleep, submit, waitForAccount,
  waitForCredits, query, sha, ENDPOINT, S, core,
} from './_lib.js';

const ENGINE_PORT = 9094;
const HEALTH_PORT = 18094;
const STATE = 'pki-ecdsa-state.json';
const line = (s = '') => console.log(s);

/** Provision with a retry that lengthens the name by one char — same ride-out as the other scripts. */
async function withRetry<T>(label: string, fn: (i: number) => Promise<T>): Promise<T> {
  let last: unknown;
  for (let i = 1; i <= 6; i++) {
    try { return await fn(i); }
    catch (e) { last = e; console.log(`      (${label}: attempt ${i} retry)`); await sleep(Math.min(15000, 3000 * i)); }
  }
  throw last;
}

/** Every signature object anywhere in a queried record, however deeply the API nests it. */
function findSignatures(node: unknown, out: Record<string, any>[] = []): Record<string, any>[] {
  if (Array.isArray(node)) { for (const n of node) findSignatures(n, out); return out; }
  if (node && typeof node === 'object') {
    const o = node as Record<string, any>;
    if (typeof o.type === 'string' && typeof o.signer === 'string' && typeof o.signature === 'string') out.push(o);
    for (const v of Object.values(o)) findSignatures(v, out);
  }
  return out;
}

async function main() {
  const ts = Date.now();
  line('\n════════════════════════════════════════════════════════════════════');
  line('  PKI LIVE PROOF — the signer votes with an ECDSA P-256 key, on the test network');
  line('════════════════════════════════════════════════════════════════════\n');
  line(`  network: ${ENDPOINT}\n`);

  // ── the certificate key ─────────────────────────────────────────────────────────────────────
  // A real deployment does not generate this: it is the key behind an employee's existing corporate
  // certificate, and its DER is what the CA already bound to her name. Generated here only because
  // this script provisions its own throwaway world.
  line('[1/7] Generating a P-256 key and PERSISTING it before it is used anywhere…');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privDerHex = Buffer.from(privateKey.export({ format: 'der', type: 'pkcs8' })).toString('hex');
  const spki = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }));
  const keyHashHex = createHash('sha256').update(Buffer.from(spki)).digest('hex');
  const bAdi = `acc://pkib${ts}.acme`;
  writeFileSync(STATE, JSON.stringify({
    note: 'Throwaway P-256 key for scripts/verify/pki-ecdsa-vote.ts. Written BEFORE use: a key that is on a page and lost can lock that page permanently.',
    createdAt: new Date().toISOString(), endpoint: ENDPOINT,
    adi: bAdi, page: `${bAdi}/book/1`, keyHash: keyHashHex,
    publicKeySpkiDerHex: Buffer.from(spki).toString('hex'), privateKeyPkcs8DerHex: privDerHex,
  }, null, 2) + '\n');
  line(`      key page entry will be sha256(PKIX DER) = ${keyHashHex.slice(0, 24)}…`);
  line(`      persisted to ${STATE}\n`);

  line('[2/7] Funding a temporary test account…');
  const f = await fundLite();

  line('[3/7] Creating ADI A — the submitter, an ordinary Ed25519 identity…');
  const A = await withRetry('adi A', (i) => createPrincipal(f, `acc://pkia${ts}${'x'.repeat(i - 1)}.acme`, 0x71, '90000'));

  line('[4/7] Creating ADI B — its key page holds the CERTIFICATE key and nothing else…');
  const bBook = `${bAdi}/book`, bPage = `${bBook}/1`;
  await withRetry('adi B', async () => {
    await submit(new core.Transaction({
      header: { principal: f.fLite },
      body: { type: 'createIdentity', url: bAdi, keyHash: sha(spki), keyBookUrl: bBook },
    }), S.Signer.forLite(f.funding.key), `adi ${bAdi}`);
    await waitForAccount(bPage, 'B page');
  });
  await submit(new core.Transaction({
    header: { principal: f.fLta },
    body: { type: 'addCredits', recipient: bPage, amount: '90000', oracle: f.oracle },
  }), S.Signer.forLite(f.funding.key), 'cr B');
  await waitForCredits(bPage, 'B page');

  const pageRec: any = await query(bPage);
  const onPage: string[] = (pageRec?.account?.keys ?? []).map((k: any) => String(k?.publicKeyHash ?? '').toLowerCase());
  line(`      ${bPage}`);
  line(`      keys on page: ${onPage.length}   is our certificate hash the only one: ${onPage.length === 1 && onPage[0] === keyHashHex}\n`);

  // ── the signer, configured for a key it cannot sign for with Ed25519 ─────────────────────────
  const dir = mkdtempSync(join(tmpdir(), 'certen-pki-'));
  const cfgPath = join(dir, 'pki.yaml');
  writeFileSync(cfgPath,
`wallet: { org_id: "pki-proof-${ts}", accumulate_endpoints: ["${ENDPOINT}"], signer_url: "${bPage}", attachment_model: "per_tx" }
signer: { provider: "local-ecdsa-p256", local: { private_key_der_hex: "${privDerHex}" } }
policy: { url: "http://127.0.0.1:${ENGINE_PORT}/decision", mode: "sync", auth: "none", timeout_ms: 4000 }
trigger: { webhook: { enabled: false, bind: "127.0.0.1:${HEALTH_PORT}" }, poller: { enabled: true, interval_seconds: 8 } }
behavior: { submit_reject_vote: true }
store: { path: "${join(dir, 'state.json').replace(/\\/g, '/')}" }
health: { bind: "127.0.0.1:${HEALTH_PORT}" }
observability: { log_level: "info" }
`);

  const engine = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
      const r = JSON.parse(b || '{}');
      console.log(`    [policy] APPROVE tx=${String(r.txHash).slice(0, 12)} "${r.actionSummary}"`);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'approve', reason: 'PKI live proof' }));
    });
  });
  await new Promise<void>((r) => engine.listen(ENGINE_PORT, '127.0.0.1', () => r()));

  line('[5/7] Starting the signer. SR6 must find OUR certificate hash on the page or it refuses to boot…\n');
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
    console.error('\n❌ signer did not start:\n' + log.join('').split('\n').filter((l) => /fatal|error|refus|SR6/i.test(l)).slice(0, 6).join('\n'));
    kill(daemon); engine.close(); process.exit(1);
  }
  line('\n   ✓ signer up on a page whose only key is a P-256 certificate\n');

  line('[6/7] ADI A submits an intent naming B\'s key book as a header authority…\n');
  const intent = await writeIntent(A, { authorities: [bBook], amountWei: '4200' });
  if (!intent.ok) { console.error(`❌ intent submit failed: ${intent.error}`); kill(daemon); engine.close(); process.exit(1); }
  line(`   intent ${intent.hash}`);
  line('   pending until B signs. Watching the signer discover it, ask the engine, and vote…\n');

  let state = 'pending';
  for (let i = 0; i < 60; i++) {
    await sleep(4000);
    state = await txState(intent.hash, A.dataPrincipal);
    if (state === 'delivered' || state === 'rejected') break;
  }

  line(`\n[7/7] Reading the signature back off the chain (queried, not remembered)…\n`);
  const rec: any = await query(`acc://${intent.hash}@${A.dataPrincipal}`).catch(() => undefined);
  const sigs = findSignatures(rec);
  const ours = sigs.filter((s) => String(s.signer).toLowerCase().includes(bAdi.replace(/^acc:\/\//, '').toLowerCase()));
  for (const s of ours) {
    const sigLen = String(s.signature).length / 2, keyLen = String(s.publicKey ?? '').length / 2;
    line(`   SIGNATURE: type=${s.type}   signer=${s.signer}`);
    line(`              siglen=${sigLen} bytes   pubkeylen=${keyLen} bytes`);
    line(`              sha256(publicKey)=${createHash('sha256').update(Buffer.from(String(s.publicKey), 'hex')).digest('hex').slice(0, 24)}…`);
  }
  const ecdsa = ours.find((s) => s.type === 'ecdsaSha256');

  line('\n════════════════════════════════════════════════════════════════════');
  line('  RESULT');
  line('════════════════════════════════════════════════════════════════════');
  line(`  transaction            ${state === 'delivered' ? '✅ DELIVERED' : `❌ ${state}`}`);
  line(`  signature type on chain ${ecdsa ? '✅ ecdsaSha256' : `❌ ${ours.map((s) => s.type).join(', ') || 'none found for B'}`}`);
  line(`  public key on chain     ${ecdsa && createHash('sha256').update(Buffer.from(String(ecdsa.publicKey), 'hex')).digest('hex') === keyHashHex ? '✅ hashes to the page entry' : '❌ does not match the page entry'}`);
  line('');
  line('  B\'s page holds no Ed25519 key, so nothing else could have satisfied that authority.');
  line(`  state file: ${STATE}\n`);

  kill(daemon); engine.close();
  await sleep(500);
  process.exit(state === 'delivered' && ecdsa ? 0 : 1);
}
main().catch((e) => { console.error('\n❌ error:', (e as Error).message); process.exit(1); });
