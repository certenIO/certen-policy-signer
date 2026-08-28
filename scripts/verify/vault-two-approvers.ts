/**
 * Two people, two keys, one page, one transaction — and the chain counts the approvals.
 *
 * Runbook F Phase F2's acceptance, run against a real network with real custody:
 *
 *   "Two different approvers, two Vault keys, two distinct on-chain signatures against one role page
 *    with threshold 2 — and the transaction executes only when both have signed."
 *
 * The shape:
 *
 *   Vault            generates TWO ecdsa-p256 keys and never releases either. This process can ask
 *                    for a signature over 32 bytes and can do nothing else with them.
 *   ADI R            the role page. Its entries are sha256 of each Vault key's PKIX public key, and
 *                    its accept threshold is 2. No Ed25519 key is left on it.
 *   ADI A            an ordinary submitter, which writes an intent naming R's book as an authority.
 *
 * What makes this a proof rather than a demonstration is the NEGATIVE half. After Alice's vote the
 * transaction is queried and must still be pending: one seat is not enough, and the page says so. Only
 * after Bob's does the network execute it. Both signatures are then read back off the chain — not off
 * this program's memory — and must be two DIFFERENT public keys, because a threshold satisfied twice
 * by one key would satisfy the assertion above while proving nothing about two people.
 *
 *   docker must be available (a dev Vault is started and removed here)
 *   npx tsx scripts/verify/vault-two-approvers.ts
 *
 * ── WHAT THIS DOES NOT PROVE, AND IT IS THE POINT OF §F6 ──────────────────────────────────────────
 *
 * That Alice approved anything. Both keys live in one Vault, released by one token held by this
 * process: the organisation can sign as either person at any time, without them. That is model A of
 * the runbook's §F6 and it is scaffolding — what it establishes is that per-person attribution is
 * REAL ON CHAIN and that the protocol, not a database, counts the approvals. Who may release the key
 * is F6's question, and F4's job is to make the answer visible in the record.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { VaultTransitSigner } from '../../src/signer/vault-transit.js';
import { MapKeyring, singleKeyring, bookOf } from '../../src/signer/keyring.js';
import { applyKeyPageOp } from '../../src/ops/keypage.js';
import { DirectVoteBackend } from '../../src/vote/backend.js';
import {
  ENDPOINT, raw, core, S, sha, sleep, submit, fundLite, createPrincipal, writeIntent, txState, query,
  waitForAccount, waitForCredits,
} from './_lib.js';
import pino from 'pino';

const VAULT = 'certen-vault-two-approvers';
const VAULT_ADDR = 'http://127.0.0.1:8200';
const TOKEN = 'root';
const STATE = 'vault-two-approvers-state.json';
const line = (s = '') => console.log(s);
const logger = pino({ level: 'warn' });

const docker = (args: string[]) => execFileSync('docker', args, { encoding: 'utf8', stdio: 'pipe' });

async function startVault(): Promise<void> {
  try { docker(['rm', '-f', VAULT]); } catch { /* not running */ }
  docker(['run', '-d', '--name', VAULT, '-p', '8200:8200',
    '-e', `VAULT_DEV_ROOT_TOKEN_ID=${TOKEN}`, '-e', 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200',
    '--cap-add=IPC_LOCK', 'hashicorp/vault', 'server', '-dev']);

  // A ref'd timer for the same reason scripts/vault-it.mjs keeps one: a fetch at a port nothing is
  // listening on yet does not always fail fast, and with nothing else pending node empties its loop
  // and exits with no message about Vault at all.
  const heartbeat = setInterval(() => {}, 250);
  try {
    for (let i = 0; i < 60; i++) {
      const ok = await fetch(`${VAULT_ADDR}/v1/sys/health`, { signal: AbortSignal.timeout(1000) })
        .then((r) => r.status < 500).catch(() => false);
      if (ok) break;
      await sleep(500);
      if (i === 59) throw new Error('dev Vault never became reachable');
    }
  } finally { clearInterval(heartbeat); }

  docker(['exec', '-e', 'VAULT_ADDR=http://127.0.0.1:8200', '-e', `VAULT_TOKEN=${TOKEN}`, VAULT, 'sh', '-c',
    'vault secrets enable transit'
    + ' && vault write -f transit/keys/alice-seat type=ecdsa-p256'
    + ' && vault write -f transit/keys/bob-seat type=ecdsa-p256']);
}

/**
 * Cast one approver's vote through the PRODUCT'S OWN vote path.
 *
 * DirectVoteBackend is what the running signer uses: it builds the preimage from the key's declared
 * signature type, signs, and submits. Rolling a submission by hand here would prove that this script
 * can talk to Accumulate, which is not the thing under test.
 *
 * The pending transaction is fetched first because a vote is a signature over a transaction that
 * already exists -- the envelope carries the transaction the network is holding, not a fresh one.
 */
async function voteWith(signer: VaultTransitSigner, page: string, txHash: string, principal: string): Promise<void> {
  // Retry, because a freshly written intent is not queryable the instant its submit returns. The
  // running signer never notices this: its poller asks again every few seconds. A script that asks
  // once sees "not found" and would report it as the network refusing to hold the transaction.
  let pending: any;
  for (let i = 0; i < 30; i++) {
    pending = await (raw as any).getPendingTx(txHash, page).catch(() => undefined);
    if (pending?.found) break;
    await sleep(2000);
  }
  if (!pending?.found) throw new Error(`the network is not holding ${txHash.slice(0, 12)} for ${page} after 60s`);
  const info = await (raw as any).getSignerInfo(page);

  const backend = new DirectVoteBackend(raw as any, singleKeyring(signer, page), logger);
  const res = await backend.cast({
    txHash,
    signerUrl: page,
    signerVersion: info.version,
    rawTransaction: pending.rawTransaction,
    lastUsedOn: info.lastUsedOn,
    account: principal,
  }, 'approve');
  if (!res.ok) throw new Error(`vote rejected: ${res.error}`);
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
  let ok = false;

  line('\n════════════════════════════════════════════════════════════════════');
  line('  TWO APPROVERS, TWO VAULT KEYS, ONE PAGE — the chain counts, not a database');
  line('════════════════════════════════════════════════════════════════════\n');
  line(`  network: ${ENDPOINT}\n`);

  line('[1/8] Starting Vault and generating two P-256 keys inside it…');
  await startVault();
  const alice = new VaultTransitSigner({ addr: VAULT_ADDR, keyName: 'alice-seat', token: TOKEN, keyType: 'ecdsa-p256' });
  const bob = new VaultTransitSigner({ addr: VAULT_ADDR, keyName: 'bob-seat', token: TOKEN, keyType: 'ecdsa-p256' });
  const aPub = await alice.publicKey();
  const bPub = await bob.publicKey();
  const aHash = createHash('sha256').update(aPub).digest('hex');
  const bHash = createHash('sha256').update(bPub).digest('hex');
  if (aHash === bHash) throw new Error('the two Vault keys are the same key');
  line(`      alice  ${aHash.slice(0, 24)}…   (${aPub.length}-byte PKIX public key)`);
  line(`      bob    ${bHash.slice(0, 24)}…   (${bPub.length}-byte PKIX public key)`);
  line('      neither private key is readable by this process.\n');

  try {
    line('[2/8] Funding a temporary test account…');
    const f = await fundLite();

    line('[3/8] Creating the submitter, an ordinary Ed25519 identity…');
    const A = await createPrincipal(f, `acc://va${ts}.acme`, 0x73, '90000');

    line('[4/8] Creating the ROLE page, whose first entry is Alice\'s Vault key…');
    const rAdi = `acc://vr${ts}.acme`;
    const rBook = `${rAdi}/book`, rPage = `${rBook}/1`;
    // Persisted before use: a key that is on a page and lost locks that page permanently. Here the keys
    // live in a Vault this script deletes, so what is recorded is the page and the hashes -- enough to
    // recognise the wreckage, and there is deliberately no private key to write down.
    writeFileSync(STATE, JSON.stringify({
      note: 'Throwaway role page for scripts/verify/vault-two-approvers.ts. The keys lived in a dev Vault that this script removes.',
      createdAt: new Date().toISOString(), endpoint: ENDPOINT, page: rPage,
      entries: { alice: aHash, bob: bHash },
    }, null, 2) + '\n');

    await submit(new core.Transaction({
      header: { principal: f.fLite },
      body: { type: 'createIdentity', url: rAdi, keyHash: sha(aPub), keyBookUrl: rBook },
    }), S.Signer.forLite(f.funding.key), `adi ${rAdi}`);
    await waitForAccount(rPage, 'role page');
    await submit(new core.Transaction({
      header: { principal: f.fLta },
      body: { type: 'addCredits', recipient: rPage, amount: '90000', oracle: f.oracle },
    }), S.Signer.forLite(f.funding.key), 'credits');
    await waitForCredits(rPage, 'role page');

    line('[5/8] Adding Bob\'s seat and raising the threshold to 2 — signed by ALICE\'S VAULT KEY.');
    line('      This is a certificate governing a key page, which is the case T27 was opened for.\n');
    const ring = new MapKeyring([{ page: rPage, book: bookOf(rPage), signer: alice, keys: { alice, bob } }]);
    const gov = { accumulate: raw as any, signer: ring.forPage(rPage, 'alice'), logger, page: rPage };

    const added = await applyKeyPageOp(gov, { op: 'add-key', keyHash: bHash } as never);
    if (!added.ok) throw new Error(`add-key failed: ${added.error}`);
    line(`      add-key    ok, page now has ${added.after.keyHashes.length} keys`);

    const raised = await applyKeyPageOp(gov, { op: 'set-threshold', threshold: 2 } as never);
    if (!raised.ok) throw new Error(`set-threshold failed: ${raised.error}`);
    line(`      threshold  ${raised.after.threshold} of ${raised.after.entries.length}\n`);

    line('[6/8] The submitter writes an intent naming the role book as an authority…');
    const intent = await writeIntent(A, { authorities: [rBook], amountWei: '4200' });
    if (!intent.ok) throw new Error(`intent submit failed: ${intent.error}`);
    line(`      intent ${intent.hash}\n`);

    line('[7/8] ALICE votes — one seat of two. The transaction must NOT execute.');
    await voteWith(alice, rPage, intent.hash, A.dataPrincipal);
    let state = 'pending';
    for (let i = 0; i < 8; i++) { await sleep(4000); state = await txState(intent.hash, A.dataPrincipal); if (state !== 'pending') break; }
    const heldAfterOne = state === 'pending';
    line(`      after one signature: ${state}   ${heldAfterOne ? '✅ still held' : '❌ executed on one seat'}\n`);

    line('      BOB votes — the second seat.');
    await voteWith(bob, rPage, intent.hash, A.dataPrincipal);
    for (let i = 0; i < 20; i++) { await sleep(4000); state = await txState(intent.hash, A.dataPrincipal); if (state !== 'pending') break; }
    line(`      after two signatures: ${state}\n`);

    line('[8/8] Reading both signatures back off the chain (queried, not remembered)…\n');
    const rec: any = await query(`acc://${intent.hash}@${A.dataPrincipal}`).catch(() => undefined);
    const ours = findSignatures(rec).filter((s) => String(s.signer).toLowerCase().includes(rAdi.replace(/^acc:\/\//, '').toLowerCase()));
    const keys = new Set<string>();
    for (const s of ours) {
      const h = createHash('sha256').update(Buffer.from(String(s.publicKey), 'hex')).digest('hex');
      keys.add(h);
      line(`      type=${s.type}  signer=${s.signer}  sha256(publicKey)=${h.slice(0, 24)}…  ${h === aHash ? '(alice)' : h === bHash ? '(bob)' : '(UNKNOWN KEY)'}`);
    }

    const twoDistinct = keys.size === 2 && keys.has(aHash) && keys.has(bHash);
    const allEcdsa = ours.length > 0 && ours.every((s) => s.type === 'ecdsaSha256');
    ok = heldAfterOne && state === 'delivered' && twoDistinct && allEcdsa;

    line('\n════════════════════════════════════════════════════════════════════');
    line('  RESULT');
    line('════════════════════════════════════════════════════════════════════');
    line(`  held on one signature      ${heldAfterOne ? '✅ pending, as a threshold of 2 requires' : '❌ executed early'}`);
    line(`  executed on two            ${state === 'delivered' ? '✅ DELIVERED' : `❌ ${state}`}`);
    line(`  two DISTINCT keys on chain ${twoDistinct ? '✅ alice and bob, both present' : `❌ ${keys.size} distinct key(s)`}`);
    line(`  both ecdsaSha256           ${allEcdsa ? '✅' : `❌ ${ours.map((s) => s.type).join(', ') || 'none found'}`}`);
    line('');
    line('  The page holds no Ed25519 key, and neither private key ever left Vault.');
    line('  The protocol counted the approvals. No database was consulted.\n');
  } finally {
    try { docker(['rm', '-f', VAULT]); line('[vault] dev Vault removed'); } catch { /* already gone */ }
  }

  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error('\n❌ error:', (e as Error).message);
  try { execFileSync('docker', ['rm', '-f', VAULT], { stdio: 'pipe' }); } catch { /* already gone */ }
  process.exit(1);
});
