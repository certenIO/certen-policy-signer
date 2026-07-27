/**
 * Key rotation, live — all three modes, each CONFIRMED ON CHAIN by reading the key page.
 *
 * A rotation that submits a transaction but never confirms it is worthless. Accumulate executes
 * asynchronously, so "submitted" tells you nothing about whether your authority actually moved. Every
 * rotation here is verified by polling the page's listed key hashes.
 *
 * Proves:
 *   1. `updateKey`       — atomic single-transaction rotation; the page swaps old for new
 *   2. `update`          — the same via a key-page update, which also bumps the page version
 *   3. `add-then-remove` — both keys live at once (the zero-downtime window), then the old one removed
 *   4. CONTINUITY — after rotating, a signer running the NEW key discovers a pending transaction and
 *      votes, and the network accepts it. This is the only thing that proves the rotation preserved
 *      authority rather than merely changing a record.
 *   5. The OLD key can no longer act: its signature is refused.
 *
 * Procedure and how to choose a mode: docs/OPERATIONS.md
 *
 *   npx tsx scripts/verify/key-rotation.ts
 */
import { createHash } from 'node:crypto';
import { ChildProcess } from 'node:child_process';
import { rmSync } from 'node:fs';
import nacl from 'tweetnacl';
import { logger } from '../../src/logger.js';
import { LocalSigner } from '../../src/signer/signer.js';
import { rotateKey, readPage } from '../../src/ops/rotate.js';
import {
  ENDPOINT, raw, sleep, fundLite, createOrg, createPrincipal, writeIntent, txState,
  writeConfig, spawnEngine, spawnDaemon, kill,
} from './_lib.js';

const quiet = logger.child({ level: 'warn' });
const ENGINE = 9121, HEALTH = 18121;
const ADMIN_KEY = 'rotate-admin-key', GOV_KEY = 'rotate-gov-key';
const CONFIG = 'config.rotate.generated.yaml';
const keyHashOf = (pub: Uint8Array) => createHash('sha256').update(pub).digest('hex');
const newKey = () => {
  const seed = nacl.randomBytes(32);
  const kp = nacl.sign.keyPair.fromSeed(seed);
  return { seedHex: Buffer.from(seed).toString('hex'), pub: kp.publicKey, hash: keyHashOf(kp.publicKey) };
};

const kids: ChildProcess[] = [];

async function main() {
  const ts = Date.now();
  const results: Record<string, string> = {};
  console.log('=== Live key rotation on', ENDPOINT, '===\n');

  console.log('[1] provision O (the signing org) + A (the initiator)');
  const f = await fundLite();
  const O = await createOrg(f, `acc://orot-${ts}.acme`, 0x33, '400000000');
  const A = await createPrincipal(f, `acc://arot-${ts}.acme`, 0x22);
  let current = { seedHex: Buffer.from(O.key.seed).toString('hex'), pub: O.key.pub, hash: keyHashOf(O.key.pub) };
  console.log(`  O page: ${O.page}\n  key on page: ${current.hash}`);

  const deps = (seedHex: string) => ({
    accumulate: raw,
    signer: new LocalSigner(new Uint8Array(Buffer.from(seedHex, 'hex'))),
    logger: quiet,
  });

  // ---- 1: atomic updateKey ----
  console.log('\n[2] mode=updateKey (atomic, single tx)');
  const k1 = newKey();
  const r1 = await rotateKey(deps(current.seedHex), { page: O.page, newKeyHash: k1.hash, mode: 'updateKey' });
  console.log(`  ok=${r1.ok} version ${r1.before.version} -> ${r1.after.version} | keys now: ${r1.after.keyHashes.join(',')}`);
  results['1 updateKey (atomic)'] = r1.ok && r1.after.keyHashes.includes(k1.hash) && !r1.after.keyHashes.includes(current.hash) ? 'PASS' : 'FAIL';
  if (r1.ok) current = k1;

  // ---- 2: updateKeyPage / update operation ----
  console.log('\n[3] mode=update (key-page update operation)');
  const k2 = newKey();
  const r2 = await rotateKey(deps(current.seedHex), { page: O.page, newKeyHash: k2.hash, mode: 'update' });
  console.log(`  ok=${r2.ok} version ${r2.before.version} -> ${r2.after.version} | keys now: ${r2.after.keyHashes.join(',')}`);
  results['2 update (page operation)'] = r2.ok && r2.after.keyHashes.includes(k2.hash) && !r2.after.keyHashes.includes(current.hash) ? 'PASS' : 'FAIL';
  const oldBeforeR2 = current.hash;
  if (r2.ok) current = k2;

  // ---- 3: add-then-remove (zero-downtime) ----
  console.log('\n[4] mode=add-then-remove (both keys live briefly, then the old one goes)');
  const k3 = newKey();
  const r3 = await rotateKey(deps(current.seedHex), { page: O.page, newKeyHash: k3.hash, mode: 'add-then-remove' });
  console.log(`  ok=${r3.ok} version ${r3.before.version} -> ${r3.after.version} | keys now: ${r3.after.keyHashes.join(',')}`);
  results['3 add-then-remove (zero-downtime)'] = r3.ok && r3.after.keyHashes.includes(k3.hash) && !r3.after.keyHashes.includes(current.hash) ? 'PASS' : 'FAIL';
  const supersededKey = current;         // the key we just rotated AWAY from
  if (r3.ok) current = k3;

  // ---- 4: the rotated-to key still signs for the org (authority preserved) ----
  console.log('\n[5] CONTINUITY: boot the signer on the ROTATED key; it must still discover + vote');
  writeConfig(CONFIG, { orgId: `orot-${ts}`, oPage: O.page, oSeedHex: current.seedHex, enginePort: ENGINE, healthPort: HEALTH, interval: 12, adminKey: ADMIN_KEY, govKey: GOV_KEY });
  kids.push(spawnEngine(ENGINE));
  await sleep(1500);
  const log: string[] = [];
  kids.push(spawnDaemon(CONFIG, log));

  const intent = await writeIntent(A, { authorities: [O.book], amountWei: '4000' });
  console.log(`  A wrote an EVEN intent naming O: ${intent.hash}`);
  let state = 'pending';
  for (let i = 0; i < 45; i++) {
    await sleep(4000);
    state = await txState(intent.hash, A.dataPrincipal);
    if (state === 'delivered') break;
  }
  const sr6 = /SR6 self-check OK/i.test(log.join(''));
  const voted = /vote submitted/i.test(log.join(''));
  console.log(`  SR6 (new key IS on the page): ${sr6} | voted: ${voted} | tx: ${state}`);
  results['4 continuity: rotated key still signs'] = sr6 && voted && state === 'delivered' ? 'PASS' : 'FAIL';

  // ---- 5: the superseded key must no longer have authority ----
  console.log('\n[6] the SUPERSEDED key must be powerless now');
  const dead = await rotateKey(deps(supersededKey.seedHex), { page: O.page, newKeyHash: newKey().hash, mode: 'updateKey', confirmTimeoutMs: 20_000 })
    .then((r) => r)
    .catch((e) => ({ ok: false, error: (e as Error).message } as any));
  const page = await readPage(raw, O.page);
  const stillOnlyNew = page.keyHashes.includes(current.hash) && !page.keyHashes.includes(supersededKey.hash);
  console.log(`  old key rotation attempt rejected: ${!dead.ok} (${String(dead.error ?? '').slice(0, 80)})`);
  console.log(`  page still holds only the current key: ${stillOnlyNew}`);
  results['5 superseded key has no authority'] = !dead.ok && stillOnlyNew ? 'PASS' : 'FAIL';

  // ---- 6: the TYPED governance endpoint (no blind signing) actually changes the page ----
  console.log('\n[7] typed governance endpoint: POST /v1/admin/key-page (the signer builds the tx itself)');
  const admin = (body: unknown, gov = GOV_KEY) => fetch(`http://127.0.0.1:${HEALTH}/v1/admin/key-page`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': ADMIN_KEY, 'x-governance-key': gov },
    body: JSON.stringify(body),
  });

  const noGov = await admin({ op: 'add-key', keyHash: newKey().hash }, 'wrong-key').then((r) => r.status);
  const blind = await fetch(`http://127.0.0.1:${HEALTH}/v1/admin/sign-governance`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': ADMIN_KEY, 'x-governance-key': GOV_KEY },
    body: JSON.stringify({ hash: 'cd'.repeat(32) }),
  }).then((r) => r.status);

  const spare = newKey();
  const added = await admin({ op: 'add-key', keyHash: spare.hash }).then((r) => r.json() as any);
  const pageNow = await readPage(raw, O.page);
  const lastKey = await admin({ op: 'remove-key', keyHash: current.hash }).then((r) => r.json() as any);  // would strip our own key... but 2 keys exist, so allowed
  console.log(`  wrong governance key -> ${noGov} (expect 401)`);
  console.log(`  blind sign-governance route -> ${blind} (expect 404: it no longer exists)`);
  console.log(`  add-key confirmed on-chain: ${added.ok} | page keys now: ${pageNow.keyHashes.length}`);
  console.log(`  remove-key (page still has another key): ${lastKey.ok}`);
  results['6 typed governance (no blind signing)'] =
    noGov === 401 && blind === 404 && added.ok && pageNow.keyHashes.includes(spare.hash) ? 'PASS' : 'FAIL';

  console.log('\n=== RESULTS ===');
  for (const [k, v] of Object.entries(results)) console.log(`  ${v === 'PASS' ? '✅' : '❌'} ${k}: ${v}`);
  const pass = Object.values(results).every((v) => v === 'PASS');
  console.log(`\n=== Key rotation: ${pass ? 'PASS ✅ — all three modes rotate the org\'s authority and are confirmed on-chain; the signer keeps signing on the new key and the old key is powerless.' : 'INCOMPLETE — see above.'} ===`);

  for (const k of kids) kill(k);
  rmSync(CONFIG, { force: true });
  await sleep(300);
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL', e.message);
  for (const k of kids) kill(k);
  rmSync(CONFIG, { force: true });
  process.exit(1);
});
