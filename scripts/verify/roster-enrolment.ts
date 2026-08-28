/**
 * A seat that cannot be created without the person agreeing to hold it.
 *
 * Runbook F Phase F3's acceptance, on a real network:
 *
 *   "An employee is enrolled only after their own key signs; an attempt to complete enrolment without
 *    it stays pending forever. Revocation removes the seat and the next vote from that employee fails."
 *
 * The shape:
 *
 *   ADI R    the role page. Holds the organisation's own key, and gains a DELEGATE seat.
 *   ADI E    the employee: an identity whose book holds one key, a P-256 certificate. She is never
 *            asked to create it -- in a deployment it is the key behind the certificate she already
 *            carries, and here it is generated only because this script builds its own world.
 *   ADI A    an ordinary submitter, so there is a transaction for the seat to be exercised on.
 *
 * ── WHAT IS ACTUALLY UNDER TEST, AND IT IS THE NEGATIVE ───────────────────────────────────────────
 *
 * That the organisation CANNOT seat somebody by itself. `update_key_page.go` `TransactionIsReady`
 * requires every new delegate to sign the transaction that adds them, so the org proposes and the
 * protocol holds it. Step 5 waits, deliberately, and the seat must still not exist. Only in step 6,
 * when the employee's own certificate signs the same transaction, does it execute.
 *
 * A run that only checked the end state would pass against a network that never enforced anything.
 *
 *   npx tsx scripts/verify/roster-enrolment.ts
 *
 * ── AND WHAT IT DOES NOT PROVE ────────────────────────────────────────────────────────────────────
 *
 * That a PERSON consented. The employee's key here is held by this process, and in the F2 pilot
 * posture it would be held in the organisation's Vault -- so the same party can produce both halves of
 * the ceremony. The protocol's guard is real and the org cannot route around it; what the guard is
 * worth depends on who holds the key, which is §F6's question and not this script's.
 */
import { writeFileSync } from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import pino from 'pino';
import { LocalEcdsaP256Signer, LocalSigner } from '../../src/signer/signer.js';
import { applyKeyPageOp } from '../../src/ops/keypage.js';
import { DirectVoteBackend } from '../../src/vote/backend.js';
import { singleKeyring } from '../../src/signer/keyring.js';
import { readPage } from '../../src/ops/rotate.js';
import {
  ENDPOINT, raw, core, S, sha, sleep, submit, fundLite, createPrincipal, createOrg, writeIntent,
  txState, query, waitForAccount, waitForCredits, ed,
} from './_lib.js';

const STATE = 'roster-enrolment-state.json';
const line = (s = '') => console.log(s);
const logger = pino({ level: 'warn' });

/**
 * Sign an existing pending transaction with one key, through the product's own vote path.
 *
 * `delegators` is what turns a signature made on the employee's own page into one that satisfies a
 * SEAT on the role page. Without it the signature is recorded against her own book, which is not an
 * authority on the transaction at all -- so the network accepts the signature, counts it towards
 * nothing, and the transaction sits pending with no error anywhere. That is the shape of the wrapper
 * the protocol calls a DelegatedSignature, and it is why the wallet has an `attachment_model:
 * delegate` and a `delegator_url`: a delegate seat is not exercised by signing normally.
 */
async function coSign(signer: LocalEcdsaP256Signer, page: string, txHash: string, principal: string, delegators?: string[]): Promise<string | undefined> {
  let pending: any;
  for (let i = 0; i < 30; i++) {
    pending = await (raw as any).getPendingTx(txHash, page).catch(() => undefined);
    if (pending?.found) break;
    await sleep(2000);
  }
  if (!pending?.found) return `the network is not holding ${txHash.slice(0, 12)} for ${page}`;

  const info = await (raw as any).getSignerInfo(page);
  const backend = new DirectVoteBackend(raw as any, singleKeyring(signer, page), logger, delegators?.length ? { delegators } : {});
  const res = await backend.cast({
    txHash, signerUrl: page, signerVersion: info.version,
    rawTransaction: pending.rawTransaction, lastUsedOn: info.lastUsedOn, account: principal,
  }, 'approve');
  return res.ok ? undefined : res.error;
}

const seatsOn = (p: { entries: Array<{ delegate: string | null }> }) =>
  p.entries.filter((e) => e.delegate).map((e) => (e.delegate ?? '').toLowerCase());

async function main() {
  const ts = Date.now();
  const results: Record<string, string> = {};

  line('\n════════════════════════════════════════════════════════════════════');
  line('  ENROLMENT — a seat the organisation cannot create on its own');
  line('════════════════════════════════════════════════════════════════════\n');
  line(`  network: ${ENDPOINT}\n`);

  line('[1/8] Generating the employee\'s certificate key, and persisting it before use…');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privDerHex = Buffer.from(privateKey.export({ format: 'der', type: 'pkcs8' })).toString('hex');
  const spki = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }));
  const empHash = createHash('sha256').update(Buffer.from(spki)).digest('hex');
  const empAdi = `acc://emp${ts}.acme`;
  const empBook = `${empAdi}/book`, empPage = `${empBook}/1`;
  writeFileSync(STATE, JSON.stringify({
    note: 'Throwaway employee certificate for scripts/verify/roster-enrolment.ts. Written BEFORE use: a key that is on a page and lost can lock that page permanently.',
    createdAt: new Date().toISOString(), endpoint: ENDPOINT, adi: empAdi, page: empPage,
    keyHash: empHash, privateKeyPkcs8DerHex: privDerHex,
  }, null, 2) + '\n');
  const employee = new LocalEcdsaP256Signer(Buffer.from(privDerHex, 'hex'));
  line(`      employee key hash ${empHash.slice(0, 24)}…  (sha256 of the PKIX DER)\n`);

  line('[2/8] Funding a temporary test account…');
  const f = await fundLite();

  line('[3/8] Creating the role ADI (org-held) and the employee\'s own identity…');
  const roleAdi = `acc://role${ts}.acme`;
  const R = await createOrg(f, roleAdi, 0x77, '90000');
  const rolePage = R.page;

  await submit(new core.Transaction({
    header: { principal: f.fLite },
    body: { type: 'createIdentity', url: empAdi, keyHash: sha(spki), keyBookUrl: empBook },
  }), S.Signer.forLite(f.funding.key), `adi ${empAdi}`);
  await waitForAccount(empPage, 'employee page');
  await submit(new core.Transaction({
    header: { principal: f.fLta },
    body: { type: 'addCredits', recipient: empPage, amount: '90000', oracle: f.oracle },
  }), S.Signer.forLite(f.funding.key), 'credits');
  await waitForCredits(empPage, 'employee page');
  line(`      role page      ${rolePage}`);
  line(`      employee book  ${empBook}   (one key: her certificate)\n`);

  line('[4/8] The organisation PROPOSES the seat, signing with its own key…');
  // The organisation's own Ed25519 key, the one createOrg put on the role page.
  const gov = { accumulate: raw as any, signer: new LocalSigner(R.key.seed), logger, page: rolePage };
  const proposal = await applyKeyPageOp(gov, { op: 'add-delegate', delegate: empBook }, 20_000);
  if (!proposal.ok) { line(`\n❌ proposal failed: ${proposal.error}\n`); process.exit(1); }
  const proposalTx = proposal.submitted[0]!;
  line(`      submitted ${proposalTx}`);
  line(`      awaitingConsent = ${proposal.awaitingConsent === true}\n`);
  results['the proposal reports that it is awaiting consent'] = proposal.awaitingConsent === true ? 'PASS' : 'FAIL';

  line('[5/8] WAITING. Nobody but the organisation has signed. The seat must NOT exist.');
  for (let i = 0; i < 8; i++) {
    await sleep(4000);
    const st = await txState(proposalTx, rolePage);
    if (st === 'delivered') break;
  }
  const midway = await readPage(raw as any, rolePage);
  const notSeated = !seatsOn(midway).includes(empBook.toLowerCase());
  line(`      seats on the role page: ${seatsOn(midway).length}   employee seated: ${!notSeated}`);
  line(`      ${notSeated ? '✅ the protocol is holding it — the org cannot seat her alone' : '❌ she was seated with no signature of her own'}\n`);
  results['the org alone cannot create the seat'] = notSeated ? 'PASS' : 'FAIL';

  line('[6/8] The EMPLOYEE\'S OWN CERTIFICATE co-signs the same transaction…');
  const err = await coSign(employee, empPage, proposalTx, rolePage);
  if (err) line(`      co-signature refused: ${err}`);
  let seatedNow = false;
  for (let i = 0; i < 20; i++) {
    await sleep(4000);
    const p = await readPage(raw as any, rolePage).catch(() => midway);
    if (seatsOn(p).includes(empBook.toLowerCase())) { seatedNow = true; break; }
  }
  line(`      ${seatedNow ? '✅ seated — the seat exists because SHE agreed to hold it' : '❌ still not seated'}\n`);
  results['her own signature completes the enrolment'] = seatedNow ? 'PASS' : 'FAIL';

  line('[7/8] She exercises the seat: a transaction naming the role book as an authority…');
  const A = await createPrincipal(f, `acc://sub${ts}.acme`, 0x79, '90000');
  const intent = await writeIntent(A, { authorities: [R.book], amountWei: '4200' });
  let exercised = 'not submitted';
  if (!intent.ok) {
    line(`      intent submit failed: ${intent.error}`);
  } else {
    // She signs on HER page, WRAPPED as a delegated signature naming the role page. That wrapper is
    // what makes it satisfy the seat: it says "this is the role page acting, through the book it
    // delegated to". Signing plainly leaves the transaction pending forever, silently.
    const voteErr = await coSign(employee, empPage, intent.hash, A.dataPrincipal, [rolePage]);
    if (voteErr) line(`      vote refused: ${voteErr}`);
    for (let i = 0; i < 20; i++) { await sleep(4000); exercised = await txState(intent.hash, A.dataPrincipal); if (exercised !== 'pending') break; }
    line(`      transaction: ${exercised}\n`);
  }
  results['the seat can be exercised'] = exercised === 'delivered' ? 'PASS' : `FAIL (${exercised})`;

  line('[8/8] REVOKING the seat — no consent needed, it is the org\'s own page…');
  const revoke = await applyKeyPageOp(gov, { op: 'remove-delegate', delegate: empBook }, 60_000);
  const gone = revoke.ok && !seatsOn(revoke.after).includes(empBook.toLowerCase());
  line(`      ${gone ? '✅ seat removed' : `❌ ${revoke.error ?? 'still present'}`}`);
  results['revocation removes the seat'] = gone ? 'PASS' : 'FAIL';

  line('      and the next vote from that employee must now fail…');
  const intent2 = await writeIntent(A, { authorities: [R.book], amountWei: '4300' });
  let afterRevoke = 'not submitted';
  if (intent2.ok) {
    const voteErr = await coSign(employee, empPage, intent2.hash, A.dataPrincipal, [rolePage]);
    // Either the submission is refused outright, or it is accepted and never satisfies the authority.
    if (voteErr) {
      line(`      vote refused outright: ${voteErr}`);
      afterRevoke = 'refused';
    } else {
      for (let i = 0; i < 8; i++) { await sleep(4000); afterRevoke = await txState(intent2.hash, A.dataPrincipal); if (afterRevoke === 'delivered') break; }
      line(`      transaction after revocation: ${afterRevoke}`);
    }
  }
  results['a revoked seat cannot authorise'] = afterRevoke !== 'delivered' ? 'PASS' : 'FAIL (it still executed)';

  line('\n════════════════════════════════════════════════════════════════════');
  line('  RESULT');
  line('════════════════════════════════════════════════════════════════════');
  let allOk = true;
  for (const [what, how] of Object.entries(results)) {
    line(`  ${how.startsWith('PASS') ? '✅' : '❌'}  ${what}${how.startsWith('PASS') ? '' : `  — ${how}`}`);
    if (!how.startsWith('PASS')) allOk = false;
  }
  line('');
  line('  The organisation proposed. The protocol refused to seat her until her own key agreed.');
  line(`  state file: ${STATE}\n`);
  process.exit(allOk ? 0 : 1);
}

main().catch((e) => { console.error('\n❌ error:', (e as Error).message); process.exit(1); });
