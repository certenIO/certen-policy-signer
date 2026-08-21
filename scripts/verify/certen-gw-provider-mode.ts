/**
 * Does GATEWAY PROVIDER-MODE signing work for a HEADER-AUTHORITY transaction?
 *
 * This is the one functional unknown left between here and telling a policy provider that both of
 * their signing routes work. Phase 0 proved the EXTERNAL-mode route: we held the key, the gateway
 * handed back signing data, we signed and submitted. Provider mode is different in the way that
 * matters — the GATEWAY holds the key and signs on the identity's behalf, so a browser page needs
 * no key, no extension and no CLI.
 *
 * It has never been tested against this transaction shape. Every other provider-mode caller signs
 * for an authority OF THE PRINCIPAL; here the signer's key book is named in the transaction's
 * `header.authorities` and is not an authority of the principal at all. The gateway subsystem has
 * already produced two silent-failure bugs in one day (a chain query missing `expand`, and a parse
 * reading `r.transaction` when v3 puts it under `r.message.transaction`), both of which returned
 * plausible-looking empty results rather than errors. A schema description is not evidence.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-gw-provider-mode.ts <step>
 *
 * steps: identity | fixture | sign | all
 * state: $PROVIDER_STATE (defaults to ./provider-mode-state.json)
 *
 * WHAT A PASS MEANS, precisely: the gateway signed with a key it holds, and the transaction reached
 * `delivered`. It does NOT mean the enrollee proved possession of a private key — in provider mode
 * the assertion is "whoever authenticated to Certen caused this identity to sign". That is a
 * different claim, and a policy provider relying on it should be told so explicitly.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  raw, query, sleep, submit, core, S, msg, nextTs,
  fundLite, createOrg, waitForAccount, txState, intentBlobs,
} from './_lib.js';

const GW = process.env.CERTEN_API_URL ?? 'https://gateway.kompendium.co';
const API_KEY = process.env.CERTEN_API_KEY
  ?? JSON.parse(readFileSync(join(homedir(), '.certen', 'config.json'), 'utf8')).api_key;

const STATE_PATH = process.env.PROVIDER_STATE ?? 'provider-mode-state.json';
const state: any = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const save = () => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));

async function gw(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(`${GW}${path}`, {
    method,
    headers: { 'X-API-Key': API_KEY, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: any;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

/** Step 1 — a PROVIDER-mode identity. The gateway generates and holds the key; we never see it. */
async function stepIdentity() {
  if (state.identity?.can_sign) { console.log('identity ready:', state.identity.adi_url); return; }
  if (!state.identity?.id) {
    const name = `pm${Date.now().toString(36)}`;
    // No public_key / public_key_hash: supplying them is what makes an identity EXTERNAL. Provider
    // mode means the gateway generates the key, which is the whole point of this test.
    //
    // `signing_provider` is mandatory here — the gateway rejects the create without it
    // (identity.orchestrator.ts:268). `local` + `random` is the correct provider for this test
    // specifically: the gateway generates a key and holds it itself, which IS the custody model
    // under test. A callback or KMS provider would delegate the signature elsewhere and prove
    // something about that service instead.
    const r = await gw('POST', '/v1/identity', {
      name,
      signing_mode: 'provider',
      signing_provider: { type: 'local', config: { method: 'random' } },
      credits: 5000,
    });
    console.log('POST /v1/identity ->', r.status, JSON.stringify(r.body).slice(0, 500));
    if (r.status >= 300) throw new Error('identity create failed');
    state.identity = { id: r.body.id, name };
    save();
  }
  for (let i = 0; i < 60; i++) {
    const r = await gw('GET', `/v1/identity/${state.identity.id}?include=governance`);
    const st = r.body?.status;
    console.log(`  [${i}] status=${st} adi=${r.body?.adi_url} can_sign=${r.body?.can_sign} mode=${r.body?.signing_mode}`);
    if (st && !['provisioning', 'pending', 'creating'].includes(st)) {
      state.identity = { ...state.identity, ...r.body };
      save();
      if (st !== 'active') throw new Error(`identity terminal but not active: ${st}`);
      if (state.identity.signing_mode !== 'provider') {
        throw new Error(`identity is ${state.identity.signing_mode}, not provider — the test would prove nothing`);
      }
      return;
    }
    await sleep(6000);
  }
  throw new Error('identity never became terminal');
}

/** Step 2 — ADI-A writes to its OWN data account, naming the provider identity's book as authority. */
async function stepFixture() {
  if (state.fixture?.txHash) { console.log('fixture exists:', state.fixture.txHash); return; }
  const bBook = `${String(state.identity.adi_url).replace(/\/$/, '')}/book`;

  const f = await fundLite();
  const adiA = `acc://pma${Date.now().toString(36)}.acme`;
  const A = await createOrg(f, adiA, 0x33, '400000000');
  const dataAccount = `${adiA}/data`;
  const vA = (await raw.getSignerInfo(A.page)).version;
  await submit(
    new core.Transaction({ header: { principal: adiA }, body: { type: 'createDataAccount', url: dataAccount } }),
    S.Signer.forPage(A.page, A.key.key).withVersion(vA), 'dataAccount',
  );
  await waitForAccount(dataAccount, 'data account');

  const v = (await raw.getSignerInfo(A.page)).version;
  const tx = new core.Transaction({
    header: { principal: dataAccount, authorities: [bBook], memo: 'certen-provider-mode' },
    body: { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs('1') } },
  });
  const sig = await S.Signer.forPage(A.page, A.key.key).withVersion(v).sign(tx, { timestamp: nextTs() });
  const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
  const txid = String(r?.result?.[0]?.status?.txID ?? '');
  if (!r.ok || !txid) throw new Error(`writeData submit failed: ${JSON.stringify(r).slice(0, 400)}`);
  const txHash = txid.replace(/^acc:\/\//, '').split('@')[0];

  state.fixture = { adiA, dataAccount, principal: dataAccount.replace(/^acc:\/\//, ''), bBook, txHash, txid };
  save();
  console.log('fixture tx:', txid);

  // A vote is submitted on the SIGNER's partition, so the transaction has to reach it first.
  // Signing inside that window loses the vote silently — the submit succeeds and nothing lands.
  const signerPath = String(state.identity.key_page_url).replace(/^acc:\/\//, '');
  for (let i = 0; i < 25; i++) {
    const q: any = await query(`acc://${txHash}@${signerPath}`).catch(() => undefined);
    if (q) { console.log('  resolves on signer partition'); state.fixture.resolved = true; save(); return; }
    await sleep(5000);
  }
  throw new Error('transaction never resolved on the signer partition');
}

/** Step 3 — one call. Provider mode should sign AND submit; there is no signature to hand back. */
async function stepSign() {
  const { txHash, principal } = state.fixture;
  const vote = process.env.PROVIDER_VOTE ?? 'approve';

  const r = await gw('POST', '/v1/sign', {
    type: 'pending_tx',
    target_id: txHash,
    identity: state.identity.adi_url,
    signer_url: state.identity.key_page_url,
    vote,
  });
  console.log('POST /v1/sign ->', r.status, JSON.stringify(r.body, null, 2).slice(0, 900));
  if (r.status >= 300) throw new Error('sign failed');

  // The distinguishing assertion. External mode answers `signing_required` with signing_data for the
  // caller to sign; provider mode must have signed and submitted on its own. If this comes back
  // asking us to sign, the identity is not really in provider mode and the test proved nothing.
  const status = String(r.body?.status ?? '');
  if (status === 'signing_required' || r.body?.signing_data) {
    throw new Error(`expected provider-mode auto-sign, got "${status}" with signing_data — this is the external flow`);
  }
  state.sign = { status, body: r.body, vote };
  save();

  const want = vote === 'reject' ? 'rejected' : 'delivered';
  for (let i = 0; i < 40; i++) {
    const st = await txState(txHash, principal);
    console.log(`  [${i}] tx ${txHash.slice(0, 12)} state=${st}`);
    if (st === want) {
      state.sign.finalState = st; save();
      console.log(`\nPROVIDER MODE PASS - transaction ${st}`);
      console.log('NOTE: this proves the gateway signed with a key IT holds. It does not prove the');
      console.log('      enrollee possesses a private key. Tell any policy provider relying on this.');
      return;
    }
    if (['delivered', 'rejected', 'expired'].includes(st)) {
      state.sign.finalState = st; save();
      throw new Error(`terminal state ${st}, wanted ${want}`);
    }
    await sleep(8000);
  }
  throw new Error('transaction never reached a terminal state');
}

const step = process.argv[2] ?? 'all';
(async () => {
  if (step === 'identity' || step === 'all') await stepIdentity();
  if (step === 'fixture' || step === 'all') await stepFixture();
  if (step === 'sign' || step === 'all') await stepSign();
})().catch((e) => { console.error('\nFAILED:', e?.message ?? e); process.exit(1); });
