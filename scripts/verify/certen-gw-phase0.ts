/**
 * PHASE 0 GATE — does api-gateway compute correct signing data when the signer's key book is named
 * in the transaction's header.authorities rather than being an authority of the principal?
 *
 * Untracked scratch script for the certen-sdk pending-sign work. Lives here because it needs this
 * repo's accumulate.js install and its independent preimage implementation (src/accumulate/signing.ts).
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-gw-phase0.ts <step>
 *
 * steps: identity | fixture | sign | all
 * state: $PHASE0_STATE (defaults to ./phase0-state.json)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import {
  raw, query, sleep, sha, submit, core, S, msg, nextTs,
  fundLite, createOrg, waitForAccount, txState, intentBlobs,
} from './_lib.js';
import { buildPreimage } from '../../src/accumulate/signing.js';

const GW = process.env.CERTEN_API_URL ?? 'https://gateway.kompendium.co';
const API_KEY = process.env.CERTEN_API_KEY
  ?? JSON.parse(readFileSync(join(homedir(), '.certen', 'config.json'), 'utf8')).api_key;

const STATE_PATH = process.env.PHASE0_STATE ?? 'phase0-state.json';
const state: any = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const save = () => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (h: string) => new Uint8Array(Buffer.from(h.replace(/^0x/, ''), 'hex'));

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

/** Step 1 — register ADI-B with the Certen org, holding its private key locally. */
async function stepIdentity() {
  if (state.identity?.can_sign) { console.log('identity already provisioned:', state.identity.adi_url); return; }
  if (!state.bKey) {
    const seed = nacl.randomBytes(32);
    const kp = nacl.sign.keyPair.fromSeed(seed);
    state.bKey = { seedHex: hex(seed), publicKeyHex: hex(kp.publicKey) };
    save();
  }
  if (!state.identity?.id) {
    const name = `p0sign${Date.now().toString(36)}`;
    const r = await gw('POST', '/v1/identity', {
      name,
      public_key: state.bKey.publicKeyHex,
      // External mode requires the hash too; the gateway rejects the create without it.
      public_key_hash: hex(sha(bytes(state.bKey.publicKeyHex))),
      signing_mode: 'external',
      credits: 5000,
    });
    console.log('POST /v1/identity ->', r.status, JSON.stringify(r.body).slice(0, 600));
    if (r.status >= 300) throw new Error('identity create failed');
    state.identity = { id: r.body.id, name };
    save();
  }
  for (let i = 0; i < 60; i++) {
    const r = await gw('GET', `/v1/identity/${state.identity.id}?include=governance`);
    const st = r.body?.status;
    console.log(`  [${i}] status=${st} adi=${r.body?.adi_url} can_sign=${r.body?.can_sign} page=${r.body?.key_page_url}`);
    if (st && !['provisioning', 'pending', 'creating'].includes(st)) {
      state.identity = { ...state.identity, ...r.body };
      save();
      if (st !== 'active') throw new Error(`identity terminal but not active: ${st}`);
      return;
    }
    await sleep(6000);
  }
  throw new Error('identity never became terminal');
}

/** Step 2 — ADI-A writes data to its OWN data account naming ADI-B's key book as an authority. */
async function stepFixture() {
  if (state.fixture?.txHash) { console.log('fixture already exists:', state.fixture.txHash); return; }
  const bBook = `${String(state.identity.adi_url).replace(/\/$/, '')}/book`;

  // ADI-A: faucet -> lite credits -> ADI + book + page -> data account. Keys are ephemeral; the
  // fixture is single-use so nothing needs to survive this process beyond the hash.
  const f = await fundLite();
  const adiA = `acc://p0a${Date.now().toString(36)}.acme`;
  const A = await createOrg(f, adiA, 0x22, '400000000');
  const dataAccount = `${adiA}/data`;
  const vA = (await raw.getSignerInfo(A.page)).version;
  await submit(
    new core.Transaction({ header: { principal: adiA }, body: { type: 'createDataAccount', url: dataAccount } }),
    S.Signer.forPage(A.page, A.key.key).withVersion(vA), 'dataAccount',
  );
  await waitForAccount(dataAccount, 'data account');

  const v = (await raw.getSignerInfo(A.page)).version;
  const tx = new core.Transaction({
    header: { principal: dataAccount, authorities: [bBook], memo: 'certen-phase0' },
    body: { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs('1') } },
  });
  const sig = await S.Signer.forPage(A.page, A.key.key).withVersion(v).sign(tx, { timestamp: nextTs() });
  const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
  const txid = String(r?.result?.[0]?.status?.txID ?? '');
  if (!r.ok || !txid) throw new Error(`writeData submit failed: ${JSON.stringify(r).slice(0, 500)}`);
  const txHash = txid.replace(/^acc:\/\//, '').split('@')[0];

  state.fixture = { adiA, dataAccount, principal: dataAccount.replace(/^acc:\/\//, ''), bBook, txHash, txid };
  save();
  console.log('fixture tx:', txid);

  // The vote is submitted on the SIGNER's partition. Wait until the transaction resolves there
  // before asking the gateway for signing data — signing early loses the vote silently.
  const signerPath = String(state.identity.key_page_url).replace(/^acc:\/\//, '');
  for (let i = 0; i < 25; i++) {
    const q: any = await query(`acc://${txHash}@${signerPath}`).catch(() => undefined);
    if (q) { console.log('  resolves on signer partition'); state.fixture.resolved = true; save(); return; }
    await sleep(5000);
  }
  throw new Error('transaction never resolved on the signer partition');
}

/** Step 3 — gateway pending_tx sign request; compare its preimage to a locally computed one. */
async function stepSign() {
  const { txHash, principal } = state.fixture;
  const vote = process.env.PHASE0_VOTE ?? 'approve';

  const r = await gw('POST', '/v1/sign', {
    type: 'pending_tx',
    target_id: txHash,
    identity: state.identity.adi_url,
    signer_url: state.identity.key_page_url,
    public_key: state.bKey.publicKeyHex,
    vote,
  });
  console.log('POST /v1/sign ->', r.status, JSON.stringify(r.body, null, 2).slice(0, 1200));
  if (r.status >= 300) throw new Error('sign create failed');

  const sd = r.body.signing_data ?? {};
  const gwPreimage = String(sd.data_for_signature ?? sd.hash_to_sign ?? '');
  if (!gwPreimage) throw new Error('no signing data returned');

  // Independent computation: SHA256( SHA256(encode(sig metadata)) || txHash ).
  const local = buildPreimage(bytes(txHash), {
    publicKey: bytes(state.bKey.publicKeyHex),
    signerUrl: sd.signer_url ?? state.identity.key_page_url,
    signerVersion: Number(sd.signer_version),
    timestamp: Number(sd.timestamp),
    vote: vote as any,
  });
  const localPreimage = hex(local.dataForSignature);

  console.log('\n--- preimage comparison ---');
  console.log('gateway signing_data.data_for_signature:', gwPreimage);
  console.log('local  SHA256(sigMdHash || txHash)     :', localPreimage);
  console.log('sigMdHash (local)                      :', hex(local.sigMdHash));
  console.log('signer_version / timestamp / vote      :', sd.signer_version, sd.timestamp, vote);
  const match = gwPreimage.toLowerCase() === localPreimage.toLowerCase();
  console.log('MATCH:', match);
  state.sign = { gwPreimage, localPreimage, match, signRequestId: r.body.sign_request_id, signingData: sd, vote };
  save();
  if (!match) throw new Error('PHASE 0 FAILED: gateway preimage differs from the locally computed one');

  // Sign it and cast the vote.
  const kp = nacl.sign.keyPair.fromSeed(bytes(state.bKey.seedHex));
  const signature = hex(nacl.sign.detached(bytes(gwPreimage), kp.secretKey));
  const localSig = hex(nacl.sign.detached(local.dataForSignature, kp.secretKey));
  console.log('signature (over gateway preimage):', signature);
  console.log('signature (over local   preimage):', localSig);
  console.log('SIGNATURE BYTES IDENTICAL:', signature === localSig);
  state.sign.signature = signature;
  save();

  const sub = await gw('POST', r.body.submit_url ?? `/v1/sign/${r.body.sign_request_id}/signature`, {
    signature, public_key: state.bKey.publicKeyHex,
  });
  console.log('POST submit ->', sub.status, JSON.stringify(sub.body).slice(0, 800));
  state.sign.submit = { status: sub.status, body: sub.body };
  save();
  if (sub.status >= 300) throw new Error('signature submit failed');

  const want = vote === 'reject' ? 'rejected' : 'delivered';
  for (let i = 0; i < 40; i++) {
    const st = await txState(txHash, principal);
    console.log(`  [${i}] tx ${txHash.slice(0, 12)} state=${st}`);
    if (st === want) { state.sign.finalState = st; save(); console.log(`\nPHASE 0 PASS - transaction ${st}`); return; }
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
