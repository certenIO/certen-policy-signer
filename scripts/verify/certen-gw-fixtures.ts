/**
 * Mint N pending transactions in the enrollment shape for the certen-sdk live verification.
 *
 * Each one is a writeData to ADI-A's OWN data account naming ADI-B's key book in
 * `header.authorities` — so ADI-B must approve, without being an authority of the principal.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-gw-fixtures.ts <count>
 *
 * Appends to $PHASE0_STATE under `fixtures[]`. Reuses ADI-A across runs when its keys are recorded.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import nacl from 'tweetnacl';
import {
  raw, query, sleep, sha, submit, core, S, msg, nextTs, liteId, rpc,
  waitForAccount, waitForCredits, intentBlobs,
} from './_lib.js';

const STATE_PATH = process.env.PHASE0_STATE ?? 'phase0-state.json';
const state: any = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const save = () => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** Rebuild an accumulate.js key object from a stored seed, so ADI-A survives between runs. */
function keyFromSeed(seedHex: string) {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(seedHex, 'hex')));
  const key = S.ED25519Key.from ? S.ED25519Key.from(kp.secretKey) : new S.ED25519Key(kp.secretKey);
  return { kp, key, pub: kp.publicKey };
}

async function ensureFunder() {
  if (!state.funder) {
    const seed = nacl.randomBytes(32);
    state.funder = { seedHex: hex(seed) };
    save();
  }
  const k = keyFromSeed(state.funder.seedHex);
  const fLite = liteId(k.pub);
  const fLta = `${fLite}/ACME`;
  const net: any = await rpc('network-status', {});
  const oracle = net?.oracle?.price ?? 10000000;

  const balance = async () => Number(((await query(fLta).catch(() => undefined)) as any)?.account?.balance ?? 0);
  if ((await balance()) < 1_000_000_000) {
    for (let i = 0; i < 4; i++) {
      await rpc('faucet', { account: fLta }).catch(() => rpc('faucet', { url: fLta }).catch(() => {}));
      await sleep(2500);
    }
    for (let i = 0; i < 14; i++) { await sleep(3000); if ((await balance()) > 0) break; }
  }
  const credits = await raw.getSignerInfo(fLite).catch(() => ({ creditBalance: 0 } as any));
  if ((credits.creditBalance ?? 0) < 1_000_000) {
    await submit(
      new core.Transaction({ header: { principal: fLta }, body: { type: 'addCredits', recipient: fLite, amount: '700000000', oracle } }),
      S.Signer.forLite(k.key), 'cr-lite',
    );
    await waitForCredits(fLite, 'funding lite');
  }
  return { k, fLite, fLta, oracle };
}

async function ensureAdiA() {
  const f = await ensureFunder();
  if (state.adiA?.url) {
    return { ...state.adiA, key: keyFromSeed(state.adiA.seedHex), f };
  }
  const seed = nacl.randomBytes(32);
  const key = keyFromSeed(hex(seed));
  const url = `acc://p0a${Date.now().toString(36)}.acme`;
  const book = `${url}/book`;
  const page = `${book}/1`;
  const dataAccount = `${url}/data`;

  await submit(
    new core.Transaction({ header: { principal: f.fLite }, body: { type: 'createIdentity', url, keyHash: sha(key.pub), keyBookUrl: book } }),
    S.Signer.forLite(f.k.key), `adi ${url}`,
  );
  await waitForAccount(page, 'A page');
  await submit(
    new core.Transaction({ header: { principal: f.fLta }, body: { type: 'addCredits', recipient: page, amount: '900000000', oracle: f.oracle } }),
    S.Signer.forLite(f.k.key), 'cr A page',
  );
  await waitForCredits(page, 'A page');
  await submit(
    new core.Transaction({ header: { principal: url }, body: { type: 'createDataAccount', url: dataAccount } }),
    S.Signer.forPage(page, key.key).withVersion((await raw.getSignerInfo(page)).version), 'dataAccount',
  );
  await waitForAccount(dataAccount, 'A data account');

  state.adiA = { url, book, page, dataAccount, seedHex: hex(seed) };
  save();
  return { ...state.adiA, key, f };
}

async function mint(count: number) {
  const A = await ensureAdiA();
  const bBook = `${String(state.identity.adi_url).replace(/\/$/, '')}/book`;
  const signerPath = String(state.identity.key_page_url).replace(/^acc:\/\//, '');
  state.fixtures = state.fixtures ?? [];

  for (let i = 0; i < count; i++) {
    const v = (await raw.getSignerInfo(A.page)).version;
    const tag = `certen-live-${Date.now().toString(36)}-${i}`;
    const tx = new core.Transaction({
      header: { principal: A.dataAccount, authorities: [bBook], memo: tag },
      body: { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs(String(1000 + i)) } },
    });
    const sig = await S.Signer.forPage(A.page, A.key.key).withVersion(v).sign(tx, { timestamp: nextTs() });
    const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
    const txid = String(r?.result?.[0]?.status?.txID ?? '');
    if (!r.ok || !txid) throw new Error(`mint ${i} failed: ${JSON.stringify(r).slice(0, 400)}`);
    const txHash = txid.replace(/^acc:\/\//, '').split('@')[0];
    state.fixtures.push({ tag, txHash, txid, principal: A.dataAccount.replace(/^acc:\/\//, ''), used: false });
    save();
    console.log(`minted ${i}: ${txid}`);
    await sleep(1500);
  }

  // Every fixture must RESOLVE on the signer's partition before anything votes on it. A vote cast
  // earlier is cryptographically valid and attaches to nothing — it fails silently and looks
  // exactly like "the user has not signed yet".
  for (const fx of state.fixtures.filter((f: any) => !f.used)) {
    let ok = false;
    for (let i = 0; i < 30; i++) {
      if (await query(`acc://${fx.txHash}@${signerPath}`).catch(() => undefined)) { ok = true; break; }
      await sleep(5000);
    }
    if (!ok) throw new Error(`fixture ${fx.txHash} never resolved on the signer partition`);
    fx.resolved = true;
    save();
    console.log(`resolved ${fx.txHash}`);
  }
  console.log(`\n${state.fixtures.filter((f: any) => !f.used).length} fixtures ready`);
}

mint(Number(process.argv[2] ?? 8)).catch((e) => { console.error('FAILED:', e?.message ?? e); process.exit(1); });
