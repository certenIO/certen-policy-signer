/**
 * Mint pending transactions that the gateway's poller CAN discover, so the inbox-id path has
 * something real to sign.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-gw-inbox-fixtures.ts <count>
 *
 * Why this is shaped differently from certen-gw-fixtures.ts: Accumulate keeps a transaction's
 * pending entry on the PRINCIPAL, and the poller scans only the registered ADI's own accounts and
 * key books. A transaction that merely names ADI-B's book in header.authorities is pending on
 * SOMEONE ELSE's data account, so it never reaches ADI-B's inbox — which is exactly why the
 * by-hash route has to exist.
 *
 * To get an inbox row we need the reverse: a principal that lives under ADI-B, which ADI-B has NOT
 * yet signed. So we create a data account under ADI-B owned by two books (ADI-B's and ADI-C's) and
 * let ADI-C initiate the write. It is pending on ADI-B's own account, awaiting ADI-B.
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

function keyFromSeed(seedHex: string) {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(seedHex, 'hex')));
  const key = S.ED25519Key.from ? S.ED25519Key.from(kp.secretKey) : new S.ED25519Key(kp.secretKey);
  return { kp, key, pub: kp.publicKey };
}

async function funder() {
  const k = keyFromSeed(state.funder.seedHex);
  const fLite = liteId(k.pub);
  const fLta = `${fLite}/ACME`;
  const net: any = await rpc('network-status', {});
  const oracle = net?.oracle?.price ?? 10000000;
  const bal = async () => Number(((await query(fLta).catch(() => undefined)) as any)?.account?.balance ?? 0);
  if ((await bal()) < 500_000_000) {
    for (let i = 0; i < 4; i++) {
      await rpc('faucet', { account: fLta }).catch(() => rpc('faucet', { url: fLta }).catch(() => {}));
      await sleep(2500);
    }
    for (let i = 0; i < 14; i++) { await sleep(3000); if ((await bal()) > 0) break; }
  }
  return { k, fLite, fLta, oracle };
}

/** ADI-C: the third party that INITIATES, so ADI-B is left with something unsigned to sign. */
async function ensureAdiC() {
  const f = await funder();
  if (state.adiC?.url) return { ...state.adiC, key: keyFromSeed(state.adiC.seedHex), f };

  const seed = nacl.randomBytes(32);
  const key = keyFromSeed(hex(seed));
  const url = `acc://p0c${Date.now().toString(36)}.acme`;
  const book = `${url}/book`;
  const page = `${book}/1`;
  await submit(
    new core.Transaction({ header: { principal: f.fLite }, body: { type: 'createIdentity', url, keyHash: sha(key.pub), keyBookUrl: book } }),
    S.Signer.forLite(f.k.key), `adi ${url}`,
  );
  await waitForAccount(page, 'C page');
  await submit(
    new core.Transaction({ header: { principal: f.fLta }, body: { type: 'addCredits', recipient: page, amount: '600000000', oracle: f.oracle } }),
    S.Signer.forLite(f.k.key), 'cr C page',
  );
  await waitForCredits(page, 'C page');
  state.adiC = { url, book, page, seedHex: hex(seed) };
  save();
  return { ...state.adiC, key, f };
}

/** A data account under ADI-B, owned by ADI-B's book AND ADI-C's book. */
async function ensureSharedAccount(C: any) {
  if (state.sharedAccount) return state.sharedAccount;
  const bAdi = String(state.identity.adi_url).replace(/\/$/, '');
  const bBook = `${bAdi}/book`;
  const bPage = String(state.identity.key_page_url);
  const bKey = keyFromSeed(state.bKey.seedHex);
  const url = `${bAdi}/shared`;

  await submit(
    new core.Transaction({
      header: { principal: bAdi },
      body: { type: 'createDataAccount', url, authorities: [bBook, C.book] },
    }),
    S.Signer.forPage(bPage, bKey.key).withVersion((await raw.getSignerInfo(bPage)).version),
    'shared data account',
  );
  await waitForAccount(url, 'shared data account');
  state.sharedAccount = url;
  save();
  return url;
}

async function mint(count: number) {
  const C = await ensureAdiC();
  const shared = await ensureSharedAccount(C);
  state.inboxFixtures = state.inboxFixtures ?? [];

  for (let i = 0; i < count; i++) {
    const v = (await raw.getSignerInfo(C.page)).version;
    const tag = `certen-inbox-${Date.now().toString(36)}-${i}`;
    const tx = new core.Transaction({
      header: { principal: shared, memo: tag },
      body: { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs(String(2000 + i)) } },
    });
    const sig = await S.Signer.forPage(C.page, C.key.key).withVersion(v).sign(tx, { timestamp: nextTs() });
    const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
    const txid = String(r?.result?.[0]?.status?.txID ?? '');
    if (!r.ok || !txid) throw new Error(`inbox mint ${i} failed: ${JSON.stringify(r).slice(0, 400)}`);
    const txHash = txid.replace(/^acc:\/\//, '').split('@')[0];
    state.inboxFixtures.push({ tag, txHash, txid, principal: shared.replace(/^acc:\/\//, ''), used: false });
    save();
    console.log(`minted inbox ${i}: ${txid}`);
    await sleep(1500);
  }
  console.log(`\n${state.inboxFixtures.filter((f: any) => !f.used).length} inbox fixtures pending on ${shared}`);
}

mint(Number(process.argv[2] ?? 2)).catch((e) => { console.error('FAILED:', e?.message ?? e); process.exit(1); });
