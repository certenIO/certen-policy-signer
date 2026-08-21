/**
 * Provision a fixture the BROWSER EXTENSION can sign, and print what the page needs.
 *
 * The last unverified hop in enrollment: the Key Vault extension's `signPendingTransaction`. Its
 * signature construction was verified offline as byte-identical to the local path, but the
 * postMessage round trip, the approval popup and the returned shape have never been exercised.
 *
 * The trick is that the extension holds a key we do not, so the fixture has to be built AROUND it:
 * create an ADI whose key page is keyed to the extension's public key hash, and the extension's key
 * becomes a real authority on it. Then a header-authority transaction against that book is
 * something only the extension can approve.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-kv-browser.ts <keyHashHex> <pubKeyHex>
 *
 * Prints a JSON block for the page: txHash, signer, signerVersion, timestamp, dataForSignature.
 * State: $KV_STATE (defaults to ./kv-browser-state.json)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import {
  raw, query, sleep, submit, core, S, msg, nextTs,
  fundLite, createOrg, waitForAccount, waitForCredits, intentBlobs,
} from './_lib.js';
import { buildPreimage } from '../../src/accumulate/signing.js';

const STATE_PATH = process.env.KV_STATE ?? 'kv-browser-state.json';
const state: any = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const save = () => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (h: string) => new Uint8Array(Buffer.from(h.replace(/^0x/, ''), 'hex'));

const keyHash = (process.argv[2] ?? state.keyHash ?? '').toLowerCase();
const pubKey = (process.argv[3] ?? state.pubKey ?? '').toLowerCase();
if (!/^[0-9a-f]{64}$/.test(keyHash) || !/^[0-9a-f]{64}$/.test(pubKey)) {
  throw new Error('usage: certen-kv-browser.ts <keyHashHex64> <pubKeyHex64>  (from window.certen.selectKey)');
}
state.keyHash = keyHash; state.pubKey = pubKey; save();

async function main() {
  // ── The extension's ADI: key page keyed to ITS hash, so its key really is an authority ────────
  if (!state.ext?.adi) {
    const f = await fundLite();
    const adi = `acc://kvext${Date.now().toString(36)}.acme`;
    const book = `${adi}/book`;
    const page = `${book}/1`;
    // Inline rather than createOrg: that helper derives the key from a seed we choose, and the
    // whole point here is a page keyed to a hash whose PRIVATE half only the extension holds.
    await submit(
      new core.Transaction({
        header: { principal: f.fLite },
        body: { type: 'createIdentity', url: adi, keyHash: bytes(keyHash), keyBookUrl: book },
      }),
      S.Signer.forLite(f.funding.key), `adi ${adi}`,
    );
    await waitForAccount(page, 'extension key page');
    await submit(
      new core.Transaction({
        header: { principal: f.fLta },
        body: { type: 'addCredits', recipient: page, amount: '400000000', oracle: f.oracle },
      }),
      S.Signer.forLite(f.funding.key), `credits ${page}`,
    );
    await waitForCredits(page, 'extension key page');
    state.ext = { adi, book, page };
    save();
    console.log('extension ADI :', adi);
  } else {
    console.log('extension ADI :', state.ext.adi, '(reused)');
  }

  // ── ADI-A initiates a transaction requiring the extension's book ──────────────────────────────
  if (!state.fixture?.txHash) {
    const f2 = await fundLite();
    const adiA = `acc://kva${Date.now().toString(36)}.acme`;
    const A = await createOrg(f2, adiA, 0x45, '400000000');
    const dataAccount = `${adiA}/data`;
    const vA = (await raw.getSignerInfo(A.page)).version;
    await submit(
      new core.Transaction({ header: { principal: adiA }, body: { type: 'createDataAccount', url: dataAccount } }),
      S.Signer.forPage(A.page, A.key.key).withVersion(vA), 'dataAccount',
    );
    await waitForAccount(dataAccount, 'data account');

    const v = (await raw.getSignerInfo(A.page)).version;
    const tx = new core.Transaction({
      header: {
        principal: dataAccount,
        authorities: [state.ext.book],
        memo: 'Enrollment request - Trust Stamp (browser probe)',
      },
      body: { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs('1') } },
    });
    const sig = await S.Signer.forPage(A.page, A.key.key).withVersion(v).sign(tx, { timestamp: nextTs() });
    const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
    const txid = String(r?.result?.[0]?.status?.txID ?? '');
    if (!r.ok || !txid) throw new Error(`submit failed: ${JSON.stringify(r).slice(0, 400)}`);
    const txHash = txid.replace(/^acc:\/\//, '').split('@')[0];
    state.fixture = { adiA, dataAccount, principal: dataAccount.replace(/^acc:\/\//, ''), txHash, txid };
    save();
    console.log('fixture tx    :', txid);

    // Must resolve on the SIGNER's partition before a vote can attach, or the vote is dropped.
    const signerPath = String(state.ext.page).replace(/^acc:\/\//, '');
    for (let i = 0; i < 25; i++) {
      if (await query(`acc://${txHash}@${signerPath}`).catch(() => undefined)) {
        console.log('  resolves on signer partition'); break;
      }
      if (i === 24) throw new Error('never resolved on the signer partition');
      await sleep(5000);
    }
  } else {
    console.log('fixture tx    :', state.fixture.txid, '(reused)');
  }

  // ── What the page hands the extension ─────────────────────────────────────────────────────────
  const version = (await raw.getSignerInfo(state.ext.page)).version;
  const timestamp = Date.now() * 1000;
  const pre = buildPreimage(bytes(state.fixture.txHash), {
    publicKey: bytes(pubKey),
    signerUrl: state.ext.page,
    signerVersion: Number(version),
    timestamp,
    vote: 'approve' as any,
  });

  state.signArgs = {
    transactionHash: state.fixture.txHash,
    dataForSignature: hex(pre.dataForSignature),
    signer: state.ext.page,
    signerVersion: Number(version),
    timestamp,
  };
  save();
  console.log('\n=== hand this to window.certen.signPendingTransaction ===');
  console.log(JSON.stringify(state.signArgs, null, 2));
  console.log('\nprincipal for status polling:', state.fixture.principal);
}

main().catch((e) => { console.error('\nFAILED:', e?.message ?? e); process.exit(1); });
