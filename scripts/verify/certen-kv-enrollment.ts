/**
 * A REAL enrollment transaction, shaped the way Trust Stamp would actually send one.
 *
 * The earlier browser test reused `intentBlobs()` from the gateway fixtures, which mints the 4-blob
 * CERTEN_INTENT payload. That proved the signing mechanism but made the explorer entry meaningless:
 * four JSON documents about cross-chain legs and governance, none of it about an enrollment.
 *
 * What carries the security is the HEADER, not the body:
 *   authorities[] — Accumulate will not deliver until the named key book approves to its threshold
 *   expire        — an unsigned enrollment lapses instead of hanging around
 *   memo          — the only thing the signer sees in their inbox saying what this IS
 * The body is the RECORD. One small self-describing entry, so someone reading the explorer later
 * can tell what happened without Trust Stamp's database.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-kv-enrollment.ts <keyHash> <pubKey> [adiUrl]
 *
 * With <adiUrl> it enrolls an EXISTING ADI. Without, it provisions one keyed to <keyHash> first.
 * State: $KV_STATE (default ./kv-enrollment-state.json)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import {
  raw, query, sleep, submit, core, S, msg, nextTs,
  fundLite, createOrg, waitForAccount, waitForCredits,
} from './_lib.js';
import nacl from 'tweetnacl';
import { buildPreimage } from '../../src/accumulate/signing.js';

/**
 * Rebuild a key from a stored seed.
 *
 * NOT `ed(seedFill)` — that generates `nacl.randomBytes(32)` and merely stamps the fill into byte 0,
 * so two calls with the same fill produce DIFFERENT keys. Calling it twice to "recover" an identity's
 * key yields a key the page has never heard of, and the node rejects the signature with
 * `unauthorized: key does not belong to signer`. Persist the seed instead.
 */
function keyFromSeed(seedHex: string) {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(seedHex, 'hex')));
  const key = (S as any).ED25519Key.from
    ? (S as any).ED25519Key.from(kp.secretKey)
    : new (S as any).ED25519Key(kp.secretKey);
  return { kp, key, pub: kp.publicKey };
}

const STATE_PATH = process.env.KV_STATE ?? 'kv-enrollment-state.json';
const state: any = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const save = () => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (h: string) => new Uint8Array(Buffer.from(h.replace(/^0x/, ''), 'hex'));

const keyHash = (process.argv[2] ?? state.keyHash ?? '').toLowerCase();
const pubKey = (process.argv[3] ?? state.pubKey ?? '').toLowerCase();
const givenAdi = process.argv[4] ?? state.subjectAdi;
if (!/^[0-9a-f]{64}$/.test(keyHash) || !/^[0-9a-f]{64}$/.test(pubKey)) {
  throw new Error('usage: certen-kv-enrollment.ts <keyHash64> <pubKey64> [adiUrl]');
}
state.keyHash = keyHash; state.pubKey = pubKey; save();

/** Trust Stamp's enrollment window. Short on purpose: a stale half-finished enrollment is a ticket. */
const WINDOW_SECONDS = 4 * 60 * 60;

async function main() {
  // ── The subject: an ADI whose key page holds the enrollee's key ───────────────────────────────
  if (!state.subject?.book) {
    if (givenAdi) {
      const book = `${String(givenAdi).replace(/\/$/, '')}/book`;
      state.subject = { adi: givenAdi, book, page: `${book}/1` };
    } else {
      const f = await fundLite();
      const adi = `acc://member${Date.now().toString(36)}.acme`;
      const book = `${adi}/book`, page = `${book}/1`;
      await submit(
        new core.Transaction({
          header: { principal: f.fLite },
          body: { type: 'createIdentity', url: adi, keyHash: bytes(keyHash), keyBookUrl: book },
        }),
        S.Signer.forLite(f.funding.key), `adi ${adi}`,
      );
      await waitForAccount(page, 'member key page');
      await submit(
        new core.Transaction({
          header: { principal: f.fLta },
          body: { type: 'addCredits', recipient: page, amount: '400000000', oracle: f.oracle },
        }),
        S.Signer.forLite(f.funding.key), `credits ${page}`,
      );
      await waitForCredits(page, 'member key page');
      state.subject = { adi, book, page };
    }
    save();
  }
  console.log('member ADI    :', state.subject.adi);

  // ── Trust Stamp's own identity and the account its enrollment records live on ─────────────────
  if (!state.ts?.dataAccount) {
    const f = await fundLite();
    const adi = `acc://trust-stamp-${Date.now().toString(36)}.acme`;
    const T = await createOrg(f, adi, 0x55, '400000000');
    const dataAccount = `${adi}/enrollments`;
    const v = (await raw.getSignerInfo(T.page)).version;
    await submit(
      new core.Transaction({ header: { principal: adi }, body: { type: 'createDataAccount', url: dataAccount } }),
      S.Signer.forPage(T.page, T.key.key).withVersion(v), 'enrollments account',
    );
    await waitForAccount(dataAccount, 'enrollments account');
    state.ts = { adi, page: T.page, seedHex: hex(T.key.seed), dataAccount };
    save();
  }
  console.log('Trust Stamp   :', state.ts.dataAccount);

  // ── The enrollment transaction ────────────────────────────────────────────────────────────────
  if (!state.enrollment?.txHash) {
    const enrollmentId = `ts-${Date.now().toString(36)}`;
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + WINDOW_SECONDS * 1000);

    // The RECORD. Self-describing so the explorer entry means something on its own; `enrollmentId`
    // is the only load-bearing field — it ties this to Trust Stamp's row and stops an already
    // executed enrollment being replayed as a fresh one.
    const entry = JSON.stringify({
      v: 1,
      kind: 'certen.enrollment',
      provider: 'trust-stamp',
      enrollmentId,
      adi: state.subject.adi,
      keyBook: state.subject.book,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    });

    // Rebuild Trust Stamp's key from the seed we stored at creation.
    const T = keyFromSeed(state.ts.seedHex);
    const v = (await raw.getSignerInfo(state.ts.page)).version;

    const tx = new core.Transaction({
      header: {
        principal: state.ts.dataAccount,
        // The security property, in one field: Accumulate will not deliver this until the member's
        // key book approves to its own threshold. Nothing in the body can substitute for it.
        authorities: [state.subject.book],
        expire: { atTime: expiresAt },
        // What the member sees in `certen pending list` — the only thing telling them what this is.
        memo: `Enrollment request - Trust Stamp (${enrollmentId})`,
      },
      body: { type: 'writeData', entry: { type: 'doubleHash', data: [Buffer.from(entry, 'utf8')] } },
    });
    const sig = await S.Signer.forPage(state.ts.page, T.key).withVersion(v)
      .sign(tx, { timestamp: nextTs() });
    const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
    const txid = String(r?.result?.[0]?.status?.txID ?? '');
    if (!r.ok || !txid) throw new Error(`submit failed: ${JSON.stringify(r).slice(0, 400)}`);
    const txHash = txid.replace(/^acc:\/\//, '').split('@')[0];

    state.enrollment = {
      enrollmentId, txHash, txid, entry,
      principal: state.ts.dataAccount.replace(/^acc:\/\//, ''),
      expiresAt: expiresAt.toISOString(),
    };
    save();
    console.log('enrollment tx :', txid);
    console.log('memo          :', `Enrollment request - Trust Stamp (${enrollmentId})`);

    const signerPath = String(state.subject.page).replace(/^acc:\/\//, '');
    for (let i = 0; i < 25; i++) {
      if (await query(`acc://${txHash}@${signerPath}`).catch(() => undefined)) {
        console.log('  resolves on the member partition'); break;
      }
      if (i === 24) throw new Error('never resolved on the member partition');
      await sleep(5000);
    }
  } else {
    console.log('enrollment tx :', state.enrollment.txid, '(reused)');
  }

  // ── What the member's browser hands the Key Vault ─────────────────────────────────────────────
  const version = (await raw.getSignerInfo(state.subject.page)).version;
  const timestamp = Date.now() * 1000;
  const pre = buildPreimage(bytes(state.enrollment.txHash), {
    publicKey: bytes(pubKey),
    signerUrl: state.subject.page,
    signerVersion: Number(version),
    timestamp,
    vote: 'approve' as any,
  });
  state.signArgs = {
    transactionHash: state.enrollment.txHash,
    dataForSignature: hex(pre.dataForSignature),
    signer: state.subject.page,
    signerVersion: Number(version),
    timestamp,
  };
  state.fixture = { principal: state.enrollment.principal };
  save();

  console.log('\n=== window.certen.signHash ===');
  console.log(JSON.stringify({
    hash: state.signArgs.dataForSignature,
    address: state.signArgs.signer,
    keyType: 'ed25519',
  }, null, 2));
  console.log('\nentry written :', state.enrollment.entry);
  console.log('explorer      : https://explorer.accumulatenetwork.io/tx/' + state.enrollment.txHash);
}

main().catch((e) => { console.error('\nFAILED:', e?.message ?? e); process.exit(1); });
