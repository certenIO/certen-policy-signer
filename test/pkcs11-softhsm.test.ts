/**
 * The pkcs11 provider against a real PKCS#11 token: SoftHSM2 in Docker. Phase 8.1 (K3), contract §1.1.
 *
 * Runs only inside the container `npm run test:pkcs11` builds (test/docker/softhsm): it needs PKCS11_MODULE,
 * the throwaway PKCS11_PIN generated there, and the pkcs11js addon compiled by scripts/build-pkcs11js.sh. On
 * any other host it skips. The keys were generated inside the token by provision.mjs; this file sees public
 * keys and signatures only. All labels and parties are FICTIONAL.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Writable } from 'node:stream';
import { createHash, randomBytes } from 'node:crypto';
import pino from 'pino';
import nacl from 'tweetnacl';
import { p256 } from '@noble/curves/nist.js';
import { Pkcs11Signer, Pkcs11KeyType } from '../src/signer/pkcs11.js';
import { buildPreimage } from '../src/accumulate/signing.js';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { startCustodianStub } from './support/pin-custodian-stub.js';

const MODULE = process.env.PKCS11_MODULE;
const TOKEN = process.env.PKCS11_TOKEN_LABEL ?? 'orchid-seat-fictional';
const PIN = process.env.PKCS11_PIN;
const run = MODULE && PIN ? describe : describe.skip;

const PAGE = 'acc://orchid-logistics-fictional.acme/book/2';
const PRINCIPAL = 'acc://bank-fictional.acme/payments';
const ED = 'machine-orchid-ed25519-fictional';
const EC = 'machine-orchid-p256-fictional';

run('Pkcs11Signer (integration, SoftHSM2)', () => {
  const lines: string[] = [];
  const logger = pino({ level: 'trace' }, new Writable({ write(c, _e, cb) { lines.push(String(c)); cb(); } }));
  const errors: string[] = [];
  const HMAC = randomBytes(16).toString('hex');
  const approved = new Set<string>();
  let custodian: Awaited<ReturnType<typeof startCustodianStub>>;

  const withPin = (keyLabel: string, keyType: Pkcs11KeyType) =>
    new Pkcs11Signer({ module: MODULE!, tokenLabel: TOKEN, keyLabel, keyType, pin: PIN!, logger });
  const withSource = (keyLabel: string, keyType: Pkcs11KeyType) =>
    new Pkcs11Signer({ module: MODULE!, tokenLabel: TOKEN, keyLabel, keyType, pinSource: { url: custodian.url, hmacSecret: HMAC, timeoutMs: 3000 }, logger });
  const preimage = (pub: Uint8Array, type: 'ed25519' | 'ecdsaSha256', txHash = new Uint8Array(randomBytes(32))) =>
    Object.assign(buildPreimage(txHash, { publicKey: pub, signatureType: type, signerUrl: PAGE, signerVersion: 2, timestamp: 1757894400000000, vote: 'approve' }), { txHash });
  const keep = async <T>(p: Promise<T>): Promise<T> => p.catch((e: Error) => { errors.push(e.message); throw e; });

  beforeAll(async () => {
    custodian = await startCustodianStub({ hmacSecret: HMAC, pin: () => PIN!, page: PAGE, keyLabel: EC, approved });
  });
  afterAll(async () => {
    await custodian?.close();
  });

  it('Ed25519 (CKM_EDDSA): raw 32-byte public key; the signature over the preimage verifies', async () => {
    const s = withPin(ED, 'ed25519');
    expect(await s.health()).toBe(true);
    const pub = await s.publicKey();
    expect(pub.length).toBe(32);
    const pre = preimage(pub, 'ed25519');
    const sig = await s.sign(pre.dataForSignature);
    expect(sig.length).toBe(64);
    expect(nacl.sign.detached.verify(pre.dataForSignature, sig, pub)).toBe(true);
  });

  it('P-256 (CKM_ECDSA over the digest): SPKI public key; raw r||s becomes DER that verifies by S6', async () => {
    const s = withPin(EC, 'ecdsa-p256');
    const pub = await s.publicKey();
    expect(pub.length).toBe(91);
    for (let i = 0; i < 8; i++) {
      const pre = preimage(pub, 'ecdsaSha256');
      const sig = await s.sign(pre.dataForSignature);
      const digest = createHash('sha256').update(Buffer.concat([pre.sigMdHash, pre.txHash])).digest();
      expect(digest.equals(Buffer.from(pre.dataForSignature))).toBe(true);
      expect(sig[0]).toBe(0x30);
      expect(p256.verify(sig, digest, pub.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(true);
      expect(p256.verify(sig, createHash('sha256').update(digest).digest(), pub.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(false);
    }
  });

  it('refuses to start on an extractable key, and on a non-sensitive key', async () => {
    await expect(keep(withPin('extractable-p256-fictional', 'ecdsa-p256').publicKey())).rejects.toThrow(/CKA_EXTRACTABLE is not false/);
    await expect(keep(withPin('insensitive-p256-fictional', 'ecdsa-p256').publicKey())).rejects.toThrow(/CKA_SENSITIVE is not true/);
    expect(await withPin('extractable-p256-fictional', 'ecdsa-p256').health()).toBe(false);
  });

  it('refuses a key declared as the wrong type, and a wrong PIN', async () => {
    await expect(keep(withPin(ED, 'ecdsa-p256').publicKey())).rejects.toThrow(/not an ecdsa-p256 key/);
    const wrong = new Pkcs11Signer({ module: MODULE!, tokenLabel: TOKEN, keyLabel: EC, keyType: 'ecdsa-p256', pin: 'not-the-pin-0000', logger });
    await expect(keep(wrong.publicKey())).rejects.toThrow(/PIN_INCORRECT/);
  });

  it('pin_source: the custodian releases the PIN per approved transaction; the token signs; nothing is cached', async () => {
    const s = withSource(EC, 'ecdsa-p256');
    const pub = await s.publicKey();
    const before = custodian.seen.length;
    for (let i = 0; i < 2; i++) {
      const pre = preimage(pub, 'ecdsaSha256');
      const tx = Buffer.from(pre.txHash).toString('hex');
      approved.add(tx);
      const sig = await s.sign(pre.dataForSignature, { txHash: tx, principal: PRINCIPAL, page: PAGE });
      expect(p256.verify(sig, pre.dataForSignature, pub.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(true);
      expect(custodian.seen.at(-1)).toMatchObject({ result: 'released', body: { txHash: tx, principal: PRINCIPAL, page: PAGE, keyLabel: EC } });
    }
    expect(custodian.seen.length - before).toBe(2);
  });

  it('pin_source: a custodian refusal produces no signature and the vote is withheld', async () => {
    const s = withSource(EC, 'ecdsa-p256');
    await s.publicKey();
    const tx = randomBytes(32).toString('hex'); // no approve decision
    await expect(keep(s.sign(new Uint8Array(32).fill(3), { txHash: tx, principal: PRINCIPAL, page: PAGE }))).rejects.toThrow(/refused \(HTTP 403\)/);

    let submitted = 0;
    const acc = { getSignerInfo: async () => ({ version: 2, lastUsedOn: 0, creditBalance: 1 }), submit: async () => { submitted++; return { ok: true }; } } as never;
    const res = await new DirectVoteBackend(acc, singleKeyring(s, PAGE), logger)
      .cast({ txHash: tx, signerUrl: PAGE, signerVersion: 2, rawTransaction: {}, lastUsedOn: 0, account: PRINCIPAL }, 'approve');
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/signing failed: .*refused/);
    expect(submitted).toBe(0);
    if (res.error) errors.push(res.error);
  });

  it('pin_source: an unreachable custodian is a signing failure, not a signature', async () => {
    const s = new Pkcs11Signer({ module: MODULE!, tokenLabel: TOKEN, keyLabel: EC, keyType: 'ecdsa-p256', pinSource: { url: 'http://127.0.0.1:9/v1/pin', hmacSecret: HMAC, timeoutMs: 500 }, logger });
    await s.publicKey();
    await expect(keep(s.sign(new Uint8Array(32).fill(4), { txHash: 'ab'.repeat(32), principal: PRINCIPAL, page: PAGE }))).rejects.toThrow(/unreachable/);
  });

  it('the PIN appears in no log line and no error message', () => {
    expect(lines.length).toBeGreaterThan(0);
    expect(errors.length).toBeGreaterThan(0);
    const everything = [...lines, ...errors].join('\n');
    expect(everything).not.toContain(PIN!);
  });
});
