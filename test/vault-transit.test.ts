/**
 * Vault Transit integration test. Runs only when VAULT_ADDR is set (dev Vault).
 * Provision:  docker run -d -p8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 hashicorp/vault server -dev
 *             enable transit + create an ed25519 key named `wallet-test`
 * Run:        VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root VAULT_KEY=wallet-test npx vitest run test/vault-transit.test.ts
 */
import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import { createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { VaultTransitSigner } from '../src/signer/vault-transit.js';
import { buildPreimage } from '../src/accumulate/signing.js';

const ADDR = process.env.VAULT_ADDR;
const run = ADDR ? describe : describe.skip;

run('VaultTransitSigner (integration, live dev Vault)', () => {
  // constructed lazily: when ADDR is unset the suite is skipped, so this is never used
  const signer = ADDR
    ? new VaultTransitSigner({ addr: ADDR, keyName: process.env.VAULT_KEY ?? 'wallet-test', token: process.env.VAULT_TOKEN ?? 'root' })
    : (undefined as unknown as VaultTransitSigner);

  it('health() is true and returns a 32-byte ed25519 public key', async () => {
    expect(await signer.health()).toBe(true);
    const pub = await signer.publicKey();
    expect(pub.length).toBe(32);
  });

  it('signs a 32-byte message; the signature is network-valid (verifies against the pubkey)', async () => {
    const pub = await signer.publicKey();
    const msg = new Uint8Array(32).fill(0x42);
    const sig = await signer.sign(msg);
    expect(sig.length).toBe(64);
    expect(nacl.sign.detached.verify(msg, sig, pub)).toBe(true);
  });

  it('signs the real wallet preimage; Vault output verifies (proves the provider is byte-correct)', async () => {
    const pub = await signer.publicKey();
    const txHash = new Uint8Array(32).fill(0xab);
    const pre = buildPreimage(txHash, { publicKey: pub, signerUrl: 'acc://demo.acme/book/1', signerVersion: 1, timestamp: 1751630000000000, vote: 'approve' });
    const sig = await signer.sign(pre.dataForSignature);
    expect(nacl.sign.detached.verify(pre.dataForSignature, sig, pub)).toBe(true);
    // the key hash the operator registers on the Accumulate page (SR6 self-check):
    expect(createHash('sha256').update(pub).digest('hex')).toHaveLength(64);
  });
});

/**
 * The same provider holding a P-256 key. Runbook F Phase F2.
 *
 * The unit tests in test/vault-ecdsa.test.ts prove this against a stub that answers the way a real
 * Vault was observed to answer. This proves it against the real thing, which is the only way to know
 * that observation still holds: both differences from the Ed25519 path -- a PEM public key and a
 * signature that must be asked for over a PREHASHED input -- are ones a stub would happily reproduce
 * wrongly forever.
 *
 * `npm run test:vault` provisions the ecdsa-p256 key this needs, alongside the ed25519 one.
 */
run('VaultTransitSigner with an ecdsa-p256 key (integration, live dev Vault)', () => {
  const signer = ADDR
    ? new VaultTransitSigner({
        addr: ADDR,
        keyName: process.env.VAULT_EC_KEY ?? 'wallet-test-p256',
        token: process.env.VAULT_TOKEN ?? 'root',
        keyType: 'ecdsa-p256',
      })
    : (undefined as unknown as VaultTransitSigner);

  it('declares ecdsaSha256 and returns a 91-byte PKIX public key, decoded from Vault PEM', async () => {
    expect(signer.signatureType).toBe('ecdsaSha256');
    expect(await signer.health()).toBe(true);
    const pub = await signer.publicKey();
    expect(pub.length).toBe(91);
    // What the operator puts on the key page. sha256(publicKey) for every signature type alike.
    expect(createHash('sha256').update(pub).digest('hex')).toHaveLength(64);
  });

  it('signs the real wallet preimage AS a digest, and Vault output verifies over it', async () => {
    const pub = await signer.publicKey();
    const txHash = new Uint8Array(32).fill(0xcd);
    const pre = buildPreimage(txHash, {
      publicKey: pub,
      signerUrl: 'acc://demo.acme/roster/1',
      signerVersion: 1,
      timestamp: 1751630000000000,
      vote: 'approve',
      signatureType: 'ecdsaSha256',
    });
    const sig = await signer.sign(pre.dataForSignature);

    expect(sig[0]).toBe(0x30);
    const point = pub.subarray(pub.length - 65);
    // lowS: false, and this is not a loosened assertion -- it is the network's own rule. Accumulate
    // verifies with Go's `ecdsa.VerifyASN1` (protocol/signature.go), which does not require a
    // canonical low-S value, and Vault emits high-S signatures about half the time: 3 of 8, measured.
    // A verifier stricter than the chain would fail this test for every other signature, at random.
    expect(p256.verify(sig, pre.dataForSignature, point, { prehash: false, format: 'der', lowS: false })).toBe(true);

    // And NOT over a second hash of the preimage, which is what `prehashed: false` would have signed:
    // a valid ECDSA signature over the wrong message, refused by the network for reasons that read
    // like a key that is not on the page.
    const rehashed = new Uint8Array(createHash('sha256').update(pre.dataForSignature).digest());
    expect(p256.verify(sig, rehashed, point, { prehash: false, format: 'der', lowS: false })).toBe(false);
  });

  it('refuses a key whose type in Vault is not the one it was configured for', async () => {
    const mismatched = new VaultTransitSigner({
      addr: ADDR!,
      keyName: process.env.VAULT_EC_KEY ?? 'wallet-test-p256',
      token: process.env.VAULT_TOKEN ?? 'root',
      // the default, and wrong for this key
    });
    await expect(mismatched.publicKey()).rejects.toThrow(/ecdsa-p256/);
  });
});
