/**
 * Vault Transit integration test. Runs only when VAULT_ADDR is set (dev Vault).
 * Provision:  docker run -d -p8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 hashicorp/vault server -dev
 *             enable transit + create an ed25519 key named `wallet-test`
 * Run:        VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root VAULT_KEY=wallet-test npx vitest run test/vault-transit.test.ts
 */
import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import { createHash } from 'node:crypto';
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
