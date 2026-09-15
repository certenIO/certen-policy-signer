/**
 * AWS KMS adapter against LocalStack. Phase 8.2 (K3), contract §1.2. Runs only when KMS_ENDPOINT is set:
 * `npm run test:kms` starts LocalStack (kms service) in Docker, runs this file, and removes the container.
 *
 * The keys are created HERE, inside LocalStack KMS, and never leave it: the test sees public keys and
 * signatures only. Credentials are LocalStack's documented placeholder values, supplied by the runner.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { CreateKeyCommand, KMSClient, SignCommand, CreateAliasCommand } from '@aws-sdk/client-kms';
import { AwsKmsAdapter, CloudKmsSigner } from '../src/signer/cloud-kms.js';
import { derToRaw, rawToDer } from '../src/signer/ecdsa-der.js';
import { buildPreimage } from '../src/accumulate/signing.js';

const ENDPOINT = process.env.KMS_ENDPOINT;
const REGION = process.env.AWS_REGION ?? 'us-east-1';
const run = ENDPOINT ? describe : describe.skip;

run('AWS KMS adapter (integration, LocalStack)', () => {
  const kms = ENDPOINT ? new KMSClient({ region: REGION, endpoint: ENDPOINT }) : (undefined as unknown as KMSClient);
  const keys: Record<string, string> = {};

  beforeAll(async () => {
    const create = async (name: string, KeySpec: 'ECC_NIST_P256' | 'ECC_SECG_P256K1' | 'SYMMETRIC_DEFAULT', KeyUsage: 'SIGN_VERIFY' | 'ENCRYPT_DECRYPT') => {
      const res = await kms.send(new CreateKeyCommand({ KeySpec, KeyUsage, Description: `FICTIONAL ${name}` }));
      keys[name] = res.KeyMetadata!.KeyId!;
    };
    await create('seat', 'ECC_NIST_P256', 'SIGN_VERIFY');
    await create('k1', 'ECC_SECG_P256K1', 'SIGN_VERIFY');
    await create('sym', 'SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT');
    await kms.send(new CreateAliasCommand({ AliasName: 'alias/machine-orchid-fictional', TargetKeyId: keys.seat }));
  });

  const signer = (keyId: string) => new CloudKmsSigner(new AwsKmsAdapter({ region: REGION, keyId, endpoint: ENDPOINT! }));

  it('reads the SPKI public key and signs the wallet preimage as a DIGEST; the DER verifies by S6', async () => {
    const s = signer('alias/machine-orchid-fictional');
    expect(await s.health()).toBe(true);
    const spki = await s.publicKey();
    expect(spki.length).toBe(91);

    for (let i = 0; i < 6; i++) {
      const txHash = new Uint8Array(32).fill(0x10 + i);
      const pre = buildPreimage(txHash, {
        publicKey: spki, signatureType: 'ecdsaSha256', signerUrl: 'acc://orchid-logistics-fictional.acme/book/2',
        signerVersion: 2, timestamp: 1757894400000000 + i, vote: 'approve',
      });
      const sig = await s.sign(pre.dataForSignature);
      // S6: ECDSA over sha256(sigMdHash ‖ txHash) — which is the preimage — verified AS the digest.
      const digest = createHash('sha256').update(Buffer.concat([pre.sigMdHash, txHash])).digest();
      expect(digest.equals(Buffer.from(pre.dataForSignature))).toBe(true);
      expect(sig[0]).toBe(0x30);
      expect(p256.verify(sig, digest, spki.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(true);
      // And not over a second hash, which MessageType RAW would have produced.
      const rehashed = createHash('sha256').update(digest).digest();
      expect(p256.verify(sig, rehashed, spki.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(false);
    }
  });

  it('KMS DER and the shared helpers agree both ways', async () => {
    const res = await kms.send(new SignCommand({ KeyId: keys.seat, Message: new Uint8Array(32).fill(7), MessageType: 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256' }));
    const der = new Uint8Array(res.Signature!);
    expect(Buffer.from(rawToDer(derToRaw(der))).equals(Buffer.from(der))).toBe(true);
  });

  it('refuses a key whose spec or usage is not ECC_NIST_P256 / SIGN_VERIFY, without signing', async () => {
    await expect(signer(keys.k1!).sign(new Uint8Array(32))).rejects.toThrow(/ECC_SECG_P256K1, not ECC_NIST_P256/);
    await expect(signer(keys.sym!).sign(new Uint8Array(32))).rejects.toThrow(/refusing/);
    expect(await signer(keys.k1!).health()).toBe(false);
  });

  it('fails closed on a key that does not exist', async () => {
    await expect(signer('alias/no-such-key-fictional').sign(new Uint8Array(32))).rejects.toThrow();
  });
});
