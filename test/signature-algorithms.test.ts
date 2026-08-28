/**
 * The signature envelope, for keys that are not Ed25519.
 *
 * Accumulate verifies RSA-SHA256 and ECDSA-SHA256 natively, and the thing that makes a second algorithm
 * cheap is that the SIGNING PREIMAGE IS THE SAME ONE: sha256(sigMdHash || txnHash) for every key type
 * (protocol/signature_utils.go:50, signingHash). Only the type enum inside the signature metadata moves.
 * This file exists so that a later refactor cannot quietly break that.
 *
 * The vectors in test/fixtures/protocol-signature-vectors.json were produced BY THE GO PROTOCOL — a
 * throwaway program inside C:\Accumulate_Stuff\accumulate-core that built the two signature structs with
 * identical field values and printed their metadata encoding, Metadata().Hash() and signing hash. They are
 * not this repo's arithmetic checked against itself; signedByGo.verifiesInProtocol is Go's own
 * (*EcdsaSha256Signature).Verify saying yes.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import pino from 'pino';
import { p256 } from '@noble/curves/nist.js';
import {
  buildPreimage, buildSignatureObject, buildDelegatedSignatureObject, bytesToHex, hexToBytes, concatBytes,
} from '../src/accumulate/signing.js';
import { LocalSigner, LocalEcdsaP256Signer, KeySigner } from '../src/signer/signer.js';
import { MapKeyring, bookOf } from '../src/signer/keyring.js';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { AccumulateClient, SignerInfo, SubmitResult, PendingTxResult } from '../src/accumulate/client.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
const V: any = JSON.parse(readFileSync(new URL('./fixtures/protocol-signature-vectors.json', import.meta.url), 'utf8'));
const silent = pino({ level: 'silent' });

const TX_HASH_HEX = V.signedByGo.txnHash as string;
const txHash = hexToBytes(TX_HASH_HEX);
const spki = hexToBytes(V.key.publicKeySpkiDer);
const privDer = hexToBytes(V.key.privateKeyDerSec1);
const rawPub = spki.subarray(spki.length - 65);

/** The field values the Go program used. Change one and every vector below stops matching. */
const base = { publicKey: spki, signerUrl: 'acc://demo.acme/book/1', signerVersion: 3, timestamp: 1751630000000000 };
const VOTES = [['approve', 'accept'], ['reject', 'reject'], ['abstain', 'abstain']] as const;

describe('preimage conformance with the Go protocol', () => {
  for (const [vote, goName] of VOTES) {
    for (const sigType of ['ecdsaSha256', 'ed25519'] as const) {
      it(`${sigType}/${vote}: sigMdHash and preimage match the protocol's own vector`, () => {
        const pre = buildPreimage(txHash, { ...base, vote, signatureType: sigType });
        expect(bytesToHex(pre.sigMdHash)).toBe(V[goName][sigType].sigMdHash);
        expect(bytesToHex(pre.dataForSignature)).toBe(V[goName][sigType].preimage);
      });
    }
  }

  it('the preimage is sha256(sigMdHash || txnHash) for every signature type — signature_utils.go:50', () => {
    for (const sigType of ['ecdsaSha256', 'ed25519', 'rsaSha256'] as const) {
      const pre = buildPreimage(txHash, { ...base, vote: 'approve', signatureType: sigType });
      const independent = createHash('sha256').update(Buffer.from(concatBytes(pre.sigMdHash, txHash))).digest('hex');
      expect(bytesToHex(pre.dataForSignature)).toBe(independent);
    }
  });

  it('an ecdsaSha256 preimage is NOT an ed25519 preimage — the type is inside the hash', () => {
    const e = buildPreimage(txHash, { ...base, vote: 'approve', signatureType: 'ecdsaSha256' });
    const d = buildPreimage(txHash, { ...base, vote: 'approve', signatureType: 'ed25519' });
    expect(bytesToHex(e.dataForSignature)).not.toBe(bytesToHex(d.dataForSignature));
    // ...and the difference is exactly one byte of the metadata: the type enum, 0x0f vs 0x02.
    const ee: string = V.accept.ecdsaSha256.metadataEncoding;
    const dd: string = V.accept.ed25519.metadataEncoding;
    expect(ee.length).toBe(dd.length);
    expect([...ee].filter((c, i) => c !== dd[i]).length).toBe(1);
    expect(V.enum.ecdsaSha256).toBe(15);
  });

  it('omitting the signature type still produces the Ed25519 preimage — the ops paths depend on it', () => {
    const implicit = buildPreimage(txHash, { ...base, vote: 'approve' });
    expect(bytesToHex(implicit.dataForSignature)).toBe(V.accept.ed25519.preimage);
  });
});

describe('the signature object carries its algorithm', () => {
  it('an ecdsaSha256 vote object is typed, DER-keyed and DER-signed', async () => {
    const signer = new LocalEcdsaP256Signer(privDer);
    const pre = buildPreimage(txHash, { ...base, vote: 'approve', signatureType: 'ecdsaSha256' });
    const obj = buildSignatureObject(pre, await signer.sign(pre.dataForSignature), TX_HASH_HEX);
    expect(obj.type).toBe('ecdsaSha256');
    expect(obj.publicKey).toBe(V.key.publicKeySpkiDer);   // PKIX/SPKI DER, 91 bytes — not a 32-byte raw key
    expect(hexToBytes(obj.signature)[0]).toBe(0x30);      // ASN.1 DER SEQUENCE
    expect(obj.vote).toBeUndefined();                     // Accept is zero-valued and omitted
    expect(obj.signer).toBe(base.signerUrl);
  });

  it('a reject still names the vote, and the ed25519 object is unchanged', async () => {
    const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));
    const pre = buildPreimage(txHash, { ...base, publicKey: kp.publicKey, vote: 'reject', signatureType: 'ed25519' });
    const obj = buildSignatureObject(pre, nacl.sign.detached(pre.dataForSignature, kp.secretKey), TX_HASH_HEX);
    expect(obj.type).toBe('ed25519');
    expect(obj.vote).toBe('reject');
    expect(obj.signature.length).toBe(128);
  });

  it('a delegated wrapper preserves the inner algorithm — F4 reads this back off the chain', async () => {
    const signer = new LocalEcdsaP256Signer(privDer);
    const pre = buildPreimage(txHash, { ...base, vote: 'approve', signatureType: 'ecdsaSha256', delegators: ['acc://alice.acme/book/1'] });
    const obj: any = buildDelegatedSignatureObject(pre, await signer.sign(pre.dataForSignature), TX_HASH_HEX);
    expect(obj.type).toBe('delegated');
    expect(obj.signature.type).toBe('ecdsaSha256');
  });
});

describe('LocalEcdsaP256Signer', () => {
  const signer = new LocalEcdsaP256Signer(privDer);

  it('declares its own algorithm rather than the seam naming one', () => {
    expect(signer.signatureType).toBe('ecdsaSha256');
    expect(new LocalSigner(new Uint8Array(32).fill(7)).signatureType).toBe('ed25519');
  });

  it('exposes the PKIX DER public key, whose sha256 is the key page entry', async () => {
    const pub = await signer.publicKey();
    expect(bytesToHex(pub)).toBe(V.key.publicKeySpkiDer);
    // protocol/signature.go:1152 — GetPublicKeyHash() is doSha256(s.PublicKey), the same rule as every type.
    expect(createHash('sha256').update(Buffer.from(pub)).digest('hex')).toBe(V.key.publicKeyHash);
  });

  it('signs the 32-byte preimage AS the digest, the way ecdsa.SignASN1 does', async () => {
    const digest = hexToBytes(V.accept.ecdsaSha256.preimage);
    const mine = await signer.sign(digest);
    expect(p256.verify(mine, digest, rawPub, { prehash: false, format: 'der' })).toBe(true);
    // The other direction: a signature Go itself made over the same digest, and verified in Go.
    expect(V.signedByGo.verifiesInProtocol).toBe(true);
    expect(p256.verify(hexToBytes(V.signedByGo.signatureAsn1Der), digest, rawPub, { prehash: false, format: 'der' })).toBe(true);
  });

  it('refuses anything that is not a 32-byte preimage', async () => {
    await expect(signer.sign(new Uint8Array(31))).rejects.toThrow(/32-byte/);
  });
});

/** A submit-capturing client: the envelope is the thing under test, not the network. */
class CapturingClient implements AccumulateClient {
  envelopes: any[] = [];
  async getPendingTx(): Promise<PendingTxResult> { return { found: true }; }
  async getSignerInfo(): Promise<SignerInfo> { return { version: 1, lastUsedOn: 0 }; }
  async listPendingForSigner(): Promise<string[]> { return []; }
  async listPendingViaSignatureChain(): Promise<string[]> { return []; }
  async submit(envelope: unknown): Promise<SubmitResult> { this.envelopes.push(envelope); return { ok: true }; }
}

describe('the vote path signs with whatever the key is', () => {
  const ED_PAGE = 'acc://org.acme/book/1';
  const EC_PAGE = 'acc://org.acme/alice/book/2';
  const tx = (page: string) => ({ txHash: TX_HASH_HEX, signerUrl: page, signerVersion: 3, rawTransaction: { x: 1 }, lastUsedOn: 0, account: 'acc://org.acme/data' });

  const keyring = () => new MapKeyring([
    { page: ED_PAGE, book: bookOf(ED_PAGE), signer: new LocalSigner(new Uint8Array(32).fill(7)) },
    { page: EC_PAGE, book: bookOf(EC_PAGE), signer: new LocalEcdsaP256Signer(privDer) },
  ]);

  it('submits an ecdsaSha256 signature for the page whose key is P-256', async () => {
    const client = new CapturingClient();
    const res = await new DirectVoteBackend(client, keyring(), silent).cast(tx(EC_PAGE), 'approve');
    expect(res.ok).toBe(true);
    const sig = client.envelopes[0].signatures[0];
    expect(sig.type).toBe('ecdsaSha256');
    expect(sig.publicKey).toBe(V.key.publicKeySpkiDer);
    expect(hexToBytes(sig.signature)[0]).toBe(0x30);
  });

  it('and an ed25519 signature for the page whose key is Ed25519 — one process, two algorithms', async () => {
    const client = new CapturingClient();
    await new DirectVoteBackend(client, keyring(), silent).cast(tx(ED_PAGE), 'approve');
    const sig = client.envelopes[0].signatures[0];
    expect(sig.type).toBe('ed25519');
    expect(sig.publicKey.length).toBe(64);
  });

  it('the signature it submits verifies against the preimage the protocol would compute', async () => {
    const client = new CapturingClient();
    await new DirectVoteBackend(client, keyring(), silent).cast(tx(EC_PAGE), 'approve');
    const sig = client.envelopes[0].signatures[0];
    const pre = buildPreimage(txHash, {
      publicKey: spki, signerUrl: EC_PAGE, signerVersion: 3, timestamp: sig.timestamp,
      vote: 'approve', signatureType: 'ecdsaSha256',
    });
    expect(p256.verify(hexToBytes(sig.signature), pre.dataForSignature, rawPub, { prehash: false, format: 'der' })).toBe(true);
  });
});

describe('the key seam names no algorithm', () => {
  it('a KeySigner is anything that declares a type, a key and a sign()', () => {
    const fake: KeySigner = {
      signatureType: 'rsaSha256',
      publicKey: async () => new Uint8Array([1, 2, 3]),
      sign: async () => new Uint8Array([4, 5, 6]),
    };
    const keyring = new MapKeyring([{ page: 'acc://o.acme/book/1', book: 'acc://o.acme/book', signer: fake }]);
    expect(keyring.forPage('acc://o.acme/book/1').signatureType).toBe('rsaSha256');
  });

  it('signer.ts no longer describes its contract as Ed25519', () => {
    const src = readFileSync(new URL('../src/signer/signer.ts', import.meta.url), 'utf8');
    const seam = src.slice(0, src.indexOf('export class'));
    expect(seam).not.toMatch(/32-byte Ed25519 public key|64-byte detached signature/);
  });
});
