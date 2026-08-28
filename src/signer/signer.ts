/**
 * KeySigner: the pluggable key-custody boundary. Implementations never leak the private key.
 *
 * The seam names no algorithm. Accumulate verifies Ed25519, ECDSA-SHA256 (P-256 and friends) and
 * RSA-SHA256 with the SAME signing preimage — `sha256(sigMdHash || txnHash)`, protocol/signature_utils.go
 * `signingHash` — so what varies between key types is only three things, and each of them lives here:
 *
 *   signatureType   the enum that goes inside the signature metadata, and therefore inside the hash
 *   publicKey()     the bytes the network hashes to find the key on the page — sha256(publicKey) for
 *                   every type alike (protocol/signature.go, GetPublicKeyHash), so DER in, DER hashed
 *   sign()          32 bytes in; whatever that algorithm's signature encoding is, out
 *
 * Whoever produces those bytes — a key in this process, a Vault Transit key, a smartcard behind a local
 * agent, a bank's remote signing service — implements this one interface and nothing above it changes.
 */
import { createPrivateKey, createPublicKey, KeyObject } from 'node:crypto';
import nacl from 'tweetnacl';
import { p256 } from '@noble/curves/nist.js';

/**
 * The Accumulate signature types this signer can produce, by their protocol wire names
 * (protocol/enums_gen.go: ed25519 = 2, rsaSha256 = 14, ecdsaSha256 = 15).
 */
export type AccumulateSignatureType = 'ed25519' | 'ecdsaSha256' | 'rsaSha256';

export interface KeySigner {
  /** Which Accumulate signature this key produces. Goes into the metadata, so it is part of the preimage. */
  readonly signatureType: AccumulateSignatureType;
  /** The public key in the encoding its signature type carries — raw for Ed25519, PKIX/SPKI DER for ECDSA. */
  publicKey(): Promise<Uint8Array>;
  /** Sign the 32-byte preimage. The 32 bytes ARE the digest; nothing here hashes them again. */
  sign(preimage32: Uint8Array): Promise<Uint8Array>;
  /** Optional readiness probe (e.g. can reach Vault). */
  health?(): Promise<boolean>;
}

/**
 * The Ed25519 case of a KeySigner. Kept as a narrow alias so the ~dozen call sites that legitimately mean
 * "the org's Ed25519 governance key" — src/ops/, the rotation tooling — read the same as they did.
 */
export type EdSigner = KeySigner;

/**
 * LocalSigner — ed25519 via tweetnacl from a 32-byte seed.
 *
 * The PILOT key posture: the key is held in this process, from an `env:` ref or a mounted secret file.
 * That is a real, documented tradeoff rather than a test-only path (deploy/config.pilot.yaml and the Helm
 * chart both ship it) — but the key is readable by anything that can read this process's memory. For
 * production, VaultTransitSigner keeps the key inside Vault. See README "Security posture".
 */
export class LocalSigner implements KeySigner {
  readonly signatureType = 'ed25519' as const;
  private readonly kp: nacl.SignKeyPair;
  constructor(seed32: Uint8Array) {
    if (seed32.length !== 32) throw new Error('LocalSigner seed must be 32 bytes');
    this.kp = nacl.sign.keyPair.fromSeed(seed32);
  }
  static generate(): LocalSigner {
    return new LocalSigner(nacl.randomBytes(32));
  }
  async publicKey(): Promise<Uint8Array> { return this.kp.publicKey; }
  async sign(message32: Uint8Array): Promise<Uint8Array> {
    if (message32.length !== 32) throw new Error('expected 32-byte message');
    return nacl.sign.detached(message32, this.kp.secretKey);
  }
  async health(): Promise<boolean> { return true; }
}

/**
 * LocalEcdsaP256Signer — ECDSA P-256 from a DER private key held in this process.
 *
 * The same pilot posture as LocalSigner, and the same caveat: the key is readable by anything that can
 * read this process's memory. It exists so the envelope can be proven end to end against a real network
 * with a real PKI key type before any custody decision is made — F2 puts the key in Vault, F6 chooses
 * between that, a smartcard behind a local agent, and a bank's remote signing service.
 *
 * Two implementation notes that are not obvious and are load-bearing:
 *
 * - **The public key is PKIX/SPKI DER.** The network verifies with `x509.ParsePKIXPublicKey`
 *   (protocol/signature.go, EcdsaSha256Signature.Verify). The doc comment beside it says PKCS#1; the
 *   code does not, and the code is what runs. The page entry is `sha256` of exactly these bytes.
 * - **Node cannot do this.** `crypto.sign(null, digest, ecKey)` hashes the input again — Node has no
 *   raw-digest ECDSA — whereas Accumulate hands `ecdsa.SignASN1` the 32-byte preimage AS the digest.
 *   Hence @noble/curves for the one operation Node lacks; Node still parses and exports the DER, which
 *   is the part where getting it wrong would be silent.
 */
export class LocalEcdsaP256Signer implements KeySigner {
  readonly signatureType = 'ecdsaSha256' as const;
  private readonly scalar: Uint8Array;
  private readonly spkiDer: Uint8Array;

  /** `privateKeyDer` may be SEC1 (`-----BEGIN EC PRIVATE KEY-----` in DER form) or PKCS#8 — both occur. */
  constructor(privateKeyDer: Uint8Array) {
    const key = LocalEcdsaP256Signer.parse(privateKeyDer);
    const jwk = key.export({ format: 'jwk' }) as { crv?: string; d?: string };
    if (jwk.crv !== 'P-256') throw new Error(`LocalEcdsaP256Signer: expected a P-256 key, got curve ${jwk.crv ?? 'unknown'}`);
    if (!jwk.d) throw new Error('LocalEcdsaP256Signer: that DER holds no private key');
    this.scalar = new Uint8Array(Buffer.from(jwk.d, 'base64url'));
    this.spkiDer = new Uint8Array(createPublicKey(key).export({ format: 'der', type: 'spki' }));
  }

  private static parse(der: Uint8Array): KeyObject {
    for (const type of ['sec1', 'pkcs8'] as const) {
      try { return createPrivateKey({ key: Buffer.from(der), format: 'der', type }); } catch { /* try the other */ }
    }
    throw new Error('LocalEcdsaP256Signer: could not read that DER as a SEC1 or PKCS#8 private key');
  }

  async publicKey(): Promise<Uint8Array> { return this.spkiDer; }

  async sign(preimage32: Uint8Array): Promise<Uint8Array> {
    if (preimage32.length !== 32) throw new Error('expected 32-byte message');
    // prehash:false — the preimage IS the digest. Hashing it again would produce a signature the
    // network rejects, and it would look like a key-page problem rather than an encoding one.
    return p256.sign(preimage32, this.scalar, { prehash: false, format: 'der' });
  }

  async health(): Promise<boolean> { return true; }
}
