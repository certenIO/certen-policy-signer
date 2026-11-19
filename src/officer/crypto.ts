/**
 * ECDSA P-256 / SHA-256 verification for personal credentials. FICTIONAL Business Transaction Controls lab, Phase 7.
 *
 * Verification only: this process never holds a human key (contract §1, P3). The public key arrives as SPKI
 * DER, the page entry is `sha256(SPKI)`, and a signature arrives as ASN.1 DER or as WebCrypto's 64-byte r‖s.
 * Every parse is strict and every doubt is a `false` / `undefined` — the callers turn that into a refusal.
 */
import { createHash, createPublicKey } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';

export interface P256Key {
  /** The SPKI DER exactly as given (and verified canonical). */
  spki: Uint8Array;
  /** Uncompressed SEC1 point, 65 bytes. */
  point: Uint8Array;
  /** sha256(SPKI), lowercase hex — what a key page holds. */
  keyHash: string;
}

export const sha256 = (b: Uint8Array | string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(typeof b === 'string' ? Buffer.from(b, 'utf8') : b).digest());

const HEX = /^(?:[0-9a-fA-F]{2})+$/;
export function hexBytes(h: unknown, maxBytes = 4096): Uint8Array | undefined {
  if (typeof h !== 'string' || !HEX.test(h) || h.length > maxBytes * 2) return undefined;
  return new Uint8Array(Buffer.from(h, 'hex'));
}

/** Parse an SPKI DER P-256 public key. Refuses any other curve or algorithm and any non-canonical encoding. */
export function parseP256Spki(spki: Uint8Array): P256Key | undefined {
  try {
    const k = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    if (k.asymmetricKeyType !== 'ec' || k.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return undefined;
    // Canonical: the page entry is sha256 of these bytes, so two encodings of one key must not both pass.
    const again = new Uint8Array(k.export({ format: 'der', type: 'spki' }));
    if (Buffer.compare(Buffer.from(again), Buffer.from(spki)) !== 0) return undefined;
    const jwk = k.export({ format: 'jwk' }) as { x?: string; y?: string };
    if (!jwk.x || !jwk.y) return undefined;
    const x = Buffer.from(jwk.x, 'base64url'), y = Buffer.from(jwk.y, 'base64url');
    if (x.length !== 32 || y.length !== 32) return undefined;
    const point = new Uint8Array(Buffer.concat([Buffer.from([4]), x, y]));
    return { spki: new Uint8Array(spki), point, keyHash: Buffer.from(sha256(spki)).toString('hex') };
  } catch {
    return undefined;
  }
}

/**
 * Normalise a signature to canonical ASN.1 DER. Accepts canonical DER, or exactly 64 bytes of r‖s.
 * A DER signature that does not re-encode to itself is refused rather than repaired.
 */
export function toCanonicalDer(sig: Uint8Array): Uint8Array | undefined {
  try {
    if (sig.length === 64) return p256.Signature.fromBytes(sig, 'compact').toBytes('der');
    if (sig.length < 8 || sig.length > 72 || sig[0] !== 0x30) return undefined;
    const der = p256.Signature.fromBytes(sig, 'der').toBytes('der');
    return Buffer.compare(Buffer.from(der), Buffer.from(sig)) === 0 ? der : undefined;
  } catch {
    return undefined;
  }
}

/**
 * ECDSA-P256 over SHA-256 of `message`, hashed ONCE (WebCrypto `sign({name:'ECDSA',hash:'SHA-256'}, msg)`,
 * CNG `SignHash(sha256(msg))`, Go `ecdsa.VerifyASN1(pub, sha256(msg), sig)`). High-S is accepted, as Go does.
 */
export function verifyP256Sha256(key: P256Key, message: Uint8Array, signature: Uint8Array): boolean {
  const der = toCanonicalDer(signature);
  if (!der) return false;
  try {
    return p256.verify(der, sha256(message), key.point, { prehash: false, format: 'der', lowS: false });
  } catch {
    return false;
  }
}

// ── ed25519 officer keys (finding AGT-F42). The validators settle ed25519 signatures and refuse ecdsaSha256 (G-42), so an
// officer may hold an ed25519 key. Accumulate (v1.4.6 protocol/signature.go): an ed25519 signature carries the RAW 32-byte public
// key, the page holds sha256(raw key) (GetPublicKeyHash), and it verifies ed25519.Verify(key, sha256(sigMdHash || txHash), sig)
// (signature_utils.go verifySig: doSha256(sigMd, msg)). ──

/** An officer's ed25519 key. `spki` holds the RAW 32-byte key: for both key types `spki` is the bytes the signature's
 * publicKey field carries and whose sha256 is the page entry. */
export interface Ed25519OfficerKey { type: 'ed25519'; spki: Uint8Array; keyHash: string }
export type OfficerKey = (P256Key & { type: 'ecdsaSha256' }) | Ed25519OfficerKey;

/** The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (33) }. */
const ED25519_SPKI_PREFIX = '302a300506032b6570032100';

/** An ed25519 public key as the raw 32 bytes, or as its exact 44-byte RFC 8410 SPKI (WebCrypto's export). Anything else: undefined. */
export function parseEd25519Key(bytes: Uint8Array): Ed25519OfficerKey | undefined {
  let raw: Uint8Array | undefined;
  if (bytes.length === 32) raw = bytes;
  else if (bytes.length === 44 && Buffer.from(bytes.subarray(0, 12)).toString('hex') === ED25519_SPKI_PREFIX) raw = bytes.subarray(12);
  if (!raw) return undefined;
  try {
    // a point that does not decode is not a key (never "verify later")
    ed25519.Point.fromHex(Buffer.from(raw).toString('hex'));
  } catch {
    return undefined;
  }
  const r = new Uint8Array(raw);
  return { type: 'ed25519', spki: r, keyHash: Buffer.from(sha256(r)).toString('hex') };
}

/** A P-256 SPKI or an ed25519 key (raw or SPKI). The two forms cannot collide (a P-256 SPKI is 91 bytes). */
export function parseOfficerKey(bytes: Uint8Array): OfficerKey | undefined {
  const p = parseP256Spki(bytes);
  if (p) return { ...p, type: 'ecdsaSha256' };
  return parseEd25519Key(bytes);
}

/** ed25519 over `message` exactly (RFC 8032, strict: 64-byte signature, canonical S). */
export function verifyEd25519(key: Ed25519OfficerKey, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  try {
    return ed25519.verify(signature, message, key.spki, { zip215: false });
  } catch {
    return false;
  }
}

/** The officer-auth header signature: ECDSA-P256-SHA256 over the message, or ed25519 over the message. */
export function verifyOfficerMessage(key: OfficerKey, message: Uint8Array, signature: Uint8Array): boolean {
  return key.type === 'ed25519' ? verifyEd25519(key, message, signature) : verifyP256Sha256(key, message, signature);
}

/**
 * The officer's signature of a transaction as Accumulate verifies it: ecdsaSha256 = ECDSA-P256 over sha256(sigMd || txHash) (the
 * verifier hashes once); ed25519 = ed25519 over the 32 bytes sha256(sigMd || txHash). Returns the signature bytes to submit
 * (canonical DER for P-256, the 64 raw bytes for ed25519), or undefined when it does not verify.
 */
export function verifyOfficerTxSignature(key: OfficerKey, sigMd: Uint8Array, txHash: Uint8Array, signature: Uint8Array): Uint8Array | undefined {
  const preimage = new Uint8Array(sigMd.length + txHash.length);
  preimage.set(sigMd, 0);
  preimage.set(txHash, sigMd.length);
  if (key.type === 'ed25519') return verifyEd25519(key, sha256(preimage), signature) ? new Uint8Array(signature) : undefined;
  const der = toCanonicalDer(signature);
  if (!der) return undefined;
  return verifyP256Sha256(key, preimage, der) ? der : undefined;
}
