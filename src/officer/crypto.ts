/**
 * ECDSA P-256 / SHA-256 verification for personal credentials. FICTIONAL Business Transaction Controls lab, Phase 7.
 *
 * Verification only: this process never holds a human key (contract §1, P3). The public key arrives as SPKI
 * DER, the page entry is `sha256(SPKI)`, and a signature arrives as ASN.1 DER or as WebCrypto's 64-byte r‖s.
 * Every parse is strict and every doubt is a `false` / `undefined` — the callers turn that into a refusal.
 */
import { createHash, createPublicKey } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';

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
