/**
 * ECDSA P-256 encodings shared by every hardware and cloud key source. Phase 8 (K3), contract §1.
 *
 * Devices disagree about how an ECDSA signature leaves them: PKCS#11 `CKM_ECDSA` and Azure Key Vault
 * `ES256` return raw `r ‖ s` (64 bytes); AWS KMS and Google Cloud KMS return ASN.1 DER. Accumulate verifies
 * with Go's `ecdsa.VerifyASN1`, which wants DER with minimal INTEGER encodings. One pair of helpers does the
 * conversion both ways, and both directions are strict: a malformed or non-minimal DER is refused rather
 * than repaired, because a signature the network would refuse must not leave this process looking valid.
 *
 * `verifyOwnSignature` is the last check before a signature is returned: whatever the device produced must
 * verify against the public key this signer declares, over exactly the preimage it was given. A device that
 * signed with a different key, or over a hashed-again input, fails here — closed, with a named reason —
 * instead of on the network, where it reads like a key that is not on the page.
 */
import { createPublicKey } from 'node:crypto';
import nacl from 'tweetnacl';
import { p256 } from '@noble/curves/nist.js';

/** P-256 group order n. */
const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

/** SubjectPublicKeyInfo prefix for an uncompressed P-256 point: id-ecPublicKey + prime256v1, BIT STRING(66). */
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

const toBig = (b: Uint8Array): bigint => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));

function encodeInteger(v: Uint8Array): Buffer {
  let i = 0;
  while (i < v.length - 1 && v[i] === 0) i++;
  let body = Buffer.from(v.subarray(i));
  if (body[0]! & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}

/** Raw 64-byte `r ‖ s` to ASN.1 DER. Refuses zero or out-of-range components. */
export function rawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error(`ecdsa: expected a 64-byte raw r||s signature, got ${raw.length} bytes`);
  const r = raw.subarray(0, 32);
  const s = raw.subarray(32);
  for (const [name, x] of [['r', r], ['s', s]] as const) {
    const n = toBig(x);
    if (n === 0n || n >= N) throw new Error(`ecdsa: signature component ${name} is out of range`);
  }
  const seq = Buffer.concat([encodeInteger(r), encodeInteger(s)]);
  return new Uint8Array(Buffer.concat([Buffer.from([0x30, seq.length]), seq]));
}

/** ASN.1 DER to raw 64-byte `r ‖ s`. Strict: exact lengths, minimal INTEGERs, positive, in range, nothing trailing. */
export function derToRaw(der: Uint8Array): Uint8Array {
  const fail = (why: string): never => { throw new Error(`ecdsa: malformed DER signature (${why})`); };
  if (der.length < 8 || der.length > 72) fail(`length ${der.length}`);
  if (der[0] !== 0x30) fail('not a SEQUENCE');
  if (der[1]! & 0x80) fail('long-form length');
  if (der[1] !== der.length - 2) fail('SEQUENCE length does not match');
  let off = 2;
  const out = new Uint8Array(64);
  for (let k = 0; k < 2; k++) {
    if (der[off] !== 0x02) fail('expected INTEGER');
    const len = der[off + 1]!;
    if (len === 0 || len > 33 || off + 2 + len > der.length) fail('INTEGER length');
    const body = der.subarray(off + 2, off + 2 + len);
    if (body[0]! & 0x80) fail('negative INTEGER');
    if (len > 1 && body[0] === 0 && !(body[1]! & 0x80)) fail('non-minimal INTEGER');
    const value = body[0] === 0 && len > 1 ? body.subarray(1) : body;
    if (value.length > 32) fail('INTEGER too large');
    const n = toBig(value);
    if (n === 0n || n >= N) fail('component out of range');
    out.set(value, k * 32 + (32 - value.length));
    off += 2 + len;
  }
  if (off !== der.length) fail('trailing bytes');
  return out;
}

/** An uncompressed P-256 point (65 bytes, 0x04 ‖ X ‖ Y) as PKIX/SPKI DER — the bytes a key page hashes. */
export function p256SpkiFromPoint(point: Uint8Array): Uint8Array {
  if (point.length !== 65 || point[0] !== 0x04) throw new Error('ecdsa: expected an uncompressed 65-byte P-256 point');
  p256.Point.fromBytes(point); // throws unless the point is on the curve
  return new Uint8Array(Buffer.concat([P256_SPKI_PREFIX, Buffer.from(point)]));
}

/** Check that SPKI DER is a P-256 public key, and return the canonical 91-byte encoding. */
export function checkP256Spki(spki: Uint8Array): Uint8Array {
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  } catch {
    throw new Error('ecdsa: public key is not a readable SubjectPublicKeyInfo');
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error(`ecdsa: public key is ${key.asymmetricKeyType}/${key.asymmetricKeyDetails?.namedCurve ?? '?'}, not P-256`);
  }
  const canonical = new Uint8Array(key.export({ format: 'der', type: 'spki' }));
  if (canonical.length !== 91) throw new Error(`ecdsa: unexpected P-256 SPKI length ${canonical.length}`);
  return canonical;
}

/**
 * The signature must verify against the key this signer declares, over exactly this preimage. For P-256 the
 * preimage IS the digest (S6: sha256(sigMdHash ‖ txHash)) and high-S is accepted, as Go's VerifyASN1 does.
 */
export function verifyOwnSignature(type: 'ed25519' | 'ecdsaSha256', publicKey: Uint8Array, preimage32: Uint8Array, sig: Uint8Array): void {
  let ok = false;
  try {
    ok = type === 'ed25519'
      ? nacl.sign.detached.verify(preimage32, sig, publicKey)
      : p256.verify(sig, preimage32, publicKey.subarray(publicKey.length - 65), { prehash: false, format: 'der', lowS: false });
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('the key source returned a signature that does not verify against its own public key over this preimage — refusing it');
}
