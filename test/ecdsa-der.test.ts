/**
 * The DER <-> raw r‖s helpers every hardware and cloud key source shares. Phase 8 (K3), contract §1.2:
 * "the same DER→raw and raw→DER helpers must be used and tested both ways".
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import nacl from 'tweetnacl';
import { checkP256Spki, derToRaw, p256SpkiFromPoint, rawToDer, verifyOwnSignature } from '../src/signer/ecdsa-der.js';

const secret = p256.utils.randomSecretKey();
const point = p256.getPublicKey(secret, false);

describe('ECDSA P-256 encodings', () => {
  it('round-trips raw -> DER -> raw, byte-identical to @noble/curves, including high-S and short components', () => {
    for (let i = 0; i < 300; i++) {
      const digest = new Uint8Array(randomBytes(32));
      const raw = p256.sign(digest, secret, { prehash: false, format: 'compact', lowS: i % 2 === 0 });
      const nobleDer = p256.Signature.fromBytes(raw, 'compact').toBytes('der');
      const der = rawToDer(raw);
      expect(Buffer.from(der).toString('hex')).toBe(Buffer.from(nobleDer).toString('hex'));
      expect(Buffer.from(derToRaw(der)).toString('hex')).toBe(Buffer.from(raw).toString('hex'));
      expect(p256.verify(der, digest, point, { prehash: false, format: 'der', lowS: false })).toBe(true);
    }
    // Components with leading zero bytes, which a random signature produces only rarely: built directly.
    const shortR = Buffer.concat([Buffer.alloc(2), randomBytes(30)]);
    const lowS = Buffer.concat([Buffer.alloc(31), Buffer.from([5])]);
    const raw = new Uint8Array(Buffer.concat([shortR, lowS]));
    const der = rawToDer(raw);
    expect(der.length).toBeLessThan(70);
    expect(Buffer.from(der).toString('hex')).toBe(Buffer.from(p256.Signature.fromBytes(raw, 'compact').toBytes('der')).toString('hex'));
    expect(Buffer.from(derToRaw(der)).equals(Buffer.from(raw))).toBe(true);
  });

  it('refuses malformed or non-minimal DER rather than repairing it', () => {
    // Fixed components with the high bit clear, so every length below is known: r and s are 32 bytes each.
    const raw = new Uint8Array(Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)]));
    const der = Buffer.from(rawToDer(raw));
    expect(der.length).toBe(70);
    expect(() => derToRaw(Buffer.concat([der, Buffer.from([0])]))).toThrow(/SEQUENCE length/);
    const bad = Buffer.from(der); bad[0] = 0x31;
    expect(() => derToRaw(bad)).toThrow(/not a SEQUENCE/);
    // r with an unnecessary leading zero: valid BER, refused by Go's VerifyASN1, refused here.
    const r = Buffer.concat([Buffer.from([0x02, 33, 0x00]), Buffer.alloc(32, 0x11)]);
    const s = Buffer.concat([Buffer.from([0x02, 32]), Buffer.alloc(32, 0x22)]);
    expect(() => derToRaw(Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]))).toThrow(/non-minimal/);
    // A negative INTEGER (high bit set, no zero pad).
    const neg = Buffer.concat([Buffer.from([0x02, 32]), Buffer.alloc(32, 0x91)]);
    expect(() => derToRaw(Buffer.concat([Buffer.from([0x30, neg.length + s.length]), neg, s]))).toThrow(/negative/);
    expect(() => rawToDer(new Uint8Array(64))).toThrow(/out of range/);
    expect(() => rawToDer(new Uint8Array(63))).toThrow(/64-byte/);
  });

  it('builds the same SPKI Node exports, and checks one is P-256', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
    expect(Buffer.from(p256SpkiFromPoint(spki.subarray(26))).equals(Buffer.from(spki))).toBe(true);
    expect(checkP256Spki(spki).length).toBe(91);
    const k1 = generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey.export({ type: 'spki', format: 'der' });
    expect(() => checkP256Spki(new Uint8Array(k1))).toThrow(/not P-256/);
    expect(() => p256SpkiFromPoint(new Uint8Array(65).fill(4))).toThrow();
  });

  it('verifyOwnSignature accepts the right key over the preimage and refuses a re-hashed input or another key', () => {
    const spki = p256SpkiFromPoint(point);
    const pre = new Uint8Array(randomBytes(32));
    const good = p256.sign(pre, secret, { prehash: false, format: 'der', lowS: false });
    expect(() => verifyOwnSignature('ecdsaSha256', spki, pre, good)).not.toThrow();
    const rehashed = p256.sign(pre, secret, { prehash: true, format: 'der' });
    expect(() => verifyOwnSignature('ecdsaSha256', spki, pre, rehashed)).toThrow(/does not verify/);
    const kp = nacl.sign.keyPair();
    const edSig = nacl.sign.detached(pre, kp.secretKey);
    expect(() => verifyOwnSignature('ed25519', kp.publicKey, pre, edSig)).not.toThrow();
    expect(() => verifyOwnSignature('ed25519', nacl.sign.keyPair().publicKey, pre, edSig)).toThrow(/does not verify/);
  });
});
