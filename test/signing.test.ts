import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import {
  buildPreimage,
  buildSignatureObject,
  computeTimestamp,
  bytesToHex,
} from '../src/accumulate/signing.js';

describe('accumulate signing', () => {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));
  const txHash = new Uint8Array(32).fill(0xab);
  const base = {
    publicKey: kp.publicKey,
    signerUrl: 'acc://demo.acme/book/1',
    signerVersion: 3,
    timestamp: 1751630000000000,
  };

  it('produces a valid, deterministic 32-byte preimage and 64-byte signature (approve)', () => {
    const p1 = buildPreimage(txHash, { ...base, vote: 'approve' });
    const p2 = buildPreimage(txHash, { ...base, vote: 'approve' });
    expect(p1.dataForSignature.length).toBe(32);
    expect(bytesToHex(p1.dataForSignature)).toBe(bytesToHex(p2.dataForSignature));

    const sig = nacl.sign.detached(p1.dataForSignature, kp.secretKey);
    expect(sig.length).toBe(64);
    expect(nacl.sign.detached.verify(p1.dataForSignature, sig, kp.publicKey)).toBe(true);
  });

  it('reject and abstain preimages differ from approve and each other', () => {
    const a = bytesToHex(buildPreimage(txHash, { ...base, vote: 'approve' }).dataForSignature);
    const r = bytesToHex(buildPreimage(txHash, { ...base, vote: 'reject' }).dataForSignature);
    const ab = bytesToHex(buildPreimage(txHash, { ...base, vote: 'abstain' }).dataForSignature);
    expect(r).not.toBe(a);
    expect(ab).not.toBe(a);
    expect(ab).not.toBe(r);
  });

  it('changing signerVersion or timestamp changes the preimage', () => {
    const a = bytesToHex(buildPreimage(txHash, { ...base, vote: 'approve' }).dataForSignature);
    const v = bytesToHex(buildPreimage(txHash, { ...base, signerVersion: 4, vote: 'approve' }).dataForSignature);
    const t = bytesToHex(buildPreimage(txHash, { ...base, timestamp: base.timestamp + 1, vote: 'approve' }).dataForSignature);
    expect(v).not.toBe(a);
    expect(t).not.toBe(a);
  });

  it('signature object: 128-hex sig, 64-hex pubkey, vote omitted for approve, set for reject', () => {
    const a = buildPreimage(txHash, { ...base, vote: 'approve' });
    const sa = buildSignatureObject(a, nacl.sign.detached(a.dataForSignature, kp.secretKey), bytesToHex(txHash));
    expect(sa.signature.length).toBe(128);
    expect(sa.publicKey.length).toBe(64);
    expect(sa.signer).toBe(base.signerUrl);
    expect(sa.vote).toBeUndefined();

    const r = buildPreimage(txHash, { ...base, vote: 'reject' });
    const sr = buildSignatureObject(r, nacl.sign.detached(r.dataForSignature, kp.secretKey), bytesToHex(txHash));
    expect(sr.vote).toBe('reject');
  });

  it('computeTimestamp is strictly ahead of lastUsedOn', () => {
    expect(computeTimestamp(1_000_000, 500_000)).toBeGreaterThan(1_000_000);
    expect(computeTimestamp(0, 5_000_000)).toBeGreaterThan(5_000_000);
  });
});
