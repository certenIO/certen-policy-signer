import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import {
  buildPreimage,
  buildSignatureObject,
  buildDelegatedSignatureObject,
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

/**
 * Evidence in the signature's `memo` and `data`. Wrapper runbook, change 4.
 *
 * `data` is inside the signed metadata, so a vote can commit to the digest of the live check it stands
 * for. Three builders form a signature (the hashed metadata, the plain wire form, the delegated wire
 * form) and they must agree field for field: if the hashed form has `data` and a wire form does not, the
 * network computes a different metadata hash and refuses the signature as invalid.
 */
describe('signature memo and data', () => {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));
  const TX = 'ab'.repeat(32);
  const txHash = new Uint8Array(Buffer.from(TX, 'hex'));
  const base = { publicKey: kp.publicKey, signerUrl: 'acc://demo.acme/book/1', signerVersion: 3, timestamp: 1751630000000000 };
  const DIGEST = new Uint8Array(32).map((_, i) => i + 1);
  const W = 'acc://p.acme/id/1';
  const O = 'acc://o.acme/book/1';

  /**
   * Taken from the code BEFORE memo/data existed (base e73ef10 + the Phase 1 commit), with the same key,
   * transaction and fields. A signature built without evidence must still be exactly these bytes.
   */
  const BASELINE = {
    approve: { sigMdHash: 'bb8422de2f9c43e9753ce3163108ce72920a390b7acaf20f539fd5d1d60b89ff', dataForSignature: '6096acee90f921ead6db186bbecf5a5ca4579fe567d8d3e261d0d93e2771e994',
      wire: "{\"type\":\"ed25519\",\"signature\":\"f60dd6d38e34ad81ffc7b819f052d2e0c5d4e14dec479ea2615b0caeeea35331a3424bb5e66eb7a192145c76821b122bba95859af3daf3e92ae8572778b7e902\",\"publicKey\":\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\",\"signer\":\"acc://demo.acme/book/1\",\"signerVersion\":3,\"timestamp\":1751630000000000,\"transactionHash\":\"abababababababababababababababababababababababababababababababab\"}" },
    reject: { sigMdHash: '85fae0ddd341132163c0c2462d82b6c801380f59acaeb961b06666944e7608dd', dataForSignature: '41bd5c50b45bbe8308d41298c7fec94eccec9a124704398a2b9175df193a0ae7',
      wire: "{\"type\":\"ed25519\",\"signature\":\"3f73a1cae7418d5eaaf7a738984eaa28a8a2fc6e571e2ad584953a2ddbce792637c140477ee63988529939e0d3458313451f6db1556ad899a233b88fb22ea103\",\"publicKey\":\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\",\"signer\":\"acc://demo.acme/book/1\",\"signerVersion\":3,\"timestamp\":1751630000000000,\"transactionHash\":\"abababababababababababababababababababababababababababababababab\",\"vote\":\"reject\"}" },
    delegated1: { sigMdHash: 'f7d159dc6983d1a31245cc4d53c6b9f67dedbf8760c68fe6209846324fe46133', dataForSignature: '444aba8ab6f1f49acce97f413329954d8739dee46dc807613acdd93d6702c993',
      wire: "{\"type\":\"delegated\",\"signature\":{\"type\":\"ed25519\",\"publicKey\":\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\",\"signature\":\"1b09e102176ce6b01e30e979fb2ea665876045462d42b1568a80f3f242e055104b729e56561dc14d5791695ebba586dff0b5b810754ad141d6ec5cb3a39d390b\",\"signer\":\"acc://demo.acme/book/1\",\"signerVersion\":3,\"timestamp\":1751630000000000,\"transactionHash\":\"abababababababababababababababababababababababababababababababab\"},\"delegator\":\"acc://p.acme/id/1\"}" },
    delegated2: { sigMdHash: '802632f566be350ace7a5cf6ef23e527f1157c2ad243b777647825495d90b2a7', dataForSignature: '69aa114c415e7d430a185b46af21c719b1897f6f1a893f5acdb7a9e49546dfb0',
      wire: "{\"type\":\"delegated\",\"signature\":{\"type\":\"delegated\",\"signature\":{\"type\":\"ed25519\",\"publicKey\":\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\",\"signature\":\"959e181cdbb0f13734c031518b9e03cec72c3e1dc5a4dd2d4faaa4386da7e0eb7592020d780c44bbe6ccca251ecb6a2da103b7aa6685d63724e025387b364b05\",\"signer\":\"acc://demo.acme/book/1\",\"signerVersion\":3,\"timestamp\":1751630000000000,\"vote\":\"reject\",\"transactionHash\":\"abababababababababababababababababababababababababababababababab\"},\"delegator\":\"acc://p.acme/id/1\"},\"delegator\":\"acc://o.acme/book/1\"}" },
  } as const;

  const cases: Array<[keyof typeof BASELINE, { vote: 'approve' | 'reject'; delegators?: string[] }]> = [
    ['approve', { vote: 'approve' }],
    ['reject', { vote: 'reject' }],
    ['delegated1', { vote: 'approve', delegators: [W] }],
    ['delegated2', { vote: 'reject', delegators: [W, O] }],
  ];

  const wireOf = (pre: ReturnType<typeof buildPreimage>, delegated: boolean) => {
    const sig = nacl.sign.detached(pre.dataForSignature, kp.secretKey);
    return delegated ? buildDelegatedSignatureObject(pre, sig, TX) : buildSignatureObject(pre, sig, TX);
  };

  it('with no memo or data, every preimage and wire object is byte-identical to the baseline', () => {
    for (const [name, extra] of cases) {
      for (const params of [{ ...base, ...extra }, { ...base, ...extra, memo: '', data: new Uint8Array(0) }]) {
        const pre = buildPreimage(txHash, params);
        expect(bytesToHex(pre.sigMdHash), name).toBe(BASELINE[name].sigMdHash);
        expect(bytesToHex(pre.dataForSignature), name).toBe(BASELINE[name].dataForSignature);
        expect(JSON.stringify(wireOf(pre, !!extra.delegators)), name).toBe(BASELINE[name].wire);
      }
    }
  });

  it('with data, the preimage differs, the signature verifies, and both wire forms carry the same hex', () => {
    for (const [name, extra] of cases) {
      const pre = buildPreimage(txHash, { ...base, ...extra, data: DIGEST });
      expect(bytesToHex(pre.dataForSignature), name).not.toBe(BASELINE[name].dataForSignature);
      const sig = nacl.sign.detached(pre.dataForSignature, kp.secretKey);
      expect(nacl.sign.detached.verify(pre.dataForSignature, sig, kp.publicKey)).toBe(true);

      const plain = buildSignatureObject(pre, sig, TX);
      const delegated = buildDelegatedSignatureObject(pre, sig, TX) as any;
      let inner = delegated;
      while (inner.type === 'delegated') inner = inner.signature;
      expect(plain.data).toBe(bytesToHex(DIGEST));
      expect(inner.data).toBe(bytesToHex(DIGEST));
    }
  });

  it('memo is signed too, and carried on both wire forms', () => {
    const pre = buildPreimage(txHash, { ...base, vote: 'approve', memo: 'trust-stamp live check' });
    expect(bytesToHex(pre.dataForSignature)).not.toBe(BASELINE.approve.dataForSignature);
    const sig = nacl.sign.detached(pre.dataForSignature, kp.secretKey);
    expect(buildSignatureObject(pre, sig, TX).memo).toBe('trust-stamp live check');
    const d = buildDelegatedSignatureObject(buildPreimage(txHash, { ...base, vote: 'approve', memo: 'm', delegators: [W] }), sig, TX) as any;
    expect(d.signature.memo).toBe('m');
  });

  it('a different digest is a different preimage (the signature commits to the value, not its presence)', () => {
    const a = buildPreimage(txHash, { ...base, vote: 'approve', data: DIGEST });
    const b = buildPreimage(txHash, { ...base, vote: 'approve', data: DIGEST.map((x) => x ^ 1) });
    expect(bytesToHex(a.dataForSignature)).not.toBe(bytesToHex(b.dataForSignature));
  });
});
