/**
 * Contract tests for the Azure Key Vault and Google Cloud KMS adapters. Phase 8.2 (K3), contract §1.2.
 *
 * No live cloud: each adapter is driven against a recorded exchange (test/fixtures/cloud-kms/*.json) —
 * hand-built from the vendors' public REST shapes, with placeholders filled from a P-256 key generated in
 * this test. The replay asserts what the adapter SENDS (method, URL, auth header, body) as strictly as what
 * it does with the answer, because the failure that matters most here — asking a KMS to hash an input that
 * is already a digest — produces a perfectly valid signature over the wrong message. All names FICTIONAL.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { AzureKeyVaultAdapter, CloudKmsSigner, crc32c, FetchLike, GcpKmsAdapter } from '../src/signer/cloud-kms.js';
import { buildPreimage } from '../src/accumulate/signing.js';

const TOKEN = 'fictional-bearer-token-for-tests';

type Json = unknown;
interface Exchange { request: { method: string; url: string; headers: Record<string, string>; body?: Json }; response: { status: number; body: Json } }
interface Fixture { config: Record<string, string>; exchanges: Exchange[]; error_example: { status: number; body: Json } }

const load = (name: string): Fixture => JSON.parse(readFileSync(new URL(`./fixtures/cloud-kms/${name}`, import.meta.url), 'utf8'));

function fill(v: Json, vars: Record<string, string>): Json {
  if (typeof v === 'string') return v.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => {
    if (!(k in vars)) throw new Error(`fixture placeholder {{${k}}} has no value`);
    return vars[k]!;
  });
  if (Array.isArray(v)) return v.map((x) => fill(x, vars));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, vars)]));
  return v;
}

/** Replays a fixture in order; each response may be edited by `tamper` to exercise a refusal. */
function replay(fx: Fixture, vars: Record<string, string>, tamper: (i: number, body: Record<string, unknown>) => void = () => {}) {
  let i = 0;
  const fetchFn: FetchLike = async (url, init) => {
    const ex = fx.exchanges[i];
    if (!ex) throw new Error(`unexpected request ${init.method} ${url}`);
    const want = fill(ex.request, vars) as Exchange['request'];
    expect(init.method).toBe(want.method);
    expect(url).toBe(want.url);
    for (const [h, val] of Object.entries(want.headers)) expect(init.headers[h]).toBe(val);
    expect(init.redirect).toBe('error');
    if (want.body !== undefined) expect(JSON.parse(init.body ?? 'null')).toEqual(want.body);
    else expect(init.body).toBeUndefined();
    const body = fill(ex.response.body, vars) as Record<string, unknown>;
    tamper(i, body);
    i++;
    return { status: ex.response.status, json: async () => body };
  };
  return { fetchFn, count: () => i };
}

function p256Key() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = privateKey.export({ format: 'jwk' }) as { x: string; y: string; d: string };
  const scalar = new Uint8Array(Buffer.from(jwk.d, 'base64url'));
  const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  return {
    jwk, spki, pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    // lowS:false — real KMSes return high-S about half the time, and Go's VerifyASN1 accepts it.
    sign: (digest: Uint8Array, format: 'der' | 'compact') => p256.sign(digest, scalar, { prehash: false, format, lowS: false }),
  };
}

const preimageFor = (spki: Uint8Array) => {
  const txHash = new Uint8Array(randomBytes(32));
  const pre = buildPreimage(txHash, { publicKey: spki, signatureType: 'ecdsaSha256', signerUrl: 'acc://orchid-logistics-fictional.acme/book/2', signerVersion: 3, timestamp: 1757894400000000, vote: 'approve' });
  return Object.assign(pre, { txHash });
};

/** S6: the signature is ECDSA over sha256(sigMdHash ‖ txHash), which is the preimage, verified as a digest. */
function expectS6(sig: Uint8Array, spki: Uint8Array, pre: ReturnType<typeof preimageFor>) {
  expect(Buffer.from(createHash('sha256').update(Buffer.concat([pre.sigMdHash, pre.txHash])).digest()).equals(Buffer.from(pre.dataForSignature))).toBe(true);
  expect(sig[0]).toBe(0x30);
  expect(p256.verify(sig, pre.dataForSignature, spki.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(true);
}

describe('Azure Key Vault adapter (ES256, raw r||s) against a recorded exchange', () => {
  const fx = load('azure-keyvault-es256.json');
  const make = (fetchFn: FetchLike) => new CloudKmsSigner(new AzureKeyVaultAdapter({
    vaultUrl: fx.config.vault_url!, keyName: fx.config.key_name!, keyVersion: fx.config.key_version!, accessToken: TOKEN, fetch: fetchFn,
  }));
  const setup = () => {
    const key = p256Key();
    const pre = preimageFor(key.spki);
    const vars = {
      token: TOKEN, x: key.jwk.x, y: key.jwk.y,
      digest_b64url: Buffer.from(pre.dataForSignature).toString('base64url'),
      signature_raw_b64url: Buffer.from(key.sign(pre.dataForSignature, 'compact')).toString('base64url'),
    };
    return { key, pre, vars };
  };

  it('reads the JWK as SPKI, asks for ES256 over the digest, and returns DER that verifies by S6', async () => {
    const { key, pre, vars } = setup();
    const r = replay(fx, vars);
    const signer = make(r.fetchFn);
    expect(Buffer.from(await signer.publicKey()).equals(Buffer.from(key.spki))).toBe(true);
    expectS6(await signer.sign(pre.dataForSignature), key.spki, pre);
    expect(r.count()).toBe(2);
  });

  it('refuses a key that is not a P-256 signing key, before any sign request', async () => {
    const cases: Array<[(b: Record<string, unknown>) => void, RegExp]> = [
      [(b) => { (b.key as Record<string, unknown>).kty = 'RSA-HSM'; }, /not EC/],
      [(b) => { (b.key as Record<string, unknown>).crv = 'P-384'; }, /not P-256/],
      [(b) => { (b.key as Record<string, unknown>).key_ops = ['verify']; }, /does not permit sign/],
      [(b) => { (b.attributes as Record<string, unknown>).enabled = false; }, /disabled/],
      [(b) => { (b.key as Record<string, unknown>).kid = 'https://orchid-logistics-fictional.vault.azure.net/keys/machine-orchid-fictional/0000'; }, /pinned key version/],
    ];
    for (const [edit, why] of cases) {
      const { pre, vars } = setup();
      const r = replay(fx, vars, (i, b) => { if (i === 0) edit(b); });
      await expect(make(r.fetchFn).sign(pre.dataForSignature)).rejects.toThrow(why);
      expect(r.count()).toBe(1);
    }
  });

  it('refuses a signature from another key version or one that does not verify', async () => {
    let { pre, vars } = setup();
    let r = replay(fx, vars, (i, b) => { if (i === 1) b.kid = `${fx.config.vault_url}/keys/${fx.config.key_name}/other`; });
    await expect(make(r.fetchFn).sign(pre.dataForSignature)).rejects.toThrow(/other than the pinned version/);

    ({ pre, vars } = setup());
    const stranger = p256Key();
    r = replay(fx, vars, (i, b) => { if (i === 1) b.value = Buffer.from(stranger.sign(pre.dataForSignature, 'compact')).toString('base64url'); });
    await expect(make(r.fetchFn).sign(pre.dataForSignature)).rejects.toThrow(/does not verify/);
  });

  it('surfaces a vendor error by code and message, without the bearer token', async () => {
    const err = await make(async () => ({ status: fx.error_example.status, json: async () => fx.error_example.body }))
      .publicKey().catch((e: Error) => e.message);
    expect(err).toMatch(/HTTP 403 .*Forbidden/);
    expect(err).not.toContain(TOKEN);
  });
});

describe('Google Cloud KMS adapter (EC_SIGN_P256_SHA256, DER) against a recorded exchange', () => {
  const fx = load('gcp-kms-ec-sign-p256.json');
  const make = (fetchFn: FetchLike) => new CloudKmsSigner(new GcpKmsAdapter({ keyVersionName: fx.config.key_version_name!, accessToken: TOKEN, fetch: fetchFn }));
  const setup = () => {
    const key = p256Key();
    const pre = preimageFor(key.spki);
    const sig = key.sign(pre.dataForSignature, 'der');
    const vars = {
      token: TOKEN, pem: key.pem, pem_crc32c: String(crc32c(Buffer.from(key.pem))),
      digest_b64: Buffer.from(pre.dataForSignature).toString('base64'), digest_crc32c: String(crc32c(pre.dataForSignature)),
      signature_der_b64: Buffer.from(sig).toString('base64'), signature_crc32c: String(crc32c(sig)),
    };
    return { key, pre, vars };
  };

  it('CRC32C matches the Castagnoli check value', () => {
    expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
  });

  it('reads the PEM, asks asymmetricSign over the sha256 digest with its checksum, and returns DER that verifies by S6', async () => {
    const { key, pre, vars } = setup();
    const r = replay(fx, vars);
    const signer = make(r.fetchFn);
    expect(Buffer.from(await signer.publicKey()).equals(Buffer.from(key.spki))).toBe(true);
    expectS6(await signer.sign(pre.dataForSignature), key.spki, pre);
    expect(r.count()).toBe(2);
  });

  it('refuses the wrong algorithm, a corrupted PEM, or a key version it was not configured for', async () => {
    const cases: Array<[(b: Record<string, unknown>) => void, RegExp]> = [
      [(b) => { b.algorithm = 'EC_SIGN_P384_SHA384'; }, /not EC_SIGN_P256_SHA256/],
      [(b) => { b.algorithm = 'EC_SIGN_SECP256K1_SHA256'; }, /not EC_SIGN_P256_SHA256/],
      [(b) => { b.pemCrc32c = '1'; }, /CRC32C/],
      [(b) => { b.name = String(b.name).replace(/\/1$/, '/2'); }, /not for the configured key version/],
    ];
    for (const [edit, why] of cases) {
      const { pre, vars } = setup();
      const r = replay(fx, vars, (i, b) => { if (i === 0) edit(b); });
      await expect(make(r.fetchFn).sign(pre.dataForSignature)).rejects.toThrow(why);
      expect(r.count()).toBe(1);
    }
  });

  it('refuses a signature whose checksums do not hold or that came from another version', async () => {
    const cases: Array<[(b: Record<string, unknown>) => void, RegExp]> = [
      [(b) => { b.verifiedDigestCrc32c = false; }, /did not verify the digest checksum/],
      [(b) => { b.signatureCrc32c = '7'; }, /signature failed its CRC32C/],
      [(b) => { b.name = String(b.name).replace(/\/1$/, '/9'); }, /other than the configured one/],
    ];
    for (const [edit, why] of cases) {
      const { pre, vars } = setup();
      const r = replay(fx, vars, (i, b) => { if (i === 1) edit(b); });
      await expect(make(r.fetchFn).sign(pre.dataForSignature)).rejects.toThrow(why);
    }
  });

  it('surfaces a vendor error by status and message, without the bearer token', async () => {
    const err = await make(async () => ({ status: fx.error_example.status, json: async () => fx.error_example.body }))
      .publicKey().catch((e: Error) => e.message);
    expect(err).toMatch(/HTTP 403 .*Permission/);
    expect(err).not.toContain(TOKEN);
  });
});
