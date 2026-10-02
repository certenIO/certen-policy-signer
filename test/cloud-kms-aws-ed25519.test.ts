/**
 * Contract tests for the AWS KMS adapter with an Ed25519 key (KeySpec ECC_NIST_EDWARDS25519). Phase 8.2 (K3).
 *
 * LocalStack does not support Ed25519, so the adapter is driven -- through the REAL @aws-sdk/client-kms, with
 * its own serialisation and SigV4 signing -- against a local HTTP server that replays a recorded AWS JSON 1.1
 * exchange (test/fixtures/cloud-kms/aws-kms-ed25519.json). The replay asserts what the SDK SENDS (operation,
 * KeyId, Message, MessageType RAW, SigningAlgorithm ED25519_SHA_512) as strictly as what the adapter does
 * with the answer: asking for HashEdDSA, or a DIGEST, produces a valid signature over the wrong value.
 *
 * The Ed25519 key is generated in-process at test time; no private key is committed. The AWS credentials are
 * fixed FICTIONAL placeholders the replay server ignores. All names FICTIONAL.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign as nodeSign, KeyObject } from 'node:crypto';
import nacl from 'tweetnacl';
import { AwsKmsAdapter, CloudKmsSigner, ed25519RawFromSpki } from '../src/signer/cloud-kms.js';
import { buildPreimage } from '../src/accumulate/signing.js';
import type { AccumulateSignatureType } from '../src/signer/signer.js';

type Json = unknown;
interface Exchange { request: { target: string; body: Json }; response: { status: number; body: Json } }
interface Fixture { config: Record<string, string>; exchanges: Exchange[]; error_example: { status: number; body: Json } }
const FX: Fixture = JSON.parse(readFileSync(new URL('./fixtures/cloud-kms/aws-kms-ed25519.json', import.meta.url), 'utf8'));

function fill(v: Json, vars: Record<string, string>): Json {
  if (typeof v === 'string') return v.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => {
    if (!(k in vars)) throw new Error(`fixture placeholder {{${k}}} has no value`);
    return vars[k]!;
  });
  if (Array.isArray(v)) return v.map((x) => fill(x, vars));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, vars)]));
  return v;
}

function edKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  return { privateKey, spki, raw: spki.subarray(12) };
}
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
/** Key-order-independent JSON, for comparing what the SDK sent with the recorded request. */
const canon = (v: Json): string => JSON.stringify(v, (_k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b))) : x));

/** Replay state: the next exchange, plus per-test overrides of a response body or a whole answer. */
interface Replay {
  exchanges: Exchange[];
  vars: Record<string, string>;
  /** The key the server signs with when a Sign request arrives (defaults to the key whose SPKI it serves). */
  signer: KeyObject;
  tamper?: (i: number, body: Record<string, unknown>) => void;
  answer?: { status: number; body: Json };
  seen: Array<{ target: string; body: Record<string, unknown>; auth: string | undefined; contentType: string | undefined }>;
}
let replay: Replay;
let port = 0;
const server = http.createServer((req, res) => {
  let t = '';
  req.on('data', (c) => (t += c));
  req.on('end', () => {
    const target = String(req.headers['x-amz-target'] ?? '');
    const body = JSON.parse(t || '{}') as Record<string, unknown>;
    replay.seen.push({ target, body, auth: req.headers.authorization, contentType: req.headers['content-type'] });
    const send = (status: number, payload: Json) => {
      res.writeHead(status, { 'content-type': 'application/x-amz-json-1.1' });
      res.end(JSON.stringify(payload));
    };
    try {
    if (replay.answer) return send(replay.answer.status, replay.answer.body);
    const i = replay.seen.length - 1;
    const ex = replay.exchanges[i];
    if (!ex) return send(400, { __type: "TestReplayExhausted", message: `unexpected ${target} after ${replay.seen.map((x) => x.target).join(",")}` });
    // What the SDK sent must be exactly the recorded request.
    if (target !== ex.request.target) return send(400, { __type: 'TestReplayMismatch', message: `want ${ex.request.target}, got ${target}` });
    if (target === 'TrentService.Sign') {
      replay.vars.signature_b64 = b64(nodeSign(null, Buffer.from(String(body.Message ?? ''), 'base64'), replay.signer));
    }
    const want = fill(ex.request.body, replay.vars);
    if (canon(body) !== canon(want)) return send(400, { __type: 'TestReplayMismatch', message: `body ${JSON.stringify(body)} != ${JSON.stringify(want)}` });
    const out = fill(ex.response.body, replay.vars) as Record<string, unknown>;
    replay.tamper?.(i, out);
    return send(ex.response.status, out);
    } catch (e) {
      return send(400, { __type: 'TestReplayError', message: (e as Error).message });
    }
  });
});

const savedEnv: Record<string, string | undefined> = {};
const ENV = { AWS_ACCESS_KEY_ID: 'FICTIONALACCESSKEYID0', AWS_SECRET_ACCESS_KEY: 'fictional-placeholder-not-a-secret', AWS_SESSION_TOKEN: undefined, AWS_PROFILE: undefined };
beforeAll(async () => {
  for (const [k, v] of Object.entries(ENV)) { savedEnv[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  port = await new Promise((r) => server.listen(0, '127.0.0.1', () => r((server.address() as { port: number }).port)));
});
afterAll(() => {
  server.close();
  for (const [k, v] of Object.entries(savedEnv)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

let key: ReturnType<typeof edKey>;
beforeEach(() => {
  key = edKey();
  replay = {
    exchanges: FX.exchanges,
    vars: { key_id: FX.config.key_id!, key_arn: FX.config.key_arn!, spki_b64: b64(key.spki) },
    signer: key.privateKey,
    seen: [],
  };
});

const signer = () => new CloudKmsSigner(new AwsKmsAdapter({ region: FX.config.region!, keyId: FX.config.key_id!, endpoint: `http://127.0.0.1:${port}` }));
const PAGE = 'acc://orchid-logistics-fictional.acme/book/2';
/** The wallet preimage; the replay then expects exactly these bytes as the Sign Message. */
function preimage(publicKey: Uint8Array, signatureType: AccumulateSignatureType, i = 0) {
  const txHash = new Uint8Array(32).fill(0x20 + i);
  const pre = buildPreimage(txHash, { publicKey, signatureType, signerUrl: PAGE, signerVersion: 3, timestamp: 1759395600000000 + i, vote: 'approve' });
  replay.vars.message_b64 = b64(pre.dataForSignature);
  return pre;
}

describe('AWS KMS Ed25519 (ECC_NIST_EDWARDS25519): contract', () => {
  it('reads the key, declares ed25519 with the raw 32-byte key, and signs the preimage as a RAW message', async () => {
    const s = signer();
    // The type comes from the key once it is read (before that, the legacy declared default).
    expect(s.signatureType).toBe('ecdsaSha256');
    const pub = await s.publicKey();
    expect(s.signatureType).toBe('ed25519');
    expect(pub.length).toBe(32);
    expect(Buffer.from(pub).equals(Buffer.from(key.raw))).toBe(true);
    // Key hash = sha256(raw 32-byte key), as for every other Ed25519 source (LocalSigner, Vault, PKCS#11).
    expect(createHash('sha256').update(pub).digest('hex')).toBe(createHash('sha256').update(key.raw).digest('hex'));

    const pre = preimage(pub, s.signatureType);
    const sig = await s.sign(pre.dataForSignature);
    expect(sig.length).toBe(64);
    expect(nacl.sign.detached.verify(pre.dataForSignature, sig, pub)).toBe(true);

    // What the SDK sent: GetPublicKey, then Sign over the preimage itself, RAW, pure Ed25519 -- signed with SigV4.
    expect(replay.seen.map((x) => x.target)).toEqual(['TrentService.GetPublicKey', 'TrentService.Sign']);
    expect(replay.seen[1]!.body).toEqual({ KeyId: FX.config.key_id, Message: b64(pre.dataForSignature), MessageType: 'RAW', SigningAlgorithm: 'ED25519_SHA_512' });
    expect(replay.seen[1]!.contentType).toBe('application/x-amz-json-1.1');
    expect(replay.seen[1]!.auth).toMatch(/^AWS4-HMAC-SHA256 /);
  });

  it('reads the key once and keeps signing with it', async () => {
    replay.exchanges = [FX.exchanges[0]!, FX.exchanges[1]!, FX.exchanges[1]!];
    const s = signer();
    const pub = await s.publicKey();
    for (let i = 0; i < 2; i++) {
      const pre = preimage(pub, 'ed25519', i);
      expect(nacl.sign.detached.verify(pre.dataForSignature, await s.sign(pre.dataForSignature), pub)).toBe(true);
    }
    expect(replay.seen.filter((x) => x.target === 'TrentService.GetPublicKey')).toHaveLength(1);
  });

  it('refuses a signature made by another key (verified locally before it is used)', async () => {
    replay.signer = edKey().privateKey;
    const s = signer();
    const pub = await s.publicKey();
    await expect(s.sign(preimage(pub, 'ed25519').dataForSignature)).rejects.toThrow(/does not verify against its own public key/);
  });

  it('refuses a signature of the wrong length, and a Sign answered with another algorithm', async () => {
    replay.tamper = (i, body) => { if (i === 1) body.Signature = b64(new Uint8Array(65).fill(1)); };
    const s1 = signer();
    await expect(s1.sign(preimage(await s1.publicKey(), 'ed25519').dataForSignature)).rejects.toThrow(/length 65/);

    replay = { ...replay, seen: [], tamper: (i, body) => { if (i === 1) body.SigningAlgorithm = 'ED25519_PH_SHA_512'; } };
    const s2 = signer();
    await expect(s2.sign(preimage(await s2.publicKey(), 'ed25519').dataForSignature)).rejects.toThrow(/not ED25519_SHA_512/);
  });

  it('refuses unsupported key specs, a non-signing key, and a key without ED25519_SHA_512 -- before any Sign', async () => {
    const cases: Array<[(b: Record<string, unknown>) => void, RegExp]> = [
      [(b) => { b.KeySpec = 'ECC_SECG_P256K1'; }, /ECC_SECG_P256K1, not ECC_NIST_P256 or ECC_NIST_EDWARDS25519/],
      [(b) => { b.KeySpec = 'ECC_NIST_P384'; }, /ECC_NIST_P384, not ECC_NIST_P256/],
      [(b) => { b.KeySpec = 'RSA_2048'; }, /RSA_2048/],
      [(b) => { b.KeyUsage = 'ENCRYPT_DECRYPT'; }, /not SIGN_VERIFY/],
      [(b) => { b.SigningAlgorithms = ['ED25519_PH_SHA_512']; }, /does not offer ED25519_SHA_512/],
      [(b) => { delete b.PublicKey; }, /no public key/],
      // The spec says Ed25519 but the key is not: refused when the SPKI is parsed.
      [(b) => { b.PublicKey = b64(new Uint8Array(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }))); }, /not Ed25519/],
    ];
    for (const [edit, err] of cases) {
      replay = { ...replay, seen: [], tamper: (i, body) => { if (i === 0) edit(body); } };
      const s = signer();
      replay.vars.message_b64 = b64(new Uint8Array(32).fill(3));
      await expect(s.sign(new Uint8Array(32).fill(3))).rejects.toThrow(err);
      expect(replay.seen.map((x) => x.target)).toEqual(['TrentService.GetPublicKey']);
      expect(await s.health()).toBe(false);
    }
  });

  it('fails closed on an AWS error answer', async () => {
    replay.answer = FX.error_example as { status: number; body: Json };
    const s = signer();
    await expect(s.publicKey()).rejects.toThrow(/not found/);
    await expect(s.sign(new Uint8Array(32))).rejects.toThrow(/not found/);
  });

  it('a P-256 key through the same adapter still signs ecdsaSha256 (DIGEST / ECDSA_SHA_256)', async () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const spki = new Uint8Array(ec.publicKey.export({ type: 'spki', format: 'der' }));
    replay.vars.spki_b64 = b64(spki);
    replay.tamper = (i, body) => {
      if (i === 0) { body.KeySpec = 'ECC_NIST_P256'; body.CustomerMasterKeySpec = 'ECC_NIST_P256'; body.SigningAlgorithms = ['ECDSA_SHA_256']; }
    };
    replay.exchanges = [FX.exchanges[0]!, {
      request: { target: 'TrentService.Sign', body: { KeyId: '{{key_id}}', Message: '{{message_b64}}', MessageType: 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256' } },
      response: { status: 200, body: { KeyId: '{{key_arn}}', Signature: '{{signature_b64}}', SigningAlgorithm: 'ECDSA_SHA_256' } },
    }];
    const s = signer();
    const pub = await s.publicKey();
    expect(s.signatureType).toBe('ecdsaSha256');
    expect(pub.length).toBe(91);
    const pre = preimage(pub, 'ecdsaSha256');
    // The replay server's Ed25519 signing does not apply to a P-256 key; answer with a P-256 DER signature.
    const { p256 } = await import('@noble/curves/nist.js');
    const d = Buffer.from((ec.privateKey.export({ format: 'jwk' }) as { d: string }).d, 'base64url');
    const der = p256.sign(pre.dataForSignature, d, { prehash: false, format: 'der' });
    replay.tamper = (i, body) => { if (i === 1) body.Signature = b64(der); };
    const sig = await s.sign(pre.dataForSignature);
    expect(sig[0]).toBe(0x30);
    expect(replay.seen[1]!.body).toMatchObject({ MessageType: 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256' });
  });

  it('ed25519RawFromSpki refuses anything that is not a 44-byte Ed25519 SPKI', () => {
    expect(Buffer.from(ed25519RawFromSpki(key.spki)).equals(Buffer.from(key.raw))).toBe(true);
    expect(() => ed25519RawFromSpki(key.raw)).toThrow(/not a readable/);
    const ec = new Uint8Array(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }));
    expect(() => ed25519RawFromSpki(ec)).toThrow(/not Ed25519/);
  });
});
