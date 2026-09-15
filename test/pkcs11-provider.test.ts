/**
 * The pkcs11 provider and its PIN custodian client, against an in-memory PKCS#11 token. Phase 8.1.
 *
 * The real token is SoftHSM2 in Docker (test/pkcs11-softhsm.test.ts, `npm run test:pkcs11`). This file runs
 * on every host, without the native addon, and pins what a real token cannot easily show: the order of the
 * PKCS#11 calls around every signature, that a custodian refusal means no login and no signature, that the
 * vote is withheld rather than thrown, and the config rules. The fake token keeps private objects invisible
 * until login, as a real one does. All labels and parties are FICTIONAL.
 */
import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import { Writable } from 'node:stream';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import nacl from 'tweetnacl';
import { p256 } from '@noble/curves/nist.js';
import { CK, Pkcs11Api, Pkcs11Signer } from '../src/signer/pkcs11.js';
import { pinAuthHeader, requestPin } from '../src/signer/pin-source.js';
import { buildPreimage } from '../src/accumulate/signing.js';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { singleKeyring, buildSignerFromSpec } from '../src/signer/keyring.js';
import { loadConfig } from '../src/config.js';
import { startCustodianStub } from './support/pin-custodian-stub.js';

const TOKEN = 'orchid-seat-fictional';
const PAGE = 'acc://orchid-logistics-fictional.acme/book/2';
const PRINCIPAL = 'acc://bank-fictional.acme/payments';
// A throwaway value for an in-memory fake token, generated per run.
const PIN = randomBytes(9).toString('hex');
const HMAC = randomBytes(16).toString('hex');

interface FakeKey { label: string; type: 'ed25519' | 'ecdsa-p256'; extractable: boolean; sensitive: boolean; point: Buffer; sign: (d: Buffer) => Buffer }

function edKey(label: string, over: Partial<FakeKey> = {}): FakeKey {
  const kp = nacl.sign.keyPair();
  return { label, type: 'ed25519', extractable: false, sensitive: true, point: Buffer.concat([Buffer.from([4, 32]), kp.publicKey]), sign: (d) => Buffer.from(nacl.sign.detached(d, kp.secretKey)), ...over };
}
function ecKey(label: string, over: Partial<FakeKey> = {}): FakeKey {
  const sk = p256.utils.randomSecretKey();
  const pt = p256.getPublicKey(sk, false);
  return { label, type: 'ecdsa-p256', extractable: false, sensitive: true, point: Buffer.concat([Buffer.from([4, 65]), pt]), sign: (d) => Buffer.from(p256.sign(d, sk, { prehash: false, format: 'compact', lowS: false })), ...over };
}

class FakeToken implements Pkcs11Api {
  calls: string[] = [];
  loggedIn = false;
  #found: Buffer[] = [];
  #signKey: FakeKey | undefined;
  constructor(private readonly keys: FakeKey[]) {}
  #obj(h: Buffer) { const i = h.readUInt8(1); return { key: this.keys[i]!, priv: h.readUInt8(0) === 1 }; }
  load() {}
  C_Initialize() {}
  C_GetSlotList() { return [Buffer.from([1])]; }
  C_GetTokenInfo() { return { label: TOKEN.padEnd(32, ' ') }; }
  C_OpenSession() { this.calls.push('open'); return Buffer.from([9]); }
  C_CloseSession() { this.calls.push('close'); this.loggedIn = false; }
  C_Login(_s: Buffer, _u: number, pin?: string) {
    this.calls.push('login');
    if (pin !== PIN) throw Object.assign(new Error('CKR_PIN_INCORRECT:160'), { code: 0xa0 });
    this.loggedIn = true;
  }
  C_Logout() { this.calls.push('logout'); this.loggedIn = false; }
  C_FindObjectsInit(_s: Buffer, t: Array<{ type: number; value?: unknown }>) {
    const cls = t.find((a) => a.type === CK.CKA_CLASS)?.value;
    const label = t.find((a) => a.type === CK.CKA_LABEL)?.value;
    const priv = cls === CK.CKO_PRIVATE_KEY;
    this.#found = priv && !this.loggedIn ? [] : this.keys.flatMap((k, i) => (k.label === label ? [Buffer.from([priv ? 1 : 0, i])] : []));
  }
  C_FindObjects(_s: Buffer, max: number) { return this.#found.slice(0, max); }
  C_FindObjectsFinal() {}
  C_GetAttributeValue(_s: Buffer, h: Buffer, t: Array<{ type: number }>) {
    const { key } = this.#obj(h);
    const ul = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
    return t.map(({ type }) => ({
      type,
      value: type === CK.CKA_KEY_TYPE ? ul(key.type === 'ed25519' ? CK.CKK_EC_EDWARDS : CK.CKK_EC)
        : type === CK.CKA_EC_PARAMS ? Buffer.from(key.type === 'ed25519' ? '06032b6570' : '06082a8648ce3d030107', 'hex')
        : type === CK.CKA_EC_POINT ? key.point
        : type === CK.CKA_EXTRACTABLE ? Buffer.from([key.extractable ? 1 : 0])
        : type === CK.CKA_SENSITIVE ? Buffer.from([key.sensitive ? 1 : 0])
        : Buffer.alloc(0),
    }));
  }
  C_SignInit(_s: Buffer, m: { mechanism: number }, h: Buffer) {
    this.calls.push(`signinit:${m.mechanism.toString(16)}`);
    const { key, priv } = this.#obj(h);
    if (!priv || !this.loggedIn) throw new Error('CKR_USER_NOT_LOGGED_IN:257');
    this.#signKey = key;
  }
  C_Sign(_s: Buffer, data: Buffer) { this.calls.push('sign'); return this.#signKey!.sign(data); }
}

/** Every log line, from every level, so a test can assert the PIN is in none of them. */
function capture() {
  const lines: string[] = [];
  const logger = pino({ level: 'trace' }, new Writable({ write(c, _e, cb) { lines.push(String(c)); cb(); } }));
  return { logger, lines };
}

const txHash = () => randomBytes(32).toString('hex');
const ctxFor = (tx: string) => ({ txHash: tx, principal: PRINCIPAL, page: PAGE });

describe('pkcs11 provider (in-memory token)', () => {
  const approved = new Set<string>();
  let custodian: Awaited<ReturnType<typeof startCustodianStub>>;
  const logs = capture();

  beforeAll(async () => {
    custodian = await startCustodianStub({ hmacSecret: HMAC, pin: () => PIN, page: PAGE, keyLabel: 'machine-orchid-fictional', approved });
  });
  afterAll(async () => {
    await custodian.close();
    expect(logs.lines.join('\n')).not.toContain(PIN);
  });

  it('pin mode: Ed25519 over the preimage, one session and one login per signature', async () => {
    const token = new FakeToken([edKey('machine-orchid-fictional')]);
    const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'machine-orchid-fictional', keyType: 'ed25519', pin: PIN, api: token, logger: logs.logger });
    const pub = await s.publicKey();
    expect(pub.length).toBe(32);
    token.calls = [];
    const pre = buildPreimage(randomBytes(32), { publicKey: pub, signerUrl: PAGE, signerVersion: 1, timestamp: 1, vote: 'approve' });
    const sig = await s.sign(pre.dataForSignature);
    expect(nacl.sign.detached.verify(pre.dataForSignature, sig, pub)).toBe(true);
    expect(token.calls).toEqual(['open', 'login', `signinit:${CK.CKM_EDDSA.toString(16)}`, 'sign', 'logout', 'close']);
    expect(token.loggedIn).toBe(false);
  });

  it('pin mode: P-256 raw r||s is returned as DER over the S6 digest', async () => {
    const token = new FakeToken([ecKey('machine-orchid-fictional')]);
    const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'machine-orchid-fictional', keyType: 'ecdsa-p256', pin: PIN, api: token });
    const pub = await s.publicKey();
    expect(pub.length).toBe(91);
    const pre = buildPreimage(randomBytes(32), { publicKey: pub, signatureType: 'ecdsaSha256', signerUrl: PAGE, signerVersion: 1, timestamp: 1, vote: 'approve' });
    const sig = await s.sign(pre.dataForSignature);
    expect(sig[0]).toBe(0x30);
    expect(p256.verify(sig, pre.dataForSignature, pub.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(true);
    expect(token.calls).toContain(`signinit:${CK.CKM_ECDSA.toString(16)}`);
  });

  it('refuses to start on an extractable or non-sensitive key (pin mode)', async () => {
    for (const [over, why] of [[{ extractable: true }, /CKA_EXTRACTABLE/], [{ sensitive: false }, /CKA_SENSITIVE/]] as const) {
      const token = new FakeToken([ecKey('k', over)]);
      const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'k', keyType: 'ecdsa-p256', pin: PIN, api: token });
      await expect(s.publicKey()).rejects.toThrow(why);
      expect(await s.health()).toBe(false);
    }
  });

  it('refuses a key of the wrong type or a label that is missing', async () => {
    const token = new FakeToken([edKey('k')]);
    await expect(new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'k', keyType: 'ecdsa-p256', pin: PIN, api: token }).publicKey()).rejects.toThrow(/not an ecdsa-p256/);
    await expect(new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'nope', keyType: 'ed25519', pin: PIN, api: token }).publicKey()).rejects.toThrow(/found 0/);
    await expect(new Pkcs11Signer({ module: 'fake', tokenLabel: 'other', keyLabel: 'k', keyType: 'ed25519', pin: PIN, api: token }).publicKey()).rejects.toThrow(/exactly one token/);
  });

  it('pin_source: asks the custodian for every signature, naming the transaction, then logs in, signs and logs out', async () => {
    const token = new FakeToken([ecKey('machine-orchid-fictional')]);
    const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'machine-orchid-fictional', keyType: 'ecdsa-p256', pinSource: { url: custodian.url, hmacSecret: HMAC }, api: token, logger: logs.logger });
    const pub = await s.publicKey();
    // No login at startup: there is no PIN until a transaction is approved.
    expect(token.calls).not.toContain('login');
    const before = custodian.seen.length;
    for (let i = 0; i < 2; i++) {
      const tx = txHash();
      approved.add(tx);
      token.calls = [];
      const pre = buildPreimage(Buffer.from(tx, 'hex'), { publicKey: pub, signatureType: 'ecdsaSha256', signerUrl: PAGE, signerVersion: 1, timestamp: 1, vote: 'approve' });
      const sig = await s.sign(pre.dataForSignature, ctxFor(tx));
      expect(p256.verify(sig, pre.dataForSignature, pub.subarray(26), { prehash: false, format: 'der', lowS: false })).toBe(true);
      expect(token.calls).toEqual(['open', 'login', `signinit:${CK.CKM_ECDSA.toString(16)}`, 'sign', 'logout', 'close']);
      const req = custodian.seen.at(-1)!;
      expect(req.result).toBe('released');
      expect(req.body).toMatchObject({ txHash: tx, principal: PRINCIPAL, page: PAGE, keyLabel: 'machine-orchid-fictional' });
      expect(Object.keys(req.body).sort()).toEqual(['keyLabel', 'nonce', 'page', 'principal', 'ts', 'txHash']);
    }
    // Not cached: two signatures, two releases.
    expect(custodian.seen.length - before).toBe(2);
  });

  it('pin_source: a custodian refusal produces no login and no signature, and the vote is withheld', async () => {
    const token = new FakeToken([ecKey('machine-orchid-fictional')]);
    const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'machine-orchid-fictional', keyType: 'ecdsa-p256', pinSource: { url: custodian.url, hmacSecret: HMAC }, api: token, logger: logs.logger });
    await s.publicKey();
    const tx = txHash(); // never approved
    token.calls = [];
    await expect(s.sign(new Uint8Array(32).fill(1), ctxFor(tx))).rejects.toThrow(/refused \(HTTP 403\): no approve decision/);
    expect(token.calls).toEqual(['open', 'close']);

    let submitted = 0;
    const acc = { getSignerInfo: async () => ({ version: 1, lastUsedOn: 0, creditBalance: 1 }), submit: async () => { submitted++; return { ok: true }; } } as never;
    const res = await new DirectVoteBackend(acc, singleKeyring(s, PAGE), logs.logger)
      .cast({ txHash: tx, signerUrl: PAGE, signerVersion: 1, rawTransaction: {}, lastUsedOn: 0, account: PRINCIPAL }, 'approve');
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/signing failed: .*refused/);
    expect(submitted).toBe(0);
    expect(token.calls.filter((c) => c === 'sign' || c === 'login')).toEqual([]);
  });

  it('pin_source: refuses without a transaction context, and refuses an extractable key after login', async () => {
    const token = new FakeToken([ecKey('machine-orchid-fictional', { extractable: true })]);
    const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'machine-orchid-fictional', keyType: 'ecdsa-p256', pinSource: { url: custodian.url, hmacSecret: HMAC }, api: token });
    await expect(s.sign(new Uint8Array(32))).rejects.toThrow(/named transaction/);
    await s.publicKey(); // starts: the private key is invisible until a login, which pin_source has no PIN for yet
    const tx = txHash();
    approved.add(tx);
    token.calls = [];
    await expect(s.sign(new Uint8Array(32), ctxFor(tx))).rejects.toThrow(/CKA_EXTRACTABLE/);
    expect(token.calls).toEqual(['open', 'login', 'logout', 'close']);
  });

  it('a wrong PIN is a signing error that does not carry the PIN', async () => {
    const token = new FakeToken([edKey('k')]);
    const wrong = randomBytes(6).toString('hex');
    const s = new Pkcs11Signer({ module: 'fake', tokenLabel: TOKEN, keyLabel: 'k', keyType: 'ed25519', pin: wrong, api: token });
    const err = await s.publicKey().then(() => undefined, (e: Error) => e);
    expect(err?.message).toMatch(/PIN_INCORRECT/);
    expect(err?.message).not.toContain(wrong);
  });
});

describe('pin custodian client', () => {
  const ctx = ctxFor('ab'.repeat(32));
  type Init = { headers: Record<string, string>; body: string; redirect: string };
  const reply = (status: number, body: unknown) => async () => new Response(JSON.stringify(body), { status });

  it('signs the exact body it sends with t + "." + body, and returns the PIN', async () => {
    let seen: Init | undefined;
    const pin = await requestPin({
      url: 'http://pin-custodian-fictional:8080/v1/pin', hmacSecret: HMAC, now: () => 1757894400000,
      fetch: (async (_u: string, init: Init) => { seen = init; return new Response(JSON.stringify({ pin: 'x-fictional' }), { status: 200 }); }) as never,
    }, ctx, 'machine-orchid-fictional');
    expect(pin).toBe('x-fictional');
    expect(seen!.redirect).toBe('error');
    expect(seen!.headers['x-pin-auth']).toBe(pinAuthHeader(HMAC, 1757894400000, seen!.body));
    expect(seen!.headers['x-pin-auth']).toMatch(/^t=1757894400000,v1=[0-9a-f]{64}$/);
    expect(JSON.parse(seen!.body)).toMatchObject({ ...ctx, keyLabel: 'machine-orchid-fictional', ts: 1757894400000 });
  });

  it('fails closed on refusal, a PIN-less 200, a non-JSON body and an unreachable custodian', async () => {
    const o = { url: 'http://pin-custodian-fictional:8080/v1/pin', hmacSecret: HMAC };
    await expect(requestPin({ ...o, fetch: reply(403, { reason: 'decision is deny' }) as never }, ctx, 'k')).rejects.toThrow(/refused \(HTTP 403\): decision is deny/);
    await expect(requestPin({ ...o, fetch: reply(500, 'oops') as never }, ctx, 'k')).rejects.toThrow(/HTTP 500/);
    await expect(requestPin({ ...o, fetch: reply(200, { nope: 1 }) as never }, ctx, 'k')).rejects.toThrow(/without a PIN/);
    await expect(requestPin({ ...o, fetch: (async () => new Response('not json', { status: 200 })) as never }, ctx, 'k')).rejects.toThrow(/without a PIN/);
    await expect(requestPin({ ...o, fetch: (async () => { throw new TypeError('fetch failed'); }) as never }, ctx, 'k')).rejects.toThrow(/unreachable/);
    // A misbehaving custodian that puts a PIN in a refusal: the error carries the reason only.
    const leaked = await requestPin({ ...o, fetch: reply(403, { reason: 'no', pin: 'must-not-appear' }) as never }, ctx, 'k').catch((e: Error) => e.message);
    expect(leaked).not.toContain('must-not-appear');
  });

  it('times out rather than waiting on a custodian that never answers', async () => {
    const hang = (async (_u: string, init: { signal: AbortSignal }) => new Promise((_r, rej) => init.signal.addEventListener('abort', () => rej(init.signal.reason)))) as never;
    await expect(requestPin({ url: 'http://pin-custodian-fictional:8080/v1/pin', hmacSecret: HMAC, timeoutMs: 50, fetch: hang }, ctx, 'k')).rejects.toThrow(/timed out/);
  });
});

describe('pkcs11 and cloud-kms configuration', () => {
  const silent = pino({ level: 'silent' });
  const write = (signer: string) => {
    const dir = mkdtempSync(join(tmpdir(), 'signer-k3-'));
    const p = join(dir, 'c.yaml');
    writeFileSync(p, [
      'wallet: { org_id: "orchid-fictional", accumulate_endpoints: ["http://127.0.0.1:9/v3"], signer_url: "acc://orchid-logistics-fictional.acme/book/2" }',
      `signer: ${signer}`,
      'policy: { url: "http://127.0.0.1:9/decide", auth: "none" }',
    ].join('\n'));
    return p;
  };
  const base = 'module: "/usr/lib/softhsm/libsofthsm2.so", token_label: "orchid-seat", key_label: "machine-orchid-logistics", key_type: "ecdsa-p256"';

  it('accepts env: PIN refs and builds the provider; refuses a literal PIN, an unset env ref, both modes, or neither', () => {
    process.env.K3_TEST_PIN = 'fictional-pin-value';
    process.env.K3_TEST_HMAC = 'fictional-hmac-value';
    const ok = loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "env:K3_TEST_PIN" } }`));
    expect(ok.signer!.pkcs11!.pin).toBe('fictional-pin-value');
    expect(buildSignerFromSpec(ok.signer!, silent, 't')).toBeInstanceOf(Pkcs11Signer);
    expect(ok.configVersion).not.toContain('fictional-pin-value');

    const src = loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base}, pin_source: { url: "http://pin-custodian:8080/v1/pin", hmac_secret: "env:K3_TEST_HMAC", timeout_ms: 5000 } } }`));
    expect(buildSignerFromSpec(src.signer!, silent, 't').signatureType).toBe('ecdsaSha256');

    expect(() => loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "123456" } }`))).toThrow(/env: reference/);
    expect(() => loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "env:K3_UNSET_VAR" } }`))).toThrow(/resolved to nothing/);
    const both = loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "env:K3_TEST_PIN", pin_source: { url: "http://pin-custodian:8080/v1/pin", hmac_secret: "env:K3_TEST_HMAC" } } }`));
    expect(() => buildSignerFromSpec(both.signer!, silent, 't')).toThrow(/exactly one of pin/);
    const neither = loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base} } }`));
    expect(() => buildSignerFromSpec(neither.signer!, silent, 't')).toThrow(/exactly one of pin/);
    expect(() => loadConfig(write(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "env:K3_TEST_PIN", pinsource: {} } }`))).toThrow();
  });

  it('resolves and validates named keys (scopes[].keys) exactly like the scope key', () => {
    process.env.K3_TEST_PIN = 'fictional-pin-value';
    process.env.K3_TEST_VAULT_TOKEN = 'fictional-vault-token';
    const scoped = (named: string) => {
      const dir = mkdtempSync(join(tmpdir(), 'signer-k3-keys-'));
      const p = join(dir, 'c.yaml');
      writeFileSync(p, [
        'wallet:',
        '  org_id: "orchid-fictional"',
        '  accumulate_endpoints: ["http://127.0.0.1:9/v3"]',
        '  scopes:',
        '    - page: "acc://orchid-logistics-fictional.acme/book/2"',
        '      key: { provider: "local", local: { allow_ephemeral: true } }',
        '      keys:',
        `        "machine-fictional": ${named}`,
        'policy: { url: "http://127.0.0.1:9/decide", auth: "none" }',
      ].join('\n'));
      return p;
    };
    const ok = loadConfig(scoped(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "env:K3_TEST_PIN" } }`));
    const spec = ok.wallet.scopes![0]!.keys!['machine-fictional']!;
    expect(spec.pkcs11!.pin).toBe('fictional-pin-value');
    expect(buildSignerFromSpec(spec, silent, 't')).toBeInstanceOf(Pkcs11Signer);

    const vault = loadConfig(scoped('{ provider: "vault-transit", vault: { addr: "http://127.0.0.1:8200", key_name: "k", token: "env:K3_TEST_VAULT_TOKEN" } }'));
    expect(vault.wallet.scopes![0]!.keys!['machine-fictional']!.vault!.token).toBe('fictional-vault-token');

    expect(() => loadConfig(scoped(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "123456" } }`))).toThrow(/env: reference.*keys\["machine-fictional"\]/);
    expect(() => loadConfig(scoped(`{ provider: "pkcs11", pkcs11: { ${base}, pin: "env:K3_UNSET_VAR" } }`))).toThrow(/resolved to nothing/);
    expect(() => loadConfig(scoped('{ provider: "cloud-kms", cloud_kms: { vendor: "gcp", gcp: { key_version_name: "projects/orchid-fictional/locations/x/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", access_token: "literal" } } }'))).toThrow(/env: reference/);
  });

  it('cloud-kms: the vendor must have its block and only its block', () => {
    process.env.K3_TEST_TOKEN = 'fictional-token';
    const aws = loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "aws", aws: { region: "us-east-1", key_id: "alias/orchid-fictional", endpoint: "http://kms-orchid:4566" } } }'));
    expect(buildSignerFromSpec(aws.signer!, silent, 't').signatureType).toBe('ecdsaSha256');
    const az = loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "azure", azure: { vault_url: "https://orchid-fictional.vault.azure.net", key_name: "machine", key_version: "0123abcd", access_token: "env:K3_TEST_TOKEN" } } }'));
    expect(buildSignerFromSpec(az.signer!, silent, 't').signatureType).toBe('ecdsaSha256');
    const gcp = loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "gcp", gcp: { key_version_name: "projects/orchid-fictional/locations/europe-west1/keyRings/tcl/cryptoKeys/machine/cryptoKeyVersions/1" } } }'));
    expect(buildSignerFromSpec(gcp.signer!, silent, 't').signatureType).toBe('ecdsaSha256');

    const missing = loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "gcp", aws: { region: "us-east-1", key_id: "k" } } }'));
    expect(() => buildSignerFromSpec(missing.signer!, silent, 't')).toThrow(/no cloud_kms.gcp block/);
    const extra = loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "aws", aws: { region: "us-east-1", key_id: "k" }, gcp: { key_version_name: "x" } } }'));
    expect(() => buildSignerFromSpec(extra.signer!, silent, 't')).toThrow(/remove the cloud_kms.gcp block/);
    expect(() => loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "azure", azure: { vault_url: "https://v.vault.azure.net", key_name: "m", key_version: "1", access_token: "literal" } } }'))).toThrow(/env: reference/);
    const badGcp = loadConfig(write('{ provider: "cloud-kms", cloud_kms: { vendor: "gcp", gcp: { key_version_name: "projects/x/keys/y" } } }'));
    expect(() => buildSignerFromSpec(badGcp.signer!, silent, 't')).toThrow(/key_version_name must be/);
  });
});
