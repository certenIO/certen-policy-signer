/**
 * Vault Transit holding a P-256 key, and a page holding more than one of them.
 *
 * Runbook F Phase F2. F0 built the envelope — the signer can wrap a P-256 signature and the network
 * accepts it — with the key held in this process. That is the pilot posture. This is the first custody
 * model that is not: the key is generated inside Vault and never leaves it, and what this signer has is
 * the ability to ask for a signature over 32 bytes.
 *
 * ── WHAT IS ACTUALLY DIFFERENT ABOUT AN EC KEY, AND IT IS NOT THE ALGORITHM ────────────────────────
 *
 * Vault's Transit API answers differently for the two key types, in two places that a reader who
 * assumed "same API, different type" would get wrong, silently:
 *
 *   the public key   ed25519 comes back base64 of the raw 32 bytes; ecdsa-p256 comes back a PEM
 *                    SubjectPublicKeyInfo. The page entry is sha256 of the DER, so a reader that
 *                    base64-decoded the PEM would register a hash of ASCII armour on a key page.
 *
 *   the signature    an EC signature must be asked for over a PREHASHED input. Accumulate's preimage
 *                    is already the 32-byte digest, so `prehashed: false` would have Vault hash it a
 *                    second time and produce a signature over the wrong thing — valid ECDSA, refused
 *                    by the network, and indistinguishable at the wallet from a key that is not on the
 *                    page.
 *
 * Both were measured against a live dev Vault before this file was written, not read off the docs. The
 * `prehashed` case is asserted here against a stub that records what was SENT, because the failure it
 * prevents produces a well-formed signature over the wrong bytes — the kind that looks like every
 * other kind of rejection.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { createPublicKey, createPrivateKey, generateKeyPairSync, createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import pino from 'pino';
import { VaultTransitSigner } from '../src/signer/vault-transit.js';
import { MapKeyring, bookOf, buildSignerFromSpec } from '../src/signer/keyring.js';
import { LocalSigner } from '../src/signer/signer.js';

const silent = pino({ level: 'silent' });

/**
 * A stand-in for Vault Transit that answers the two routes this signer calls, and records the sign
 * bodies it was sent so a test can assert on what was asked for rather than only on what came back.
 */
interface StubKey {
  type: 'ed25519' | 'ecdsa-p256';
  publicKey: string;
  sign: (input: Buffer) => Buffer;
}

function vaultStub(keys: Record<string, StubKey>) {
  const seen: Array<{ key: string; body: Record<string, unknown> }> = [];
  const server = http.createServer((req, res) => {
    const m = /^\/v1\/transit\/(keys|sign)\/([^/?]+)/.exec(req.url ?? '');
    if (!m) { res.writeHead(404); return res.end('{}'); }
    const [, route, name] = m;
    const key = keys[name!];
    if (!key) { res.writeHead(404); return res.end(JSON.stringify({ errors: ['no such key'] })); }

    if (route === 'keys') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ data: { type: key.type, keys: { '1': { public_key: key.publicKey } } } }));
    }

    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const body = JSON.parse(raw || '{}');
      seen.push({ key: name!, body });
      const sig = key.sign(Buffer.from(String(body.input), 'base64'));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ data: { signature: `vault:v1:${sig.toString('base64')}` } }));
    });
  });
  return { server, seen };
}

/** A real P-256 key pair, so the stub's signatures are real signatures a real verifier accepts. */
function p256Pair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  const pkcs8 = new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' }));
  // The private scalar is the last 32 bytes of the inner SEC1 key inside a P-256 PKCS#8.
  const sec1 = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' }).export({ type: 'sec1', format: 'der' });
  const scalar = new Uint8Array(sec1.subarray(7, 39));
  return {
    pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    spki,
    point: spki.subarray(spki.length - 65),
    // lowS: false so the stub can emit the high-S signatures Vault actually emits (3 of 8, measured).
    // noble normalises to low-S by default, and a stub that only ever produced canonical signatures
    // would have agreed with a verifier stricter than the chain forever -- which is what happened, and
    // it took a live Vault to notice. Accumulate verifies with Go's ecdsa.VerifyASN1, which accepts both.
    sign: (digest: Buffer) => Buffer.from(p256.sign(new Uint8Array(digest), scalar, { prehash: false, format: 'der', lowS: false })),
  };
}

describe('VaultTransitSigner holding a P-256 key', () => {
  const alice = p256Pair();
  const stub = vaultStub({
    'alice-seat': { type: 'ecdsa-p256', publicKey: alice.pem, sign: alice.sign },
    'org-ed': { type: 'ed25519', publicKey: Buffer.alloc(32, 7).toString('base64'), sign: () => Buffer.alloc(64, 9) },
  });
  let addr = '';

  beforeAll(async () => {
    await new Promise<void>((r) => stub.server.listen(0, '127.0.0.1', r));
    addr = `http://127.0.0.1:${(stub.server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => stub.server.close(() => r())));

  const p256Signer = () => new VaultTransitSigner({ addr, keyName: 'alice-seat', token: 't', keyType: 'ecdsa-p256' });

  it('declares the signature type its key actually produces', () => {
    expect(p256Signer().signatureType).toBe('ecdsaSha256');
    expect(new VaultTransitSigner({ addr, keyName: 'org-ed', token: 't' }).signatureType).toBe('ed25519');
  });

  /**
   * The PEM case. `sha256(publicKey)` is the key page entry for every signature type alike, so getting
   * these bytes wrong does not fail loudly — it registers a hash of something else, and every vote is
   * then refused by a network that cannot find the key on the page.
   */
  it('returns the SubjectPublicKeyInfo DER, decoded from the PEM Vault answers with', async () => {
    const pub = await p256Signer().publicKey();
    expect(pub.length).toBe(91);
    expect(Buffer.from(pub).equals(Buffer.from(alice.spki))).toBe(true);
    // What an operator puts on the key page, and what SR6 compares against.
    expect(createHash('sha256').update(pub).digest('hex')).toHaveLength(64);
  });

  /**
   * The prehashed case, asserted on the REQUEST. Accumulate's preimage is already a digest; asking
   * Vault to hash it again yields a valid signature over the wrong bytes.
   */
  it('asks Vault to sign the preimage AS the digest, and for an ASN.1 signature', async () => {
    await p256Signer().sign(new Uint8Array(32).fill(0x42));
    const sent = stub.seen.filter((s) => s.key === 'alice-seat').pop()!;
    expect(sent.body.prehashed).toBe(true);
    expect(sent.body.hash_algorithm).toBe('sha2-256');
    expect(sent.body.marshaling_algorithm).toBe('asn1');
  });

  it('returns the ASN.1 DER signature, and it verifies over the preimage itself', async () => {
    const preimage = new Uint8Array(32).fill(0x42);
    const sig = await p256Signer().sign(preimage);
    expect(sig[0]).toBe(0x30);
    expect(p256.verify(sig, preimage, alice.point, { prehash: false, format: 'der', lowS: false })).toBe(true);
    // And NOT over a second hash of it, which is what a missing `prehashed` would have produced.
    const rehashed = new Uint8Array(createHash('sha256').update(preimage).digest());
    expect(p256.verify(sig, rehashed, alice.point, { prehash: false, format: 'der', lowS: false })).toBe(false);
  });

  it('still refuses anything that is not a 32-byte preimage', async () => {
    await expect(p256Signer().sign(new Uint8Array(31))).rejects.toThrow(/32-byte/);
  });

  /**
   * Declared type against Vault's own answer. The config default is `ed25519`, because every
   * deployment that predates this phase means exactly that — so the default is checked rather than
   * trusted. A wallet whose config and whose Vault disagree would sign with one algorithm and describe
   * itself with the other, and the network's refusal names a signature problem rather than a
   * configuration one.
   */
  it('refuses to use a key whose type in Vault is not the type it was configured for', async () => {
    const wrong = new VaultTransitSigner({ addr, keyName: 'alice-seat', token: 't', keyType: 'ed25519' });
    await expect(wrong.publicKey()).rejects.toThrow(/ecdsa-p256/);
    expect(await wrong.health()).toBe(false);
  });

  it('reports unhealthy for a key Vault does not have, rather than throwing at boot', async () => {
    const missing = new VaultTransitSigner({ addr, keyName: 'nobody', token: 't', keyType: 'ecdsa-p256' });
    expect(await missing.health()).toBe(false);
  });
});

// ── one page, several approvers ──────────────────────────────────────────────────────────────────

describe('a page that holds more than one key', () => {
  const ROSTER = 'acc://bank.acme/roster/1';
  const alice = new LocalSigner(new Uint8Array(32).fill(1));
  const bob = new LocalSigner(new Uint8Array(32).fill(2));
  const org = new LocalSigner(new Uint8Array(32).fill(3));

  const ring = new MapKeyring([
    { page: ROSTER, book: bookOf(ROSTER), signer: org, keys: { alice, bob } },
  ]);

  it('resolves each approver to their own key', () => {
    expect(ring.forPage(ROSTER, 'alice')).toBe(alice);
    expect(ring.forPage(ROSTER, 'bob')).toBe(bob);
    expect(ring.forPage(ROSTER, 'alice')).not.toBe(ring.forPage(ROSTER, 'bob'));
  });

  /**
   * The existing call sites pass no ref and must keep working unchanged — every one of them means
   * "the key this wallet signs with on that page", which is the scope's own key.
   */
  it('still answers the scope’s own key when no approver is named', () => {
    expect(ring.forPage(ROSTER)).toBe(org);
  });

  /**
   * Strict in both directions, and this is the property F2 is told to keep. A ref nobody configured
   * must not fall back to the scope key: that would sign a named approver's vote with the
   * organisation's key, which is precisely the substitution F-4 exists to make impossible to do
   * silently, and F4 exists to alarm on when it happens deliberately.
   */
  it('refuses an approver it holds no key for, and never falls back to the scope key', () => {
    expect(() => ring.forPage(ROSTER, 'carla')).toThrow(/carla/);
    expect(() => ring.forPage(ROSTER, 'carla')).toThrow(/alice, bob/);
  });

  it('refuses an approver on a page it does not hold at all', () => {
    expect(() => ring.forPage('acc://other.acme/book/1', 'alice')).toThrow(/no signing key/);
  });

  it('refuses two scopes claiming the same page, as it always did', () => {
    expect(() => new MapKeyring([
      { page: ROSTER, book: bookOf(ROSTER), signer: org },
      { page: ROSTER, book: bookOf(ROSTER), signer: alice },
    ])).toThrow(/duplicate/);
  });

  /**
   * Health covers the approver keys too. A roster whose second seat cannot reach its custody backend is
   * a roster that will fail at the moment somebody votes, and /healthz exists to say so before then.
   */
  it('is unhealthy when any approver key is unreachable', async () => {
    const unreachable = new VaultTransitSigner({ addr: 'http://127.0.0.1:1', keyName: 'x', token: 't' });
    const ring2 = new MapKeyring([{ page: ROSTER, book: bookOf(ROSTER), signer: org, keys: { alice, unreachable } }]);
    expect(await ring2.healthy()).toBe(false);
  });
});

describe('configuring a Vault P-256 key', () => {
  it('builds a P-256 Vault signer from a spec, and declares the right type', () => {
    const s = buildSignerFromSpec(
      { provider: 'vault-transit', vault: { addr: 'http://127.0.0.1:8200', key_name: 'alice-seat', token: 't', key_type: 'ecdsa-p256' } },
      silent,
      'roster',
    );
    expect(s.signatureType).toBe('ecdsaSha256');
  });

  it('defaults to ed25519, because every config written before this phase meant that', () => {
    const s = buildSignerFromSpec(
      { provider: 'vault-transit', vault: { addr: 'http://127.0.0.1:8200', key_name: 'org', token: 't' } },
      silent,
      'org',
    );
    expect(s.signatureType).toBe('ed25519');
  });
});
