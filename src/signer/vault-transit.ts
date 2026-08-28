/**
 * VaultTransitSigner — signing via HashiCorp Vault Transit. The PRODUCTION key posture: the private key
 * is generated in Vault and never leaves it. We send the 32-byte preimage and receive a signature; that
 * is the entirety of this process's access to the key. Proven end to end by test/vault-transit.test.ts
 * and `npm run test:vault`.
 *
 * Two key types, and the API is NOT symmetric between them. Both differences below were measured
 * against a live dev Vault rather than read off the documentation, and both fail silently when got
 * wrong — the network refuses a vote, and the error names a signature problem rather than an encoding
 * one, so it reads as a key that is not on the page.
 *
 * Vault (ed25519):
 *   POST {addr}/v1/transit/sign/{key}   { input: base64(msg), prehashed:false }  -> "vault:v1:<b64, 64 bytes>"
 *   GET  {addr}/v1/transit/keys/{key}   -> data.keys[<latest>].public_key = base64 of the raw 32 bytes
 *
 * Vault (ecdsa-p256):
 *   POST {addr}/v1/transit/sign/{key}   { input: base64(digest), prehashed:true,
 *                                        hash_algorithm:'sha2-256', marshaling_algorithm:'asn1' }
 *                                       -> "vault:v1:<b64 ASN.1 DER, 70-72 bytes>"
 *   GET  {addr}/v1/transit/keys/{key}   -> data.keys[<latest>].public_key = a PEM SubjectPublicKeyInfo
 *
 *   PREHASHED IS NOT OPTIONAL. Accumulate's preimage is already `sha256(sigMdHash || txnHash)` — the
 *   32 bytes ARE the digest. Sending them with `prehashed:false` makes Vault hash them a second time
 *   and return a perfectly valid signature over the wrong message.
 *
 *   AND THE PUBLIC KEY IS PEM, NOT BASE64. A key page entry is `sha256(publicKey)` for every signature
 *   type alike, so base64-decoding the PEM would register a hash of ASCII armour on a key page, and
 *   every vote would then be refused by a network that cannot find the key.
 *
 * ── POSTURE, BESIDE LocalSigner'S ─────────────────────────────────────────────────────────────────
 *
 * `LocalSigner` says the key is readable by anything that can read this process's memory. This one is
 * better than that and still needs stating plainly, because Runbook F Phase F2 is where a Vault key
 * starts standing for a PERSON rather than for the organisation:
 *
 *   A per-person key held in the organisation's Vault means the ORGANISATION CAN SIGN AS THAT PERSON.
 *   Nothing here requires the employee's consent, presence or knowledge at the moment of signing. It
 *   is a signature made in their name by a system their employer controls.
 *
 * That is acceptable for a pilot and it is not the production answer. It is model A of the runbook's
 * §F6, which chooses between it, the employee's own smartcard, and a remote signing service that
 * releases their key only on strong authentication — the difference between them being whether a
 * second party has to agree before a signature exists. F4 makes an organisation signing in a person's
 * name visible and alarmed rather than merely disclosed. Until one of those lands, a signature
 * produced here establishes that this deployment asked for it, and no more.
 */
import axios, { AxiosInstance } from 'axios';
import { createPublicKey } from 'node:crypto';
import { AccumulateSignatureType, KeySigner } from './signer.js';

/** The Vault Transit key types this signer can drive, by Vault's own names for them. */
export type VaultKeyType = 'ed25519' | 'ecdsa-p256';

export interface VaultTransitOptions {
  addr: string;
  keyName: string;
  token: string;
  mount?: string; // default 'transit'
  /**
   * What Vault holds under that name. Defaults to `ed25519`, because every configuration written
   * before Runbook F Phase F2 meant exactly that — and the default is CHECKED against Vault's own
   * answer on the first read rather than trusted. See `publicKey`.
   */
  keyType?: VaultKeyType;
}

const SIGNATURE_TYPE: Record<VaultKeyType, AccumulateSignatureType> = {
  ed25519: 'ed25519',
  'ecdsa-p256': 'ecdsaSha256',
};

export class VaultTransitSigner implements KeySigner {
  readonly signatureType: AccumulateSignatureType;
  private readonly keyType: VaultKeyType;
  private readonly http: AxiosInstance;
  private readonly mount: string;
  private cachedPub?: Uint8Array;

  constructor(private readonly opts: VaultTransitOptions) {
    this.keyType = opts.keyType ?? 'ed25519';
    this.signatureType = SIGNATURE_TYPE[this.keyType];
    this.mount = opts.mount ?? 'transit';
    this.http = axios.create({
      baseURL: opts.addr.replace(/\/$/, ''),
      headers: { 'X-Vault-Token': opts.token },
      timeout: 10_000,
    });
  }

  async publicKey(): Promise<Uint8Array> {
    if (this.cachedPub) return this.cachedPub;
    const res = await this.http.get(`/v1/${this.mount}/keys/${this.opts.keyName}`);

    // Vault's own answer for what this key IS, checked against what we were configured to believe. A
    // wallet whose config says ed25519 over an ecdsa-p256 key would sign with one algorithm and name
    // the other in the signature metadata; the network refuses that with an error about the signature,
    // which sends whoever reads it to look at the key page rather than at a line of configuration.
    const actual: string | undefined = res.data?.data?.type;
    if (actual && actual !== this.keyType) {
      throw new Error(
        `vault: key "${this.opts.keyName}" is ${actual} in Vault but this scope is configured as ${this.keyType} — ` +
        `set vault.key_type to ${actual}, or point the scope at a ${this.keyType} key`,
      );
    }

    const keys = res.data?.data?.keys ?? {};
    const versions = Object.keys(keys).map(Number).sort((a, b) => b - a);
    const latest = keys[String(versions[0])];
    const material: string | undefined = latest?.public_key;
    if (!material) throw new Error(`vault: could not read the public key for "${this.opts.keyName}"`);

    this.cachedPub = this.keyType === 'ecdsa-p256'
      ? new Uint8Array(createPublicKey(material).export({ type: 'spki', format: 'der' }))
      : new Uint8Array(Buffer.from(material, 'base64'));

    // The length is a property of the encoding, so it is the cheapest check that the branch above took
    // the right one: 32 raw bytes for Ed25519, 91 for a P-256 SubjectPublicKeyInfo.
    const expected = this.keyType === 'ecdsa-p256' ? 91 : 32;
    if (this.cachedPub.length !== expected) {
      throw new Error(`vault: unexpected ${this.keyType} public key length ${this.cachedPub.length}, expected ${expected}`);
    }
    return this.cachedPub;
  }

  async sign(message32: Uint8Array): Promise<Uint8Array> {
    if (message32.length !== 32) throw new Error('expected 32-byte message');
    const input = Buffer.from(message32).toString('base64');

    const body = this.keyType === 'ecdsa-p256'
      // The 32 bytes ARE the digest — see the header. `prehashed` is what says so, and `asn1` is the
      // encoding `ecdsa.VerifyASN1` expects on the other side.
      ? { input, prehashed: true, hash_algorithm: 'sha2-256', marshaling_algorithm: 'asn1' }
      : { input, prehashed: false };

    const res = await this.http.post(`/v1/${this.mount}/sign/${this.opts.keyName}`, body);
    const sig: string = res.data?.data?.signature ?? '';
    const bytes = new Uint8Array(Buffer.from(sig.split(':').pop() ?? '', 'base64'));

    if (this.keyType === 'ecdsa-p256') {
      // A DER SEQUENCE of two INTEGERs. Its length varies with how many leading zero bytes r and s
      // happen to need, so the check is a range rather than a constant — a fixed length would fail
      // for perhaps one signature in a few hundred, which is the worst possible frequency for a bug.
      if (bytes[0] !== 0x30 || bytes.length < 68 || bytes.length > 72) {
        throw new Error(
          `vault: expected an ASN.1 DER ECDSA signature, got ${bytes.length} bytes starting 0x${(bytes[0] ?? 0).toString(16)}`,
        );
      }
      return bytes;
    }

    if (bytes.length !== 64) throw new Error(`vault: unexpected signature length ${bytes.length}`);
    return bytes;
  }

  async health(): Promise<boolean> {
    try { await this.publicKey(); return true; } catch { return false; }
  }
}
