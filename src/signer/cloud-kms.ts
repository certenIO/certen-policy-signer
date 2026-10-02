/**
 * CloudKmsSigner — an ECDSA P-256 key (any vendor) or an Ed25519 key (AWS) inside a cloud KMS the party
 * controls. Phase 8.2 (K3), contract §1.2.
 *
 * One signer, three vendor adapters behind one small interface. The key is generated in the KMS and cannot
 * be exported; what this process holds is a credential that lets it ask for a signature over a digest. In
 * custody Mode 2 that credential is issued by the PARTY's own cloud account to an independent operator, so
 * the operator can sign but the party can revoke it, and the bank never holds it.
 *
 *   aws     @aws-sdk/client-kms   GetPublicKey (SPKI DER)       Sign DIGEST / ECDSA_SHA_256    -> DER
 *                                                                 Sign RAW / ED25519_SHA_512     -> raw 64 bytes
 *   azure   REST (fetch)          GET keys/{name}/{version} JWK POST .../sign  alg ES256       -> raw r‖s
 *   gcp     REST (fetch)          GET {version}/publicKey (PEM) POST {version}:asymmetricSign  -> DER
 *
 * Ed25519 (AWS `ECC_NIST_EDWARDS25519`). A Mode 2 machine seat needs an `ed25519` signature: the validators'
 * G1 governance proof refuses `ecdsaSha256` (G-42), so a P-256 seat key can never settle a payment on chain.
 * The algorithm is chosen from the KEY'S OWN KeySpec as AWS reports it (GetPublicKey), never from config:
 * `ECC_NIST_P256` signs as `ecdsaSha256`, `ECC_NIST_EDWARDS25519` as `ed25519`, and anything else is refused.
 * For Ed25519 the 32-byte preimage is the MESSAGE of a pure EdDSA signature (`ED25519_SHA_512` with
 * `MessageType: RAW`, FIPS 186-5 §7.6) -- exactly what the in-process LocalSigner signs -- never a digest for
 * HashEdDSA (`ED25519_PH_SHA_512`), which signs a different value. The public key is the raw 32 bytes taken
 * from the SPKI (the page entry is sha256 of those, as for every other Ed25519 source), and every signature
 * is verified locally against it before it is returned.
 *
 * Every adapter refuses a key that is not a key type it supports BEFORE anything is signed: `sign` always reads
 * (and memoises) the public key first, and that read carries the vendor's spec/usage check. Every signature
 * is normalised to strict DER and verified locally against that public key over the exact preimage before it
 * is returned (ecdsa-der.ts). The preimage IS the S6 digest sha256(sigMdHash ‖ txHash), so each vendor is
 * asked to sign a DIGEST — never a message it would hash again.
 */
import { createPublicKey } from 'node:crypto';
import { AccumulateSignatureType, KeySigner } from './signer.js';
import { checkP256Spki, derToRaw, rawToDer, verifyOwnSignature } from './ecdsa-der.js';

/** The key types a KMS adapter can hold for this signer. */
export type KmsKeyAlgorithm = 'ecdsa-p256' | 'ed25519';
export interface KmsKeyInfo { algorithm: KmsKeyAlgorithm; spki: Uint8Array }

/** SubjectPublicKeyInfo prefix for Ed25519 (RFC 8410): SEQUENCE { AlgorithmIdentifier id-Ed25519 }, BIT STRING(33). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** The raw 32-byte Ed25519 public key from its SPKI DER, after Node has parsed it as an Ed25519 key. */
export function ed25519RawFromSpki(spki: Uint8Array): Uint8Array {
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  } catch {
    throw new Error('ed25519: public key is not a readable SubjectPublicKeyInfo');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`ed25519: public key is ${key.asymmetricKeyType ?? 'unknown'}, not Ed25519`);
  const buf = Buffer.from(spki);
  if (buf.length !== 44 || !buf.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) throw new Error(`ed25519: unexpected SPKI encoding (${buf.length} bytes)`);
  const raw = new Uint8Array(buf.subarray(12));
  const x = (key.export({ format: 'jwk' }) as { x?: string }).x;
  if (!x || !Buffer.from(x, 'base64url').equals(Buffer.from(raw))) throw new Error('ed25519: SPKI key bytes disagree with the parsed key');
  return raw;
}

export interface KmsAdapter {
  readonly vendor: 'aws' | 'azure' | 'gcp';
  /** SPKI DER of the key, after the adapter has checked the vendor's own statement of spec and usage. */
  getPublicKeySpki(): Promise<Uint8Array>;
  /** Sign a 32-byte SHA-256 digest; returns DER or raw r‖s as the vendor produces it (`encoding`). */
  signDigest(digest32: Uint8Array): Promise<Uint8Array>;
  readonly encoding: 'der' | 'raw';
  /**
   * An adapter that can hold more than one key type says which this key is, from the vendor's own key spec,
   * and returns its SPKI. Absent: the adapter holds P-256 only and `getPublicKeySpki` is used.
   */
  getKeyInfo?(): Promise<KmsKeyInfo>;
  /** Ed25519: sign the 32-byte preimage as the MESSAGE (pure EdDSA); returns the raw 64-byte signature. */
  signEd25519?(message32: Uint8Array): Promise<Uint8Array>;
}

type ReadKey = { type: 'ecdsaSha256' | 'ed25519'; publicKey: Uint8Array };

export class CloudKmsSigner implements KeySigner {
  #type: 'ecdsaSha256' | 'ed25519' | undefined;
  #key: Promise<ReadKey> | undefined;

  constructor(private readonly adapter: KmsAdapter) {}

  /**
   * The signature type, from the key itself.
   *
   * An adapter that holds P-256 only (Azure, GCP: no `getKeyInfo`) can only ever sign `ecdsaSha256`, so that is
   * known before the key is read. An adapter whose keys may be either type (AWS) says which from the key's own
   * KeySpec, so until the key has been read the type is NOT known and this throws, exactly as the Windows
   * certificate-store signer does: a caller must never read a guessed type into signature metadata, where it
   * becomes part of the preimage. Await `publicKey()` (the startup self-check does, for every scope) first.
   */
  get signatureType(): AccumulateSignatureType {
    if (this.#type) return this.#type;
    if (!this.adapter.getKeyInfo) return 'ecdsaSha256';
    throw new Error(`cloud-kms ${this.adapter.vendor}: signatureType is not known until the key has been read; await publicKey() first`);
  }

  #read(): Promise<ReadKey> {
    if (!this.#key) {
      this.#key = (async (): Promise<ReadKey> => {
        let k: ReadKey;
        if (!this.adapter.getKeyInfo) {
          k = { type: 'ecdsaSha256', publicKey: checkP256Spki(await this.adapter.getPublicKeySpki()) };
        } else {
          const info = await this.adapter.getKeyInfo();
          if (info.algorithm === 'ed25519') k = { type: 'ed25519', publicKey: ed25519RawFromSpki(info.spki) };
          else if (info.algorithm === 'ecdsa-p256') k = { type: 'ecdsaSha256', publicKey: checkP256Spki(info.spki) };
          else throw new Error(`cloud-kms ${this.adapter.vendor}: unsupported key algorithm ${String(info.algorithm)} — refusing`);
        }
        // A key whose type changed under a running signer (a re-pointed alias) is refused, never followed:
        // everything already declared for this scope (the page entry, the type in the metadata) is the old one's.
        if (this.#type && this.#type !== k.type) {
          throw new Error(`cloud-kms ${this.adapter.vendor}: the key's type changed from ${this.#type} to ${k.type} — refusing`);
        }
        this.#type = k.type;
        return k;
      })();
      this.#key.catch(() => { this.#key = undefined; });
    }
    return this.#key;
  }

  /** P-256: the SPKI DER (91 bytes). Ed25519: the raw 32-byte key. sha256 of this is the page entry. */
  async publicKey(): Promise<Uint8Array> {
    return (await this.#read()).publicKey;
  }

  async sign(preimage32: Uint8Array): Promise<Uint8Array> {
    if (preimage32.length !== 32) throw new Error('expected 32-byte message');
    const key = await this.#read();
    if (key.type === 'ed25519') {
      if (!this.adapter.signEd25519) throw new Error(`cloud-kms ${this.adapter.vendor}: this adapter cannot sign with an Ed25519 key — refusing`);
      const sig = await this.adapter.signEd25519(preimage32);
      if (sig.length !== 64) throw new Error(`cloud-kms ${this.adapter.vendor}: unexpected Ed25519 signature length ${sig.length} — refusing`);
      verifyOwnSignature('ed25519', key.publicKey, preimage32, sig);
      return sig;
    }
    const spki = key.publicKey;
    const out = await this.adapter.signDigest(preimage32);
    // Strict both ways: a vendor DER is parsed and re-encoded, so a non-minimal encoding the network would
    // refuse is refused here instead.
    const der = this.adapter.encoding === 'raw' ? rawToDer(out) : rawToDer(derToRaw(out));
    verifyOwnSignature('ecdsaSha256', spki, preimage32, der);
    return der;
  }

  async health(): Promise<boolean> {
    try { await this.publicKey(); return true; } catch { return false; }
  }
}

// ── AWS ───────────────────────────────────────────────────────────────────────────────────────────────

export interface AwsKmsOptions {
  region: string;
  keyId: string;
  /** Override for LocalStack or a VPC endpoint. Credentials always come from the AWS SDK's default chain. */
  endpoint?: string;
}

type KmsModule = typeof import('@aws-sdk/client-kms');

export class AwsKmsAdapter implements KmsAdapter {
  readonly vendor = 'aws' as const;
  readonly encoding = 'der' as const;
  #client: Promise<{ mod: KmsModule; client: InstanceType<KmsModule['KMSClient']> }> | undefined;

  constructor(private readonly opts: AwsKmsOptions) {
    if (!opts.region || !opts.keyId) throw new Error('cloud-kms aws: region and key_id are required');
  }

  #kms() {
    this.#client ??= import('@aws-sdk/client-kms').then((mod) => ({
      mod,
      client: new mod.KMSClient({ region: this.opts.region, ...(this.opts.endpoint ? { endpoint: this.opts.endpoint } : {}) }),
    }));
    return this.#client;
  }

  /** The algorithm the key's own KeySpec named on the last read. Signing refuses until it is known. */
  #algorithm: KmsKeyAlgorithm | undefined;

  /**
   * GetPublicKey, and the key's type from its own `KeySpec`: `ECC_NIST_P256` (offering `ECDSA_SHA_256`) or
   * `ECC_NIST_EDWARDS25519` (offering `ED25519_SHA_512`), with `KeyUsage: SIGN_VERIFY`. Anything else is refused.
   */
  async getKeyInfo(): Promise<KmsKeyInfo> {
    const { mod, client } = await this.#kms();
    const res = await client.send(new mod.GetPublicKeyCommand({ KeyId: this.opts.keyId }));
    const spec = res.KeySpec;
    const algorithm: KmsKeyAlgorithm | undefined = spec === 'ECC_NIST_P256' ? 'ecdsa-p256' : spec === 'ECC_NIST_EDWARDS25519' ? 'ed25519' : undefined;
    if (!algorithm) throw new Error(`cloud-kms aws: key ${this.opts.keyId} is ${spec ?? 'unknown'}, not ECC_NIST_P256 or ECC_NIST_EDWARDS25519 — refusing`);
    if (res.KeyUsage !== 'SIGN_VERIFY') throw new Error(`cloud-kms aws: key ${this.opts.keyId} usage is ${res.KeyUsage ?? 'unknown'}, not SIGN_VERIFY — refusing`);
    const wantAlg = algorithm === 'ed25519' ? 'ED25519_SHA_512' : 'ECDSA_SHA_256';
    if (res.SigningAlgorithms && !res.SigningAlgorithms.includes(wantAlg)) {
      throw new Error(`cloud-kms aws: key ${this.opts.keyId} does not offer ${wantAlg} — refusing`);
    }
    if (!res.PublicKey) throw new Error('cloud-kms aws: GetPublicKey returned no public key');
    this.#algorithm = algorithm;
    return { algorithm, spki: new Uint8Array(res.PublicKey) };
  }

  /** The P-256 SPKI. Refuses an Ed25519 key: this entry point promises P-256. */
  async getPublicKeySpki(): Promise<Uint8Array> {
    const info = await this.getKeyInfo();
    if (info.algorithm !== 'ecdsa-p256') throw new Error(`cloud-kms aws: key ${this.opts.keyId} is not ECC_NIST_P256 — refusing`);
    return info.spki;
  }

  /**
   * Ed25519: pure EdDSA over the 32-byte preimage AS THE MESSAGE (`ED25519_SHA_512`, `MessageType: RAW` --
   * the only message type AWS accepts with that algorithm). Never `ED25519_PH_SHA_512` / `DIGEST`: that is
   * HashEdDSA, a different signature the network would not verify.
   */
  async signEd25519(message32: Uint8Array): Promise<Uint8Array> {
    if (this.#algorithm !== 'ed25519') throw new Error('cloud-kms aws: the key is not a known ECC_NIST_EDWARDS25519 key — refusing to sign Ed25519');
    const { mod, client } = await this.#kms();
    const res = await client.send(new mod.SignCommand({
      KeyId: this.opts.keyId,
      Message: message32,
      MessageType: 'RAW',
      SigningAlgorithm: 'ED25519_SHA_512',
    }));
    if (res.SigningAlgorithm !== undefined && res.SigningAlgorithm !== 'ED25519_SHA_512') {
      throw new Error(`cloud-kms aws: Sign answered with ${res.SigningAlgorithm}, not ED25519_SHA_512 — refusing`);
    }
    if (!res.Signature) throw new Error('cloud-kms aws: Sign returned no signature');
    return new Uint8Array(res.Signature);
  }

  async signDigest(digest32: Uint8Array): Promise<Uint8Array> {
    if (this.#algorithm === 'ed25519') throw new Error('cloud-kms aws: the key is ECC_NIST_EDWARDS25519; it does not sign ECDSA digests — refusing');
    const { mod, client } = await this.#kms();
    const res = await client.send(new mod.SignCommand({
      KeyId: this.opts.keyId,
      Message: digest32,
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    }));
    if (!res.Signature) throw new Error('cloud-kms aws: Sign returned no signature');
    return new Uint8Array(res.Signature);
  }
}

// ── Shared REST plumbing (Azure, GCP) ─────────────────────────────────────────────────────────────────

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal; redirect?: 'error' }) =>
  Promise<{ status: number; json(): Promise<unknown> }>;

/** A bearer-token source: an `env:`-resolved static token, or the platform's instance metadata identity. */
export type TokenSource = () => Promise<string>;

const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

async function call(fetchFn: FetchLike, vendor: string, url: string, token: string, method: 'GET' | 'POST', body?: unknown, timeoutMs = 10_000): Promise<Record<string, unknown>> {
  let res;
  try {
    res = await fetchFn(url, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    throw new Error(`cloud-kms ${vendor}: request failed (${(e as Error).name})`);
  }
  let json: unknown;
  try { json = await res.json(); } catch { json = undefined; }
  if (res.status !== 200 || !json || typeof json !== 'object') {
    // Vendor error objects carry a code and message, never key material; keep only those.
    const err = (json as { error?: { code?: unknown; message?: unknown; status?: unknown } } | undefined)?.error;
    const detail = err ? `${String(err.code ?? err.status ?? '')} ${String(err.message ?? '').slice(0, 200)}`.trim() : 'no detail';
    throw new Error(`cloud-kms ${vendor}: HTTP ${res.status} from ${method} ${new URL(url).pathname}: ${detail}`);
  }
  return json as Record<string, unknown>;
}

/** A cached token from an instance metadata endpoint; refreshed a minute before it expires. */
function metadataToken(fetchFn: FetchLike, url: string, headers: Record<string, string>, vendor: string): TokenSource {
  let cached: { token: string; until: number } | undefined;
  return async () => {
    if (cached && Date.now() < cached.until) return cached.token;
    const res = await fetchFn(url, { method: 'GET', headers, signal: AbortSignal.timeout(5000), redirect: 'error' })
      .catch((e) => { throw new Error(`cloud-kms ${vendor}: metadata identity unreachable (${(e as Error).name})`); });
    const j = (await res.json().catch(() => undefined)) as { access_token?: string; expires_in?: number | string } | undefined;
    if (res.status !== 200 || !j?.access_token) throw new Error(`cloud-kms ${vendor}: metadata identity returned no token (HTTP ${res.status})`);
    cached = { token: j.access_token, until: Date.now() + Math.max(0, Number(j.expires_in ?? 300) - 60) * 1000 };
    return cached.token;
  };
}

// ── Azure Key Vault ───────────────────────────────────────────────────────────────────────────────────

export interface AzureKeyVaultOptions {
  vaultUrl: string;
  keyName: string;
  /** Pinned: a floating "latest" would let a rotation in the vault silently change the key on the page. */
  keyVersion: string;
  /** A bearer token (resolved from `env:`). Absent: the Azure managed identity (IMDS) is used. */
  accessToken?: string;
  apiVersion?: string;
  fetch?: FetchLike;
}

export class AzureKeyVaultAdapter implements KmsAdapter {
  readonly vendor = 'azure' as const;
  readonly encoding = 'raw' as const;
  readonly #fetch: FetchLike;
  readonly #token: TokenSource;
  readonly #base: string;
  readonly #api: string;

  constructor(private readonly opts: AzureKeyVaultOptions) {
    if (!opts.vaultUrl || !opts.keyName || !opts.keyVersion) throw new Error('cloud-kms azure: vault_url, key_name and key_version are required');
    const u = new URL(opts.vaultUrl);
    if (u.protocol !== 'https:') throw new Error('cloud-kms azure: vault_url must be https');
    for (const [k, v] of [['key_name', opts.keyName], ['key_version', opts.keyVersion]] as const) {
      if (!/^[A-Za-z0-9-]+$/.test(v)) throw new Error(`cloud-kms azure: ${k} may contain only letters, digits and hyphens`);
    }
    this.#fetch = opts.fetch ?? (fetch as unknown as FetchLike);
    this.#base = `${u.origin}/keys/${opts.keyName}/${opts.keyVersion}`;
    this.#api = opts.apiVersion ?? '7.4';
    this.#token = opts.accessToken
      ? async () => opts.accessToken!
      : metadataToken(this.#fetch, 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net', { Metadata: 'true' }, 'azure');
  }

  async getPublicKeySpki(): Promise<Uint8Array> {
    const j = await call(this.#fetch, 'azure', `${this.#base}?api-version=${this.#api}`, await this.#token(), 'GET');
    const key = j.key as { kid?: string; kty?: string; crv?: string; x?: string; y?: string; key_ops?: string[] } | undefined;
    const attrs = j.attributes as { enabled?: boolean } | undefined;
    if (!key || (key.kty !== 'EC' && key.kty !== 'EC-HSM')) throw new Error(`cloud-kms azure: key ${this.opts.keyName} is ${key?.kty ?? 'unknown'}, not EC — refusing`);
    if (key.crv !== 'P-256') throw new Error(`cloud-kms azure: key ${this.opts.keyName} curve is ${key.crv ?? 'unknown'}, not P-256 — refusing`);
    if (!key.key_ops?.includes('sign')) throw new Error(`cloud-kms azure: key ${this.opts.keyName} does not permit sign — refusing`);
    if (attrs?.enabled === false) throw new Error(`cloud-kms azure: key ${this.opts.keyName} is disabled — refusing`);
    if (!key.kid?.endsWith(`/keys/${this.opts.keyName}/${this.opts.keyVersion}`)) throw new Error('cloud-kms azure: the key returned is not the pinned key version');
    const jwk = { kty: 'EC', crv: 'P-256', x: key.x ?? '', y: key.y ?? '' };
    return new Uint8Array(createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'der', type: 'spki' }));
  }

  async signDigest(digest32: Uint8Array): Promise<Uint8Array> {
    const j = await call(this.#fetch, 'azure', `${this.#base}/sign?api-version=${this.#api}`, await this.#token(), 'POST', { alg: 'ES256', value: b64url(digest32) });
    if (typeof j.kid !== 'string' || !j.kid.endsWith(`/keys/${this.opts.keyName}/${this.opts.keyVersion}`)) {
      throw new Error('cloud-kms azure: signature came from a key other than the pinned version');
    }
    if (typeof j.value !== 'string') throw new Error('cloud-kms azure: sign returned no value');
    return new Uint8Array(Buffer.from(j.value, 'base64url'));
  }
}

// ── Google Cloud KMS ──────────────────────────────────────────────────────────────────────────────────

/** CRC32C (Castagnoli), which Cloud KMS uses to protect request and response bytes in transit. */
const CRC32C_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0x82f63b78 : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32c(data: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of data) c = CRC32C_TABLE[(c ^ b) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const GCP_VERSION_NAME = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/\d+$/;

export interface GcpKmsOptions {
  keyVersionName: string;
  /** A bearer token (resolved from `env:`). Absent: the GCE/GKE metadata server identity is used. */
  accessToken?: string;
  endpoint?: string;
  fetch?: FetchLike;
}

export class GcpKmsAdapter implements KmsAdapter {
  readonly vendor = 'gcp' as const;
  readonly encoding = 'der' as const;
  readonly #fetch: FetchLike;
  readonly #token: TokenSource;
  readonly #base: string;

  constructor(private readonly opts: GcpKmsOptions) {
    if (!GCP_VERSION_NAME.test(opts.keyVersionName ?? '')) {
      throw new Error('cloud-kms gcp: key_version_name must be projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/<n>');
    }
    const endpoint = new URL(opts.endpoint ?? 'https://cloudkms.googleapis.com');
    if (endpoint.protocol !== 'https:') throw new Error('cloud-kms gcp: endpoint must be https');
    this.#fetch = opts.fetch ?? (fetch as unknown as FetchLike);
    this.#base = `${endpoint.origin}/v1/${opts.keyVersionName}`;
    this.#token = opts.accessToken
      ? async () => opts.accessToken!
      : metadataToken(this.#fetch, 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', { 'Metadata-Flavor': 'Google' }, 'gcp');
  }

  async getPublicKeySpki(): Promise<Uint8Array> {
    const j = await call(this.#fetch, 'gcp', `${this.#base}/publicKey`, await this.#token(), 'GET');
    if (j.algorithm !== 'EC_SIGN_P256_SHA256') throw new Error(`cloud-kms gcp: key algorithm is ${String(j.algorithm ?? 'unknown')}, not EC_SIGN_P256_SHA256 — refusing`);
    if (j.name !== undefined && j.name !== this.opts.keyVersionName) throw new Error('cloud-kms gcp: the public key returned is not for the configured key version');
    if (typeof j.pem !== 'string') throw new Error('cloud-kms gcp: publicKey returned no PEM');
    if (j.pemCrc32c !== undefined && Number(j.pemCrc32c) !== crc32c(Buffer.from(j.pem, 'utf8'))) {
      throw new Error('cloud-kms gcp: public key PEM failed its CRC32C check');
    }
    return new Uint8Array(createPublicKey(j.pem).export({ format: 'der', type: 'spki' }));
  }

  async signDigest(digest32: Uint8Array): Promise<Uint8Array> {
    const j = await call(this.#fetch, 'gcp', `${this.#base}:asymmetricSign`, await this.#token(), 'POST', {
      digest: { sha256: Buffer.from(digest32).toString('base64') },
      digestCrc32c: String(crc32c(digest32)),
    });
    if (j.verifiedDigestCrc32c !== true) throw new Error('cloud-kms gcp: the service did not verify the digest checksum — refusing the signature');
    if (j.name !== this.opts.keyVersionName) throw new Error('cloud-kms gcp: signature came from a key version other than the configured one');
    if (typeof j.signature !== 'string') throw new Error('cloud-kms gcp: asymmetricSign returned no signature');
    const sig = new Uint8Array(Buffer.from(j.signature, 'base64'));
    if (j.signatureCrc32c === undefined || Number(j.signatureCrc32c) !== crc32c(sig)) {
      throw new Error('cloud-kms gcp: signature failed its CRC32C check');
    }
    return sig;
  }
}

