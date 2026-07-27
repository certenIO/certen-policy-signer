/**
 * VaultTransitSigner — native Ed25519 signing via HashiCorp Vault Transit (SPEC §7.4, POC provider).
 * The private key never leaves Vault. We send the 32-byte preimage and receive a 64-byte signature.
 *
 * Vault (ed25519 key):
 *   POST {addr}/v1/transit/sign/{key}   { input: base64(msg), prehashed:false }  -> data.signature "vault:v1:<b64>"
 *   GET  {addr}/v1/transit/keys/{key}   -> data.keys[<latest>].public_key (b64)
 */
import axios, { AxiosInstance } from 'axios';
import { EdSigner } from './signer.js';

export interface VaultTransitOptions {
  addr: string;
  keyName: string;
  token: string;
  mount?: string; // default 'transit'
}

export class VaultTransitSigner implements EdSigner {
  private readonly http: AxiosInstance;
  private readonly mount: string;
  private cachedPub?: Uint8Array;

  constructor(private readonly opts: VaultTransitOptions) {
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
    const keys = res.data?.data?.keys ?? {};
    const versions = Object.keys(keys).map(Number).sort((a, b) => b - a);
    const latest = keys[String(versions[0])];
    const b64 = latest?.public_key;
    if (!b64) throw new Error('vault: could not read ed25519 public key');
    this.cachedPub = new Uint8Array(Buffer.from(b64, 'base64'));
    if (this.cachedPub.length !== 32) throw new Error(`vault: unexpected pubkey length ${this.cachedPub.length}`);
    return this.cachedPub;
  }

  async sign(message32: Uint8Array): Promise<Uint8Array> {
    if (message32.length !== 32) throw new Error('expected 32-byte message');
    const res = await this.http.post(`/v1/${this.mount}/sign/${this.opts.keyName}`, {
      input: Buffer.from(message32).toString('base64'),
      prehashed: false,
    });
    const sig: string = res.data?.data?.signature ?? '';
    const b64 = sig.split(':').pop() ?? '';
    const bytes = new Uint8Array(Buffer.from(b64, 'base64'));
    if (bytes.length !== 64) throw new Error(`vault: unexpected signature length ${bytes.length}`);
    return bytes;
  }

  async health(): Promise<boolean> {
    try { await this.publicKey(); return true; } catch { return false; }
  }
}
