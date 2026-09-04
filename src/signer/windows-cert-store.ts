/**
 * WindowsCertStoreSigner — signing with a certificate the organisation already issued.
 *
 * This is the custody posture Runbook F is actually about: the bank's CA bound a key to a person
 * years ago, that key sits in the Windows certificate store (issued by Microsoft ADCS, or held on a
 * PIV/CAC card and surfaced through its minidriver), and it signs Accumulate votes directly. Nothing
 * is enrolled, generated or copied — `sha256` of the certificate's public key becomes the key page
 * entry, and the key never leaves the key-storage provider.
 *
 * ── WHY A SUBPROCESS ──────────────────────────────────────────────────────────────────────────────
 *
 * Node cannot reach a CNG key, and that is not an oversight to work around: the key is non-exportable
 * by design, so there is nothing for Node to load. Signing has to happen in a process that can call
 * CNG. `agent/windows-cert-store` is that process — small, does one thing, prints hex — and it is the
 * "local signing agent" §F6 names for model B. The same shape serves a software-backed key, a
 * TPM-backed key and a smartcard; only the provider behind the certificate differs, plus a PIN prompt.
 *
 * ── WHAT THIS DELIBERATELY DOES NOT DO ────────────────────────────────────────────────────────────
 *
 * It does not choose a certificate. A thumbprint is configured and that certificate is used, or the
 * signer refuses. Picking "the first certificate that looks right" is how a deployment ends up signing
 * with last year's revoked credential, and the failure would look like an unauthorised key page rather
 * than a selection bug.
 *
 * It does not cache signatures, and it does not keep the agent running between votes. A card that
 * demands a PIN per signature must be allowed to do so; holding a handle open to avoid the prompt
 * would quietly convert "the person is present" into "the person was present once".
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { AccumulateSignatureType, KeySigner } from './signer.js';

const run = promisify(execFile);

export interface WindowsCertStoreOptions {
  /** The certificate's thumbprint. Spaces and case are ignored; certmgr copies it with both. */
  thumbprint: string;
  /** Path to the agent executable. */
  agentPath: string;
  /** Read from LocalMachine\My instead of CurrentUser\My — where a service account's key usually is. */
  machine?: boolean;
  /** How long a single agent call may take. A card with a PIN prompt needs a person, so this is generous. */
  timeoutMs?: number;
}

export class WindowsCertStoreSigner implements KeySigner {
  /**
   * Set from the certificate itself on the first call, because the certificate decides this, not the
   * configuration. A Microsoft-PKI-issued user certificate is usually RSA; a modern PIV slot may be
   * P-256. Declaring it in config would be a second source of truth that can disagree with the key,
   * and the disagreement would only surface as a signature the network refuses.
   */
  #signatureType: AccumulateSignatureType | undefined;
  #spki: Uint8Array | undefined;
  readonly #opts: Required<Omit<WindowsCertStoreOptions, 'machine'>> & { machine: boolean };

  constructor(opts: WindowsCertStoreOptions) {
    if (!opts.thumbprint?.trim()) throw new Error('WindowsCertStoreSigner: a certificate thumbprint is required');
    if (!opts.agentPath?.trim()) throw new Error('WindowsCertStoreSigner: agent_path is required (see agent/windows-cert-store)');
    this.#opts = {
      thumbprint: opts.thumbprint.trim(),
      agentPath: opts.agentPath.trim(),
      machine: opts.machine ?? false,
      timeoutMs: opts.timeoutMs ?? 120_000,
    };
  }

  /**
   * The signature type as the certificate reports it. Declared as a getter that throws before the
   * first `describe` so a caller cannot silently read `undefined` into signature metadata — where it
   * would become part of the preimage and produce a signature nothing can verify.
   */
  get signatureType(): AccumulateSignatureType {
    if (!this.#signatureType) {
      throw new Error('WindowsCertStoreSigner: signatureType is not known until the certificate has been read; await publicKey() or health() first');
    }
    return this.#signatureType;
  }

  async #agent(...extra: string[]): Promise<string> {
    const args = ['--thumbprint', this.#opts.thumbprint, ...(this.#opts.machine ? ['--machine'] : []), ...extra];
    try {
      const { stdout } = await run(this.#opts.agentPath, args, { timeout: this.#opts.timeoutMs, windowsHide: true });
      return stdout.trim();
    } catch (err) {
      // The agent puts its reason on stderr; surface that rather than "Command failed".
      const e = err as { stderr?: string; message?: string; code?: unknown };
      const detail = (e.stderr ?? '').trim() || e.message || String(err);
      throw new Error(`WindowsCertStoreSigner: ${detail}`);
    }
  }

  /** Read the certificate's type and public key once, and remember both. */
  async #load(): Promise<void> {
    if (this.#spki && this.#signatureType) return;
    const described = await this.#agent('--describe');
    const type = described.split(/\s+/)[1];
    if (type !== 'ecdsaSha256' && type !== 'rsaSha256') {
      throw new Error(`WindowsCertStoreSigner: the agent reported an unusable signature type ${JSON.stringify(described)}`);
    }
    const hex = await this.#agent('--public-key');
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
      throw new Error('WindowsCertStoreSigner: the agent did not return a hex public key');
    }
    this.#signatureType = type;
    // PKIX/SPKI DER. sha256 of exactly these bytes is the key page entry — never a hash of a raw EC
    // point or a raw modulus, which would produce an entry that silently never matches.
    this.#spki = new Uint8Array(Buffer.from(hex, 'hex'));
  }

  async publicKey(): Promise<Uint8Array> {
    await this.#load();
    return this.#spki!;
  }

  async sign(preimage32: Uint8Array): Promise<Uint8Array> {
    if (preimage32.length !== 32) throw new Error('expected 32-byte message');
    await this.#load();
    const hex = await this.#agent('--sign', Buffer.from(preimage32).toString('hex'));
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
      throw new Error('WindowsCertStoreSigner: the agent did not return a hex signature');
    }
    const sig = new Uint8Array(Buffer.from(hex, 'hex'));
    if (sig.length === 0) throw new Error('WindowsCertStoreSigner: the agent returned an empty signature');
    return sig;
  }

  /**
   * Can we still reach the certificate? Deliberately does NOT sign: on a card that prompts per
   * signature, a health check that signs would ask the holder for their PIN on a timer.
   */
  async health(): Promise<boolean> {
    try {
      await this.#load();
      return true;
    } catch {
      return false;
    }
  }
}
