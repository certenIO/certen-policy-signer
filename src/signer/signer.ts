/** EdSigner: the pluggable key-custody boundary. Implementations never leak the private key. */
import nacl from 'tweetnacl';

export interface EdSigner {
  /** 32-byte Ed25519 public key. */
  publicKey(): Promise<Uint8Array>;
  /** Sign a 32-byte message, return a 64-byte detached signature. */
  sign(message32: Uint8Array): Promise<Uint8Array>;
  /** Optional readiness probe (e.g. can reach Vault). */
  health?(): Promise<boolean>;
}

/**
 * LocalSigner — ed25519 via tweetnacl from a 32-byte seed.
 * DEV/TEST ONLY. Production uses vault-transit (see SPEC §7.4).
 */
export class LocalSigner implements EdSigner {
  private readonly kp: nacl.SignKeyPair;
  constructor(seed32: Uint8Array) {
    if (seed32.length !== 32) throw new Error('LocalSigner seed must be 32 bytes');
    this.kp = nacl.sign.keyPair.fromSeed(seed32);
  }
  static generate(): LocalSigner {
    return new LocalSigner(nacl.randomBytes(32));
  }
  async publicKey(): Promise<Uint8Array> { return this.kp.publicKey; }
  async sign(message32: Uint8Array): Promise<Uint8Array> {
    if (message32.length !== 32) throw new Error('expected 32-byte message');
    return nacl.sign.detached(message32, this.kp.secretKey);
  }
  async health(): Promise<boolean> { return true; }
}
