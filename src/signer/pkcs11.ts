/**
 * Pkcs11Signer — a key inside a PKCS#11 token (an HSM, a smartcard, SoftHSM in tests). Phase 8.1 (K3),
 * contract §1.1.
 *
 * The private key is generated in the token and cannot leave it: this provider refuses to use a key unless
 * the token itself reports `CKA_EXTRACTABLE = false` and `CKA_SENSITIVE = true`. What this process holds is
 * the ability to ask the token for a signature, gated by the token's user PIN.
 *
 *   ed25519      CKM_EDDSA over the 32-byte preimage                    -> 64-byte signature
 *   ecdsa-p256   CKM_ECDSA over the 32-byte preimage, which IS the S6 digest sha256(sigMdHash ‖ txHash)
 *                -> raw r ‖ s, converted to DER here
 *
 * TWO PIN MODES
 *
 *   pin          the PIN is process-held (an `env:` ref). The party hosts its own signer (Mode 1).
 *   pin_source   the PIN is released per signature by the key holder's cell (Mode 3, pin-source.ts).
 *
 * Either way every signature is its own session: open, (fetch the PIN), C_Login, sign, C_Logout, close.
 * No session stays logged in between votes, so a PIN released for one transaction is never reused for
 * another. PKCS#11 login state is per application rather than per session, so signatures on one module are
 * serialised.
 *
 * WHEN THE KEY ATTRIBUTES ARE CHECKED. A private key object is invisible until the user is logged in. With
 * `pin`, the check runs at startup (the first `publicKey()` — the SR6 self-check — logs in, checks and logs
 * out), so a wrong key refuses the boot. With `pin_source` there is no PIN at startup — the custodian only
 * releases one for an approved transaction — so startup checks the token and the public key, and the
 * private key attributes are checked after every login, before the token is asked to sign. A key that fails
 * the check never signs in either mode.
 *
 * NATIVE ADDON. `pkcs11js` is an optional dependency whose addon is compiled explicitly in the Docker test
 * and image builds, never by an install script (docs/KEY-SOURCES.md). Without it this provider refuses.
 */
import { AccumulateSignatureType, KeySigner, SignContext } from './signer.js';
import { p256SpkiFromPoint, rawToDer, verifyOwnSignature } from './ecdsa-der.js';
import { requestPin, PinSourceOptions } from './pin-source.js';
import type { Logger } from '../logger.js';

// PKCS#11 2.40 / 3.0 constants. Numeric, because pkcs11js 2.1.6 predates CKM_EDDSA in its constant table.
export const CK = {
  CKA_CLASS: 0x0, CKA_TOKEN: 0x1, CKA_PRIVATE: 0x2, CKA_LABEL: 0x3, CKA_ID: 0x102, CKA_KEY_TYPE: 0x100,
  CKA_SENSITIVE: 0x103, CKA_SIGN: 0x108, CKA_VERIFY: 0x10a, CKA_EXTRACTABLE: 0x162,
  CKA_EC_PARAMS: 0x180, CKA_EC_POINT: 0x181,
  CKO_PUBLIC_KEY: 2, CKO_PRIVATE_KEY: 3,
  CKK_EC: 0x3, CKK_EC_EDWARDS: 0x40,
  CKM_EC_KEY_PAIR_GEN: 0x1040, CKM_ECDSA: 0x1041, CKM_EC_EDWARDS_KEY_PAIR_GEN: 0x1055, CKM_EDDSA: 0x1057,
  CKU_USER: 1, CKF_RW_SESSION: 0x2, CKF_SERIAL_SESSION: 0x4,
  CKR_CRYPTOKI_ALREADY_INITIALIZED: 0x191,
} as const;

/** DER OBJECT IDENTIFIER prime256v1. */
const P256_EC_PARAMS = '06082a8648ce3d030107';

/** The slice of the pkcs11js API this provider uses — declared here so the optional addon is not needed to typecheck. */
export interface Pkcs11Api {
  load(path: string): void;
  C_Initialize(options?: unknown): void;
  C_GetSlotList(tokenPresent?: boolean): Buffer[];
  C_GetTokenInfo(slot: Buffer): { label: string };
  C_OpenSession(slot: Buffer, flags: number): Buffer;
  C_CloseSession(session: Buffer): void;
  C_Login(session: Buffer, userType: number, pin?: string): void;
  C_Logout(session: Buffer): void;
  C_FindObjectsInit(session: Buffer, template: Array<{ type: number; value?: unknown }>): void;
  C_FindObjects(session: Buffer, maxObjectCount: number): Buffer[];
  C_FindObjectsFinal(session: Buffer): void;
  C_GetAttributeValue(session: Buffer, object: Buffer, template: Array<{ type: number; value?: unknown }>): Array<{ type: number; value?: Buffer }>;
  C_SignInit(session: Buffer, mechanism: { mechanism: number; parameter?: unknown }, key: Buffer): void;
  C_Sign(session: Buffer, inData: Buffer, outData: Buffer): Buffer;
}

export type Pkcs11KeyType = 'ed25519' | 'ecdsa-p256';

export interface Pkcs11Options {
  module: string;
  tokenLabel: string;
  keyLabel: string;
  keyType: Pkcs11KeyType;
  /** Process-held PIN (already resolved from its `env:` ref). Exactly one of `pin` / `pinSource`. */
  pin?: string;
  pinSource?: PinSourceOptions;
  logger?: Logger;
  /** Test seam: supply the PKCS#11 API instead of loading pkcs11js. */
  api?: Pkcs11Api;
}

const modules = new Map<string, Promise<Pkcs11Api>>();
const locks = new Map<string, Promise<unknown>>();

/**
 * Load pkcs11js without `require`: a dynamic import resolves the CommonJS package under tsx/vitest (ESM)
 * and in the esbuild CJS bundle alike, where `pkcs11js` is external.
 */
async function loadModule(path: string): Promise<Pkcs11Api> {
  let existing = modules.get(path);
  if (!existing) {
    existing = (async () => {
      let mod: { PKCS11: new () => Pkcs11Api; default?: { PKCS11: new () => Pkcs11Api } };
      try {
        mod = await import('pkcs11js' as string);
      } catch (e) {
        throw new Error(`pkcs11: the pkcs11js native addon is not available (${(e as Error).message.split('\n')[0]}) — it is built explicitly in the image; see docs/KEY-SOURCES.md`);
      }
      const PKCS11 = mod.PKCS11 ?? mod.default?.PKCS11;
      if (!PKCS11) throw new Error('pkcs11: pkcs11js did not export PKCS11');
      const api = new PKCS11();
      api.load(path);
      try {
        api.C_Initialize();
      } catch (e) {
        if ((e as { code?: number }).code !== CK.CKR_CRYPTOKI_ALREADY_INITIALIZED) throw e;
      }
      return api;
    })();
    modules.set(path, existing);
    existing.catch(() => modules.delete(path));
  }
  return existing;
}

/** Run `fn` exclusively for one module: PKCS#11 login state is per application, not per session. */
async function exclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.catch(() => undefined);
  locks.set(key, tail);
  try {
    return await run;
  } finally {
    if (locks.get(key) === tail) locks.delete(key);
  }
}

const bool = (v: Buffer | undefined): boolean | undefined => (v && v.length ? v[0] !== 0 : undefined);
const ulong = (v: Buffer | undefined): number | undefined =>
  v && (v.length === 8 || v.length === 4) ? Number(v.length === 8 ? v.readBigUInt64LE() : v.readUInt32LE()) : undefined;

/** CKA_EC_POINT is a DER OCTET STRING around the point on conforming tokens, and the bare point on some. */
function unwrapPoint(v: Buffer, rawLen: number): Buffer {
  if (v.length === rawLen) return v;
  if (v.length === rawLen + 2 && v[0] === 0x04 && v[1] === rawLen) return v.subarray(2);
  throw new Error(`pkcs11: unexpected CKA_EC_POINT encoding (${v.length} bytes)`);
}

const pkcsMessage = (e: unknown): string => (e as Error).message?.split('\n')[0] ?? String(e);

export class Pkcs11Signer implements KeySigner {
  readonly signatureType: AccumulateSignatureType;
  readonly #opts: Pkcs11Options;
  #ready: Promise<{ api: Pkcs11Api; slot: Buffer; publicKey: Uint8Array }> | undefined;

  constructor(opts: Pkcs11Options) {
    for (const f of ['module', 'tokenLabel', 'keyLabel'] as const) {
      if (!opts[f]?.trim()) throw new Error(`pkcs11: ${f} is required`);
    }
    if (opts.keyType !== 'ed25519' && opts.keyType !== 'ecdsa-p256') throw new Error('pkcs11: key_type must be ed25519 or ecdsa-p256');
    if (Boolean(opts.pin) === Boolean(opts.pinSource)) {
      throw new Error('pkcs11: configure exactly one of pin (process-held) or pin_source (released per signature)');
    }
    if (opts.pinSource && (!opts.pinSource.url || !opts.pinSource.hmacSecret)) {
      throw new Error('pkcs11: pin_source requires url and hmac_secret');
    }
    this.#opts = opts;
    this.signatureType = opts.keyType === 'ed25519' ? 'ed25519' : 'ecdsaSha256';
  }

  #init() {
    if (!this.#ready) {
      this.#ready = exclusive(this.#opts.module, async () => {
        const api = this.#opts.api ?? await loadModule(this.#opts.module);
        const slot = this.#findSlot(api);
        const session = api.C_OpenSession(slot, CK.CKF_SERIAL_SESSION);
        try {
          const publicKey = this.#readPublicKey(api, session);
          if (this.#opts.pin) {
            // Process-held PIN: check the private key now, so a key that could leave the token refuses the boot.
            api.C_Login(session, CK.CKU_USER, this.#opts.pin);
            try {
              this.#checkedPrivateKey(api, session);
            } finally {
              try { api.C_Logout(session); } catch { /* closing the session below logs out regardless */ }
            }
          }
          this.#opts.logger?.info(
            { token: this.#opts.tokenLabel, keyLabel: this.#opts.keyLabel, keyType: this.#opts.keyType, pinMode: this.#opts.pin ? 'pin' : 'pin_source' },
            this.#opts.pin
              ? 'pkcs11: key found, non-extractable and sensitive; the private key stays in the token'
              : 'pkcs11: public key found; the private key is checked after each per-signature login (pin_source)',
          );
          return { api, slot, publicKey };
        } finally {
          try { api.C_CloseSession(session); } catch { /* ignore */ }
        }
      });
      this.#ready.catch(() => { this.#ready = undefined; });
    }
    return this.#ready;
  }

  #findSlot(api: Pkcs11Api): Buffer {
    const matches = api.C_GetSlotList(true).filter((s) => api.C_GetTokenInfo(s).label.replace(/[\s\0]+$/, '') === this.#opts.tokenLabel);
    if (matches.length !== 1) {
      throw new Error(`pkcs11: expected exactly one token labelled "${this.#opts.tokenLabel}", found ${matches.length}`);
    }
    return matches[0]!;
  }

  #findOne(api: Pkcs11Api, session: Buffer, template: Array<{ type: number; value?: unknown }>, what: string): Buffer {
    api.C_FindObjectsInit(session, template);
    let found: Buffer[];
    try {
      found = api.C_FindObjects(session, 2);
    } finally {
      api.C_FindObjectsFinal(session);
    }
    if (found.length !== 1) {
      throw new Error(`pkcs11: expected exactly one ${what} labelled "${this.#opts.keyLabel}", found ${found.length === 2 ? 'more than one' : 0}`);
    }
    return found[0]!;
  }

  #expectedKeyType(): number {
    return this.#opts.keyType === 'ed25519' ? CK.CKK_EC_EDWARDS : CK.CKK_EC;
  }

  #readPublicKey(api: Pkcs11Api, session: Buffer): Uint8Array {
    const obj = this.#findOne(api, session, [
      { type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
      { type: CK.CKA_LABEL, value: this.#opts.keyLabel },
    ], 'public key');
    const [kt, params, point] = api.C_GetAttributeValue(session, obj, [
      { type: CK.CKA_KEY_TYPE }, { type: CK.CKA_EC_PARAMS }, { type: CK.CKA_EC_POINT },
    ]);
    if (ulong(kt?.value) !== this.#expectedKeyType()) {
      throw new Error(`pkcs11: key "${this.#opts.keyLabel}" is not an ${this.#opts.keyType} key (CKA_KEY_TYPE 0x${(ulong(kt?.value) ?? -1).toString(16)})`);
    }
    if (!point?.value) throw new Error('pkcs11: public key has no CKA_EC_POINT');
    if (this.#opts.keyType === 'ecdsa-p256') {
      if (params?.value?.toString('hex') !== P256_EC_PARAMS) throw new Error(`pkcs11: key "${this.#opts.keyLabel}" is not on P-256`);
      return p256SpkiFromPoint(unwrapPoint(point.value, 65));
    }
    return new Uint8Array(unwrapPoint(point.value, 32));
  }

  /** Find the signing private key and refuse it unless the token says it cannot leave. Requires a login. */
  #checkedPrivateKey(api: Pkcs11Api, session: Buffer): Buffer {
    const obj = this.#findOne(api, session, [
      { type: CK.CKA_CLASS, value: CK.CKO_PRIVATE_KEY },
      { type: CK.CKA_LABEL, value: this.#opts.keyLabel },
      { type: CK.CKA_SIGN, value: true },
    ], 'signing private key');
    const [kt, extractable, sensitive] = api.C_GetAttributeValue(session, obj, [
      { type: CK.CKA_KEY_TYPE }, { type: CK.CKA_EXTRACTABLE }, { type: CK.CKA_SENSITIVE },
    ]);
    if (ulong(kt?.value) !== this.#expectedKeyType()) throw new Error(`pkcs11: private key "${this.#opts.keyLabel}" is not an ${this.#opts.keyType} key`);
    if (bool(extractable?.value) !== false) {
      throw new Error(`pkcs11: refusing key "${this.#opts.keyLabel}": CKA_EXTRACTABLE is not false — the private key could leave the token`);
    }
    if (bool(sensitive?.value) !== true) {
      throw new Error(`pkcs11: refusing key "${this.#opts.keyLabel}": CKA_SENSITIVE is not true — the token would reveal the private key`);
    }
    return obj;
  }

  async publicKey(): Promise<Uint8Array> {
    return (await this.#init()).publicKey;
  }

  async sign(preimage32: Uint8Array, ctx?: SignContext): Promise<Uint8Array> {
    if (preimage32.length !== 32) throw new Error('expected 32-byte message');
    if (this.#opts.pinSource && (!ctx?.txHash || !ctx.page || !ctx.principal)) {
      throw new Error('pkcs11: pin_source signs only for a named transaction (txHash, principal, page) — refusing');
    }
    const { api, slot, publicKey } = await this.#init();
    const log = this.#opts.logger;

    const raw = await exclusive(this.#opts.module, async () => {
      const session = api.C_OpenSession(slot, CK.CKF_SERIAL_SESSION);
      let pin: string | undefined;
      let loggedIn = false;
      try {
        if (this.#opts.pinSource) {
          pin = await requestPin(this.#opts.pinSource, ctx!, this.#opts.keyLabel);
          log?.info({ tx: ctx!.txHash, page: ctx!.page, keyLabel: this.#opts.keyLabel }, 'pkcs11: pin custodian released the PIN for this transaction');
        } else {
          pin = this.#opts.pin;
        }
        try {
          api.C_Login(session, CK.CKU_USER, pin);
        } catch (e) {
          throw new Error(`pkcs11: C_Login failed: ${pkcsMessage(e)}`);
        }
        loggedIn = true;
        pin = undefined;
        const key = this.#checkedPrivateKey(api, session);
        const mechanism = this.#opts.keyType === 'ed25519' ? CK.CKM_EDDSA : CK.CKM_ECDSA;
        const input = Buffer.from(preimage32);
        try {
          api.C_SignInit(session, { mechanism, parameter: null }, key);
          return Buffer.from(api.C_Sign(session, input, Buffer.alloc(256)));
        } catch (e) {
          throw new Error(`pkcs11: signing failed: ${pkcsMessage(e)}`);
        }
      } finally {
        pin = undefined;
        if (loggedIn) { try { api.C_Logout(session); } catch { /* closing the session logs out regardless */ } }
        try { api.C_CloseSession(session); } catch { /* ignore */ }
      }
    });

    if (raw.length !== 64) throw new Error(`pkcs11: unexpected ${this.#opts.keyType} signature length ${raw.length}`);
    const sig = this.signatureType === 'ecdsaSha256' ? rawToDer(raw) : new Uint8Array(raw);
    verifyOwnSignature(this.signatureType as 'ed25519' | 'ecdsaSha256', publicKey, preimage32, sig);
    return sig;
  }

  /** Token reachable and key present. Never signs and never asks the custodian for a PIN. */
  async health(): Promise<boolean> {
    try {
      const { api } = await this.#init();
      this.#findSlot(api);
      return true;
    } catch {
      return false;
    }
  }
}
