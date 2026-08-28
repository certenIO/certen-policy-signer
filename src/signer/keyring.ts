/**
 * Keyring — the multi-scope key-custody boundary.
 *
 * A single signer holds ONE key; a Keyring holds several, indexed by the key PAGE they sit on. The vote
 * backends resolve `forPage(tx.signerUrl)` per transaction, so one running wallet can watch and sign for
 * many pages (multiple books, an ADI's several key pages, a treasury, …) — each with its own key/provider.
 *
 * `MapKeyring` is strict: it refuses to sign for a page it holds no key for (a real security property — an
 * unknown page arriving via the webhook trigger is not honoured). `singleKeyring` is the wildcard for the
 * single-key path and tests: one key, used for whatever page it is asked about.
 */
import { KeySigner, LocalSigner, LocalEcdsaP256Signer } from './signer.js';
import { VaultTransitSigner } from './vault-transit.js';
import { resolveLocalEcdsaKey, resolveLocalSeed, SignerSpec } from '../config.js';
import { Logger } from '../logger.js';

/** The parent key book of a signer page URL: acc://o.acme/book/1 -> acc://o.acme/book */
export function bookOf(pageUrl: string): string {
  return pageUrl.replace(/\/\d+$/, '');
}

/** Normalise a page/book URL for comparison: lowercase first (so an upper-case scheme still strips),
 * then drop the scheme and any trailing slashes. */
const norm = (u: string): string => u.toLowerCase().replace(/^acc:\/\//, '').replace(/\/+$/, '');

/** Construct the concrete KeySigner for one key spec (local key material, or Vault Transit). */
export function buildSignerFromSpec(spec: SignerSpec, logger: Logger, label: string): KeySigner {
  if (spec.provider === 'local-ecdsa-p256') {
    const der = resolveLocalEcdsaKey(spec.local);
    if (!der) throw new Error(`${label}: signer.provider=local-ecdsa-p256 requires local.private_key_der_hex or local.private_key_der_file`);
    logger.warn({ scope: label }, 'using LOCAL signer: this key is held in this process (see README "Security posture")');
    return new LocalEcdsaP256Signer(der);
  }
  if (spec.provider === 'vault-transit') {
    const v = spec.vault;
    if (!v?.addr || !v.key_name || !v.token) throw new Error(`${label}: vault-transit requires addr, key_name, token`);
    // key_type defaults to ed25519 inside the signer, where it is checked against what Vault actually
    // holds. Stating it here rather than defaulting silently is what makes a P-256 seat configurable.
    return new VaultTransitSigner({ addr: v.addr, keyName: v.key_name, token: v.token, ...(v.key_type ? { keyType: v.key_type } : {}) });
  }
  const seed = resolveLocalSeed(spec.local);
  if (seed) {
    logger.warn({ scope: label }, 'using LOCAL signer: this key is held in this process (see README "Security posture")');
    return new LocalSigner(seed);
  }
  if (spec.local?.allow_ephemeral) {
    logger.warn({ scope: label }, 'using LOCAL signer with an EPHEMERAL key — it matches no on-chain page; dev/test only');
    return LocalSigner.generate();
  }
  throw new Error(`${label}: signer.provider=local requires local.seed_hex or local.seed_file (set local.allow_ephemeral for dev)`);
}

/** One signing scope: a key page, its book (for signature-chain discovery), and the key that signs there.
 * The key carries its own signature type, so two scopes in one process may sign with different algorithms. */
export interface SigningScope {
  page: string;    // acc://org.acme/book/1
  book: string;    // acc://org.acme/book
  signer: KeySigner;
  /**
   * Further keys on the SAME page, addressed by a ref the deployment chooses -- Runbook F Phase F2.
   *
   * A key page holds several keys with a threshold, so a roster page is one page with one seat per
   * approver. `signer` above stays what it always was: the key this wallet signs with on that page
   * when nobody is named. These are the named ones.
   *
   * The ref is an opaque label from the config, deliberately: it is not an identity claim and nothing
   * here can check one. What binds a ref to a person is the key page entry it resolves to, and that
   * binding is on chain rather than in this file.
   */
  keys?: Record<string, KeySigner>;
  /**
   * Whose behalf this scope's key is held on, when it is somebody's. Runbook F Phase F4.
   *
   * Present only where the deployment declared it, and it travels onto every signature made here so
   * the record can say that the organisation signed in a person's name rather than as itself.
   */
  actsFor?: string;
}

export interface Keyring {
  /**
   * The signer whose key sits on `pageUrl`. Throws if no scope covers it.
   *
   * With `keyRef`, the named key on that page. Strict in both directions: an unknown page and an
   * unknown ref both throw, and a ref is NEVER allowed to fall back to the scope key. Falling back
   * would sign a named approver's vote with the organisation's key -- a substitution the record would
   * carry forever and nobody asked for.
   */
  forPage(pageUrl: string, keyRef?: string): KeySigner;
  /**
   * The whole scope covering `pageUrl`, not only its key. Throws for a page we hold nothing for,
   * exactly as `forPage` does.
   *
   * The vote path needs this because a signature carries more than the key that made it: whose behalf
   * the key is held on is a property of the SCOPE, and a signer object has no idea.
   */
  scopeFor(pageUrl: string): SigningScope;
  /** Every configured scope. */
  scopes(): SigningScope[];
  /** True only if every scope's key provider is reachable (or has no health probe). */
  healthy(): Promise<boolean>;
}

/** A keyring backed by an explicit page -> scope map. Strict: unknown pages are refused. */
export class MapKeyring implements Keyring {
  private readonly byPage = new Map<string, SigningScope>();
  constructor(scopes: SigningScope[]) {
    if (!scopes.length) throw new Error('keyring: at least one signing scope is required');
    for (const s of scopes) {
      const k = norm(s.page);
      if (this.byPage.has(k)) throw new Error(`keyring: duplicate scope for page ${s.page}`);
      this.byPage.set(k, s);
    }
  }
  scopeFor(pageUrl: string): SigningScope {
    const s = this.byPage.get(norm(pageUrl));
    if (!s) {
      const known = [...this.byPage.values()].map((x) => x.page).join(', ');
      throw new Error(`no signing key configured for page ${pageUrl} (known pages: ${known})`);
    }
    return s;
  }
  forPage(pageUrl: string, keyRef?: string): KeySigner {
    const s = this.scopeFor(pageUrl);
    if (keyRef === undefined) return s.signer;

    const named = s.keys?.[keyRef];
    if (!named) {
      const known = Object.keys(s.keys ?? {}).join(', ') || 'none configured';
      throw new Error(`no key "${keyRef}" configured on page ${s.page} (known keys: ${known})`);
    }
    return named;
  }
  scopes(): SigningScope[] { return [...this.byPage.values()]; }
  async healthy(): Promise<boolean> {
    for (const s of this.byPage.values()) {
      // Every key on the page, not only the scope's own. A roster whose second seat cannot reach its
      // custody backend fails at the moment somebody votes, and /healthz exists to say so before then.
      for (const key of [s.signer, ...Object.values(s.keys ?? {})]) {
        if (key.health && !(await key.health())) return false;
      }
    }
    return true;
  }
}

/** Wildcard keyring: one key, used for any page. The single-scope / test path. */
export function singleKeyring(signer: KeySigner, page = 'acc://unknown.acme/book/1'): Keyring {
  const scope: SigningScope = { page, book: bookOf(page), signer };
  return {
    forPage: () => signer,
    scopeFor: () => scope,
    scopes: () => [scope],
    healthy: async () => (signer.health ? signer.health() : true),
  };
}
