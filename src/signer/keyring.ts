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
import { EdSigner, LocalSigner } from './signer.js';
import { VaultTransitSigner } from './vault-transit.js';
import { resolveLocalSeed, SignerSpec } from '../config.js';
import { Logger } from '../logger.js';

/** The parent key book of a signer page URL: acc://o.acme/book/1 -> acc://o.acme/book */
export function bookOf(pageUrl: string): string {
  return pageUrl.replace(/\/\d+$/, '');
}

/** Normalise a page/book URL for comparison: lowercase first (so an upper-case scheme still strips),
 * then drop the scheme and any trailing slashes. */
const norm = (u: string): string => u.toLowerCase().replace(/^acc:\/\//, '').replace(/\/+$/, '');

/** Construct the concrete EdSigner for one key spec (local seed / seed_file / ephemeral, or Vault Transit). */
export function buildSignerFromSpec(spec: SignerSpec, logger: Logger, label: string): EdSigner {
  if (spec.provider === 'vault-transit') {
    const v = spec.vault;
    if (!v?.addr || !v.key_name || !v.token) throw new Error(`${label}: vault-transit requires addr, key_name, token`);
    return new VaultTransitSigner({ addr: v.addr, keyName: v.key_name, token: v.token });
  }
  const seed = resolveLocalSeed(spec.local);
  if (seed) {
    logger.warn({ scope: label }, 'using LOCAL signer: this key is held in this process (see README "Key posture")');
    return new LocalSigner(seed);
  }
  if (spec.local?.allow_ephemeral) {
    logger.warn({ scope: label }, 'using LOCAL signer with an EPHEMERAL key — it matches no on-chain page; dev/test only');
    return LocalSigner.generate();
  }
  throw new Error(`${label}: signer.provider=local requires local.seed_hex or local.seed_file (set local.allow_ephemeral for dev)`);
}

/** One signing scope: a key page, its book (for signature-chain discovery), and the key that signs there. */
export interface SigningScope {
  page: string;    // acc://org.acme/book/1
  book: string;    // acc://org.acme/book
  signer: EdSigner;
}

export interface Keyring {
  /** The signer whose key sits on `pageUrl`. Throws if no scope covers it. */
  forPage(pageUrl: string): EdSigner;
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
  forPage(pageUrl: string): EdSigner {
    const s = this.byPage.get(norm(pageUrl));
    if (!s) {
      const known = [...this.byPage.values()].map((x) => x.page).join(', ');
      throw new Error(`no signing key configured for page ${pageUrl} (known pages: ${known})`);
    }
    return s.signer;
  }
  scopes(): SigningScope[] { return [...this.byPage.values()]; }
  async healthy(): Promise<boolean> {
    for (const s of this.byPage.values()) {
      if (s.signer.health && !(await s.signer.health())) return false;
    }
    return true;
  }
}

/** Wildcard keyring: one key, used for any page. The single-scope / test path. */
export function singleKeyring(signer: EdSigner, page = 'acc://unknown.acme/book/1'): Keyring {
  const scope: SigningScope = { page, book: bookOf(page), signer };
  return {
    forPage: () => signer,
    scopes: () => [scope],
    healthy: async () => (signer.health ? signer.health() : true),
  };
}
