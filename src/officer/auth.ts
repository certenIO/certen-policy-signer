/**
 * Officer authentication without a shared secret. FICTIONAL Business Transaction Controls lab, Phase 7.
 * Contract: transaction-controls docs/interfaces/phase7-personal-signing-contract.md §3.
 *
 *   x-officer-auth: v1 key=<SPKI DER hex>,ts=<unix ms>,sig=<DER ECDSA hex, or 64-byte r‖s hex>
 *   signed message = UTF-8 "tcl-officer-read/v1\n<METHOD>\n<path including query>\n<ts>", ECDSA-P256-SHA256
 *
 * The key is a P-256 SPKI (ECDSA-P256-SHA256) or an ed25519 key, raw 32 bytes or RFC 8410 SPKI (ed25519 over the message): finding
 * AGT-F42, the validators settle ed25519 and refuse ecdsaSha256 (G-42).
 *
 * Accepted only when the timestamp is within ±120 s, the signature verifies, and sha256(SPKI) is a key hash on
 * one of this signer's configured human pages, read live (cached at most 30 s). Every failure is the same
 * answer to the caller; the reason goes to the log only.
 *
 * A DELEGATED officer (finding AGT-F117): the officer's key sits on a page of their OWN book, and that book is a delegate entry on the
 * human page (an officers page listing officer books, the AGT lab's shape). The header then names where the key sits and the delegation
 * path, exactly as the intake's prepare body does:
 *   x-officer-auth: v1 key=<..>,ts=<..>,sig=<..>,page=<acc://officer.acme/book/1>[,delegators=<acc://principal.acme/book/3>[;<..>]]
 * (delegators outermost LAST, at most 4, delegators[0] holds page's book as a delegate.) Accepted only when the key hash is on `page`, each
 * delegator page lists the previous book as a delegate, and the outermost page is a configured human page - every page read live. The
 * hints only say where to look: possession of the key is proven by the signature, and the intake re-checks the same path on prepare.
 * Without the hints the direct check above is unchanged.
 */
import type http from 'node:http';
import type { PageState } from '../ops/rotate.js';
import type { Logger } from '../logger.js';
import { OfficerKey, hexBytes, parseOfficerKey, verifyOfficerMessage } from './crypto.js';

export const OFFICER_AUTH_HEADER = 'x-officer-auth';
export const OFFICER_AUTH_FAILED = 'officer_auth_failed';
export const OFFICER_AUTH_SKEW_MS = 120_000;
export const PAGE_CACHE_MAX_MS = 30_000;

export function officerAuthMessage(method: string, pathAndQuery: string, ts: string): Uint8Array {
  return new Uint8Array(Buffer.from(`tcl-officer-read/v1\n${method.toUpperCase()}\n${pathAndQuery}\n${ts}`, 'utf8'));
}

export interface ParsedOfficerAuth { key: OfficerKey; ts: string; sig: Uint8Array; /** AGT-F117: where a delegated officer's key sits, and the delegation path (outermost last) */ page?: string; delegators?: string[] }

const ACC_PAGE = 'acc://[A-Za-z0-9][A-Za-z0-9._/-]*/[0-9]+';
const HEADER_RE = new RegExp(`^v1 key=([0-9a-fA-F]+),ts=(\\d{1,16}),sig=([0-9a-fA-F]+)(?:,page=(${ACC_PAGE}))?(?:,delegators=(${ACC_PAGE}(?:;${ACC_PAGE}){0,3}))?$`);
export const MAX_AUTH_DELEGATORS = 4;

export function parseOfficerAuthHeader(h: unknown): ParsedOfficerAuth | undefined {
  if (typeof h !== 'string' || h.length > 2048) return undefined;
  const m = HEADER_RE.exec(h.trim());
  if (!m) return undefined;
  const spki = hexBytes(m[1], 512);
  const sig = hexBytes(m[3], 128);
  if (!spki || !sig) return undefined;
  const key = parseOfficerKey(spki);
  if (!key) return undefined;
  if (m[5] !== undefined && m[4] === undefined) return undefined;   // a delegation path without the page the key sits on
  return { key, ts: m[2], sig, ...(m[4] !== undefined ? { page: m[4] } : {}), ...(m[5] !== undefined ? { delegators: m[5].split(';') } : {}) };
}

export interface OfficerAuthDeps {
  humanPages: string[];
  readPage: (page: string) => Promise<PageState>;
  now?: () => number;
  cacheMs?: number;
  logger: Logger;
}

export interface AuthenticatedOfficer {
  key: OfficerKey;
  /** The configured human pages that list this key hash (as read, ≤ cacheMs old). */
  pages: string[];
}

/** Returns an authenticator: the officer on success, `undefined` on any failure. */
export function createOfficerAuthenticator(d: OfficerAuthDeps) {
  const now = d.now ?? Date.now;
  const cacheMs = Math.min(d.cacheMs ?? PAGE_CACHE_MAX_MS, PAGE_CACHE_MAX_MS);
  const cache = new Map<string, { at: number; keyHashes: string[]; delegates: string[] }>();
  const norm = (u: string) => u.toLowerCase().replace(/\/+$/, '');
  const bookOf = (page: string) => norm(page).replace(/\/\d+$/, '');
  async function readOf(page: string): Promise<{ keyHashes: string[]; delegates: string[] } | undefined> {
    const hit = cache.get(norm(page));
    if (hit && now() - hit.at <= cacheMs) return hit;
    try {
      const st = await d.readPage(page);
      const v = { at: now(), keyHashes: st.keyHashes.map((k) => k.toLowerCase()), delegates: (st.entries ?? []).filter((e) => e.delegate).map((e) => norm(String(e.delegate))) };
      cache.set(norm(page), v);
      return v;
    } catch (e) {
      // An unreadable page lists nobody: never cached, never a pass.
      d.logger.warn({ page, err: (e as Error).message }, 'officer auth: page unreadable');
      return undefined;
    }
  }
  async function keyHashesOf(page: string): Promise<string[] | undefined> { return (await readOf(page))?.keyHashes; }
  /** AGT-F117: the key on `page`, each delegator listing the previous book, the outermost a configured human page; the human page reached, or the refusal reason */
  async function delegatedHumanPage(keyHash: string, page: string, delegators: string[]): Promise<{ page: string } | { reason: string }> {
    if (delegators.length > MAX_AUTH_DELEGATORS) return { reason: 'too_many_delegators' };
    const st = await readOf(page);
    if (!st) return { reason: 'page_unreadable' };
    if (!st.keyHashes.includes(keyHash)) return { reason: 'key_not_on_page' };
    let prevBook = bookOf(page);
    for (const del of delegators) {
      const ds = await readOf(del);
      if (!ds) return { reason: 'page_unreadable' };
      if (!ds.delegates.includes(prevBook)) return { reason: 'delegation_not_on_page' };
      prevBook = bookOf(del);
    }
    const outermost = delegators.length ? delegators[delegators.length - 1]! : page;
    const human = d.humanPages.find((h) => norm(h) === norm(outermost));
    return human ? { page: human } : { reason: 'key_not_on_human_page' };
  }

  return async function authenticate(req: http.IncomingMessage): Promise<AuthenticatedOfficer | undefined> {
    const parsed = parseOfficerAuthHeader(req.headers[OFFICER_AUTH_HEADER]);
    if (!parsed) return undefined;
    const ts = Number(parsed.ts);
    if (!Number.isSafeInteger(ts) || Math.abs(now() - ts) > OFFICER_AUTH_SKEW_MS) {
      d.logger.warn({ audit: 'officer_auth_rejected', reason: 'stale_timestamp', keyHash: parsed.key.keyHash }, 'officer auth rejected');
      return undefined;
    }
    const msg = officerAuthMessage(req.method ?? 'GET', req.url ?? '/', parsed.ts);
    if (!verifyOfficerMessage(parsed.key, msg, parsed.sig)) {
      d.logger.warn({ audit: 'officer_auth_rejected', reason: 'bad_signature', keyHash: parsed.key.keyHash }, 'officer auth rejected');
      return undefined;
    }
    if (parsed.page !== undefined) {
      const r = await delegatedHumanPage(parsed.key.keyHash, parsed.page, parsed.delegators ?? []);
      if ('reason' in r) {
        d.logger.warn({ audit: 'officer_auth_rejected', reason: r.reason, keyHash: parsed.key.keyHash, page: parsed.page, delegators: parsed.delegators ?? [] }, 'officer auth rejected');
        return undefined;
      }
      return { key: parsed.key, pages: [r.page] };
    }
    const pages: string[] = [];
    for (const p of d.humanPages) {
      const hashes = await keyHashesOf(p);
      if (hashes?.map((h) => h.toLowerCase()).includes(parsed.key.keyHash)) pages.push(p);
    }
    if (!pages.length) {
      d.logger.warn({ audit: 'officer_auth_rejected', reason: 'key_not_on_human_page', keyHash: parsed.key.keyHash }, 'officer auth rejected');
      return undefined;
    }
    return { key: parsed.key, pages };
  };
}
