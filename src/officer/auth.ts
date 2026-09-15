/**
 * Officer authentication without a shared secret. FICTIONAL Business Transaction Controls lab, Phase 7.
 * Contract: transaction-controls docs/interfaces/phase7-personal-signing-contract.md §3.
 *
 *   x-officer-auth: v1 key=<SPKI DER hex>,ts=<unix ms>,sig=<DER ECDSA hex, or 64-byte r‖s hex>
 *   signed message = UTF-8 "tcl-officer-read/v1\n<METHOD>\n<path including query>\n<ts>", ECDSA-P256-SHA256
 *
 * Accepted only when the timestamp is within ±120 s, the signature verifies, and sha256(SPKI) is a key hash on
 * one of this signer's configured human pages, read live (cached at most 30 s). Every failure is the same
 * answer to the caller; the reason goes to the log only.
 */
import type http from 'node:http';
import type { PageState } from '../ops/rotate.js';
import type { Logger } from '../logger.js';
import { P256Key, hexBytes, parseP256Spki, verifyP256Sha256 } from './crypto.js';

export const OFFICER_AUTH_HEADER = 'x-officer-auth';
export const OFFICER_AUTH_FAILED = 'officer_auth_failed';
export const OFFICER_AUTH_SKEW_MS = 120_000;
export const PAGE_CACHE_MAX_MS = 30_000;

export function officerAuthMessage(method: string, pathAndQuery: string, ts: string): Uint8Array {
  return new Uint8Array(Buffer.from(`tcl-officer-read/v1\n${method.toUpperCase()}\n${pathAndQuery}\n${ts}`, 'utf8'));
}

export interface ParsedOfficerAuth { key: P256Key; ts: string; sig: Uint8Array }

const HEADER_RE = /^v1 key=([0-9a-fA-F]+),ts=(\d{1,16}),sig=([0-9a-fA-F]+)$/;

export function parseOfficerAuthHeader(h: unknown): ParsedOfficerAuth | undefined {
  if (typeof h !== 'string' || h.length > 2048) return undefined;
  const m = HEADER_RE.exec(h.trim());
  if (!m) return undefined;
  const spki = hexBytes(m[1], 512);
  const sig = hexBytes(m[3], 128);
  if (!spki || !sig) return undefined;
  const key = parseP256Spki(spki);
  return key ? { key, ts: m[2], sig } : undefined;
}

export interface OfficerAuthDeps {
  humanPages: string[];
  readPage: (page: string) => Promise<PageState>;
  now?: () => number;
  cacheMs?: number;
  logger: Logger;
}

export interface AuthenticatedOfficer {
  key: P256Key;
  /** The configured human pages that list this key hash (as read, ≤ cacheMs old). */
  pages: string[];
}

/** Returns an authenticator: the officer on success, `undefined` on any failure. */
export function createOfficerAuthenticator(d: OfficerAuthDeps) {
  const now = d.now ?? Date.now;
  const cacheMs = Math.min(d.cacheMs ?? PAGE_CACHE_MAX_MS, PAGE_CACHE_MAX_MS);
  const cache = new Map<string, { at: number; keyHashes: string[] }>();

  async function keyHashesOf(page: string): Promise<string[] | undefined> {
    const hit = cache.get(page);
    if (hit && now() - hit.at <= cacheMs) return hit.keyHashes;
    try {
      const st = await d.readPage(page);
      cache.set(page, { at: now(), keyHashes: st.keyHashes.map((k) => k.toLowerCase()) });
      return st.keyHashes;
    } catch (e) {
      // An unreadable page lists nobody: never cached, never a pass.
      d.logger.warn({ page, err: (e as Error).message }, 'officer auth: human page unreadable');
      return undefined;
    }
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
    if (!verifyP256Sha256(parsed.key, msg, parsed.sig)) {
      d.logger.warn({ audit: 'officer_auth_rejected', reason: 'bad_signature', keyHash: parsed.key.keyHash }, 'officer auth rejected');
      return undefined;
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
