/**
 * THE CONSOLE'S STRICT PARSERS, COPIED AS FIXTURES (no import across repos). Source: src/relay/routes.ts of branch pl/dax-f170-chain-parity of the
 * Console (certen-approval-console) at commit e72b27e555a5d381da4b0b224a1d65857a5e5bf8; sha256 of that file with LF line endings 164bb891fe55f060b9c7b3f874f1f89c8ef2bc516c8d82706f58f0622822dd71 (DAX-F167a: the per-page rejectThreshold; DAX-F167c: the per-page responseThreshold and entries;
 * DAX-F170: every page member REQUIRED incl. `version`, an emptied later page (D9), and `delegateBooks`, the delegation closure; parseKeybook now answers { pages, delegateBooks }).
 * Everything from `type Obj` to `parseKeybook` below is that file's text, unchanged; only the import line differs (the signer's own copy of the core).
 * When the Console changes a route shape this file is re-copied and test/binding-console-contract.test.ts says what the signer must now answer.
 *
 * `parseChainLen` is NOT the Console's: its routes.ts at f50d5b3 has no chain-length route yet. It is the shape the DAX-4S round 3 addendum
 * fixed ({ length: number }, nothing else) written in the style of the parsers above, so the Console's future parser can be diffed against it.
 */
import type { AccountHistory, DataEntry } from '../../src/core/reader.js';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
/** exactly the required keys, plus any of the optional ones */
const only = (o: Obj, keys: readonly string[], optional: readonly string[] = []): boolean => Object.keys(o).every((k) => keys.includes(k) || optional.includes(k)) && keys.every((k) => k in o);
const HEX64 = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})*$/;
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

export function parseDataEntries(v: unknown): DataEntry[] | null {
  if (!isObj(v) || !only(v, ['entries']) || !Array.isArray(v['entries'])) return null;
  const out: DataEntry[] = [];
  for (const e of v['entries'] as unknown[]) {
    if (!isObj(e) || !only(e, ['txId', 'time', 'elements']) || typeof e['txId'] !== 'string' || e['txId'] === '' || !isTime(e['time']) || !Array.isArray(e['elements'])) return null;
    const elements: Uint8Array[] = [];
    for (const h of e['elements'] as unknown[]) {
      if (typeof h !== 'string' || !HEX.test(h)) return null;
      elements.push(Uint8Array.from(Buffer.from(h, 'hex')));
    }
    out.push({ txId: e['txId'], time: e['time'], elements });
  }
  return out;
}

export function parseAuthorities(v: unknown): string[] | null {
  if (!isObj(v) || !only(v, ['authorities']) || !Array.isArray(v['authorities'])) return null;
  const a = v['authorities'] as unknown[];
  return a.every((x) => typeof x === 'string' && x !== '') ? (a as string[]) : null;
}

export function parseHistory(v: unknown): AccountHistory | null {
  if (!isObj(v) || !only(v, ['types', 'incomplete']) || !Array.isArray(v['types']) || typeof v['incomplete'] !== 'boolean') return null;
  const types = v['types'] as unknown[];
  if (!types.every((t) => typeof t === 'string' && t !== '')) return null;
  return { types: types as string[], incomplete: v['incomplete'] };
}

/** `{ length }` with a non-negative safe integer and nothing else; anything else is unreadable (the cache then falls back to the TTL alone). */
export function parseChainLength(v: unknown): number | null {
  if (!isObj(v) || !only(v, ['length'])) return null;
  const n = v['length'];
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 ? n : null;
}

/** one key entry of a page as the relay reads it (DAX-F167c): its key hash, its delegate, or both (null where it holds none) */
export interface KeybookEntry { keyHash: string | null; delegate: string | null }
/**
 * rejectThreshold: the page's stored reject threshold (0 = the page sets none); responseThreshold: its stored response threshold (0 = none); entries:
 * its key entries in chain order (DAX-F167c); version (DAX-F170 D2): the page's stored version, 1 or more. All REQUIRED since DAX-F170: an answer of
 * an older relay that lacks any of them is unreadable (authority_unreadable by name, never a guess). A page AFTER the first may be emptied (D9):
 * no entries, threshold, rejectThreshold and responseThreshold all 0.
 */
export interface KeybookPage { url: string; version: number; keyHashes: string[]; delegates: string[]; threshold: number; rejectThreshold: number; responseThreshold: number; entries: KeybookEntry[] }
/**
 * DAX-F170 (signer pl/dax-f170-relay-versions, checkins/F170-relay.md section 1): the whole keybook answer: the book's pages and `delegateBooks`, the
 * transitive closure of the books named as a delegate by any entry, each book once, keyed exactly as the entry names it, its pages read by the same
 * rules (at most 64 books; always present, {} when no page has a delegate).
 */
export interface KeybookRead { pages: KeybookPage[]; delegateBooks: Record<string, KeybookPage[]> }
const MAX_DELEGATE_BOOKS = 64;

/** the entries member (DAX-F167c): closed { keyHash?, delegate? } with at least one; their key hashes and delegates, in order, exactly the page's lists. null otherwise */
function parseEntries(v: unknown, keyHashes: string[], delegates: string[]): KeybookEntry[] | null {
  if (!Array.isArray(v)) return null;
  const out: KeybookEntry[] = [];
  for (const e of v as unknown[]) {
    if (!isObj(e) || !only(e, [], ['keyHash', 'delegate']) || Object.keys(e).length === 0) return null;
    if ('keyHash' in e && (typeof e['keyHash'] !== 'string' || !HEX64.test(e['keyHash']))) return null;
    if ('delegate' in e && typeof e['delegate'] !== 'string') return null;
    out.push({ keyHash: 'keyHash' in e ? (e['keyHash'] as string) : null, delegate: 'delegate' in e ? (e['delegate'] as string) : null });
  }
  const ks = out.flatMap((e) => (e.keyHash === null ? [] : [e.keyHash]));
  const ds = out.flatMap((e) => (e.delegate === null ? [] : [e.delegate]));
  if (ks.length !== keyHashes.length || ks.some((k, i) => k !== keyHashes[i]) || ds.length !== delegates.length || ds.some((d, i) => d !== delegates[i])) return null;
  return out;
}

/** one book's pages: each closed and strict; the first never emptied; an emptied later page carries every threshold 0 (D9); null otherwise */
function parsePages(v: unknown): KeybookPage[] | null {
  if (!Array.isArray(v)) return null;
  const out: KeybookPage[] = [];
  for (const [i, p] of (v as unknown[]).entries()) {
    if (!isObj(p) || !only(p, ['url', 'version', 'keyHashes', 'delegates', 'threshold', 'rejectThreshold', 'responseThreshold', 'entries']) || typeof p['url'] !== 'string' || !Array.isArray(p['keyHashes']) || !Array.isArray(p['delegates'])) return null;
    if (!isTime(p['version']) || p['version'] < 1 || !isTime(p['threshold']) || !isTime(p['rejectThreshold']) || !isTime(p['responseThreshold'])) return null;
    if (!(p['keyHashes'] as unknown[]).every((h) => typeof h === 'string' && HEX64.test(h)) || !(p['delegates'] as unknown[]).every((d) => typeof d === 'string')) return null;
    const entries = parseEntries(p['entries'], p['keyHashes'] as string[], p['delegates'] as string[]);
    if (entries === null) return null;
    const emptied = entries.length === 0;
    // D9: an emptied page is a later page with every threshold 0; a page with entries has an acceptance threshold of 1 or more
    if (emptied ? i === 0 || p['threshold'] !== 0 || p['rejectThreshold'] !== 0 || p['responseThreshold'] !== 0 : p['threshold'] < 1) return null;
    out.push({ url: p['url'], version: p['version'], keyHashes: p['keyHashes'] as string[], delegates: p['delegates'] as string[], threshold: p['threshold'], rejectThreshold: p['rejectThreshold'], responseThreshold: p['responseThreshold'], entries });
  }
  return out;
}

/** the keybook answer (DAX-F170): exactly `{ pages, delegateBooks }`, read strictly as a whole; an older relay's answer (no versions, no delegateBooks) is null */
export function parseKeybook(v: unknown): KeybookRead | null {
  if (!isObj(v) || !only(v, ['pages', 'delegateBooks']) || !isObj(v['delegateBooks'])) return null;
  const pages = parsePages(v['pages']);
  if (pages === null) return null;
  const names = Object.keys(v['delegateBooks']);
  if (names.length > MAX_DELEGATE_BOOKS) return null;
  const delegateBooks: Record<string, KeybookPage[]> = {};
  for (const name of names) {
    const b = (v['delegateBooks'] as Obj)[name];
    if (name === '' || !isObj(b) || !only(b, ['pages'])) return null;
    const dp = parsePages(b['pages']);
    if (dp === null || dp.length === 0) return null;
    delegateBooks[name] = dp;
  }
  return { pages, delegateBooks };
}

/** NOT the Console's text (see the header): GET /relay/chainlen/:account -> { length: number } */
export function parseChainLen(v: unknown): number | null {
  if (!isObj(v) || !only(v, ['length']) || typeof v['length'] !== 'number' || !Number.isSafeInteger(v['length']) || v['length'] < 0) return null;
  return v['length'];
}
