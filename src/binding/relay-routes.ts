/**
 * The five relay routes the Console's reader needs (DAX4C-F5, DAX4C-F13; scope `chain` of the decision-service relay), GET only, read-only,
 * Accumulate API v3 only, strictly validated, served through the SAME read cache as the signer's own decision binding. The Console parses
 * each answer strictly (an unknown member, a missing member or a value of the wrong type makes its whole read unreadable): the answers below
 * are pinned against copies of its parsers in test/binding-console-contract.test.ts:
 *
 *   GET /relay/data/:account        -> { entries: [{ txId, time?, elements: [hex] }] }      chain order; `time` = chain time, Unix
 *                                                                                           seconds, omitted when the node record
 *                                                                                           carries none (never invented)
 *   GET /relay/authorities/:account -> { authorities: [url] }                                the ENABLED authority key books NOW (a
 *                                                                                           `disabled: true` authority is dropped by the
 *                                                                                           node source); DAX-F131: also for the
 *                                                                                           principal account of a transaction, whose
 *                                                                                           enabled authorities the chain makes sign
 *   GET /relay/history/:account     -> { types: [string], incomplete: boolean }              the account's own main chain from its
 *                                                                                           creation; never an answer when the chain
 *                                                                                           could not be read back
 *   GET /relay/keybook/:book        -> { pages: [Page], delegateBooks: { <delegate url>: { pages: [Page] } } }
 *                                      Page = { url, version, keyHashes: [64 hex], delegates: [url], threshold, rejectThreshold, responseThreshold, entries: [{ keyHash?, delegate? }] }
 *                                      (DAX-F167a/F167c: the stored reject and response thresholds, 0 = the page sets none; the key entries in chain order.
 *                                      DAX-F170: the page's stored version (>= 1); threshold 0 only on an emptied page past the first (no entries);
 *                                      delegateBooks = every book the delegation reaches, transitively, each once, read as strictly; any failed read = 502)
 *                                                                                           the ROSTER of the Console's quorum (the current
 *                                                                                           members of a required book): a key seat is its
 *                                                                                           key hash, a delegate seat stands as its book url.
 *                                                                                           Cached by the TTL ALONE (key pages are not covered
 *                                                                                           by the chain-length key). Never read by an online
 *                                                                                           Grant or registration verdict.
 *   GET /relay/chainlen/:account    -> { length: number }                                    the main-chain length (ONE node query): the key
 *                                                                                           the Console cache keys its facts on, like this one
 *
 * `:account` is the acc:// URL, percent-encoded as ONE path segment. Not a generic chain proxy: `data`, `history` and `chainlen` answer only
 * for the four CERTEN data accounts (certen-grants, certen-subjects, certen-acceptances, certen-mandates); `authorities` for those, for an ADI
 * root and (DAX-F131, DECISION.md DE-110) for any other account that is not a key page: the Console's quorum reads the authority set of a
 * transaction's PRINCIPAL ACCOUNT (a payer data or token account) to know which required books Accumulate will make sign before execution.
 * That is one account query of public chain state, through the same read cache; `data`, `history` and `chainlen` stay CERTEN-only.
 * `keybook` for a key book URL. Anything else is 400. A fact the node could not give is 502 `unreadable`: never an empty
 * answer, never an allow. Every response carries `x-reader-queries`, `x-reader-cache-hits`, `x-reader-cache-misses` and
 * `x-reader-max-fact-age-ms` so a caller can measure what its read cost the node.
 */
import { isAccUrl, isAdiUrl } from '../core/grant-profile.js';
import type { CountedReader } from './read-cache.js';
import type { RosterPage } from './node-source.js';

export type AccountRoute = 'data' | 'authorities' | 'history' | 'keybook' | 'chainlen';

// AGT-2: + certen-mandates, the principal's mandate account the Console reads online and keys its cache on (findings AGT-F21, AGT-F24)
const DATA_ACCOUNT = /^acc:\/\/[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*\/certen-(?:grants|subjects|acceptances|mandates)$/;
const BOOK = /^acc:\/\/[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)+$/;

const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

export interface RelayAnswer { status: number; body: unknown; headers: Record<string, string> }

function headersOf(r: CountedReader): Record<string, string> {
  const s = r.stats();
  return {
    'x-reader-queries': String(s.queries),
    'x-reader-cache-hits': String(s.cacheHits),
    'x-reader-cache-misses': String(s.cacheMisses),
    'x-reader-max-fact-age-ms': String(Math.round(s.maxFactAgeMs)),
  };
}

export async function relayAccountRoute(reader: CountedReader, route: AccountRoute, rawAccount: string): Promise<RelayAnswer> {
  const refuse = (status: number, error: string): RelayAnswer => ({ status, body: { error }, headers: {} });
  let account: string;
  try {
    account = decodeURIComponent(rawAccount);
  } catch {
    return refuse(400, 'account must be a percent-encoded acc:// URL');
  }
  if (account !== account.toLowerCase() || !isAccUrl(account)) return refuse(400, 'account must be a lower-case acc:// URL');
  if (route === 'data' || route === 'history' || route === 'chainlen') {
    if (!DATA_ACCOUNT.test(account)) return refuse(400, 'account must be a certen-grants, certen-subjects, certen-acceptances or certen-mandates data account');
  } else if (route === 'authorities') {
    // DAX-F131: a CERTEN data account, an ADI root, or a transaction's principal account; never a key page (a page has no authority set of its own)
    if (!DATA_ACCOUNT.test(account) && !isAdiUrl(account) && (!BOOK.test(account) || /\/\d+$/.test(account))) return refuse(400, 'account must be an account URL (a CERTEN data account, an ADI or a principal account), not a key page');
  } else if (!BOOK.test(account) || /\/\d+$/.test(account)) {
    return refuse(400, 'book must be a key book URL (acc://<adi>/<book>), not a page');
  }

  if (route === 'data') {
    const e = await reader.dataEntries(account);
    const headers = headersOf(reader);
    if (e === null) return { status: 502, body: { error: 'unreadable' }, headers };
    return { status: 200, headers, body: { entries: e.map((x) => ({ txId: x.txId, ...(x.time === undefined ? {} : { time: x.time }), elements: x.elements.map(toHex) })) } };
  }
  if (route === 'chainlen') {
    const n = await reader.chainLength(account);
    const headers = headersOf(reader);
    return n === null ? { status: 502, body: { error: 'unreadable' }, headers } : { status: 200, headers, body: { length: n } };
  }
  if (route === 'authorities') {
    const a = await reader.authorities(account);
    const headers = headersOf(reader);
    return a === null ? { status: 502, body: { error: 'unreadable' }, headers } : { status: 200, headers, body: { authorities: a } };
  }
  if (route === 'history') {
    const h = await reader.accountHistory(account);
    const headers = headersOf(reader);
    return h === null ? { status: 502, body: { error: 'unreadable' }, headers } : { status: 200, headers, body: { types: h.types, incomplete: h.incomplete } };
  }
  const r = await rosterOf(reader, account);
  const headers = headersOf(reader);
  if (r === null) return { status: 502, body: { error: 'unreadable' }, headers };
  const delegateBooks: Record<string, { pages: unknown[] }> = {};
  for (const [url, pages] of r.delegateBooks) delegateBooks[url] = { pages: pages.map(pageAnswer) };
  return { status: 200, headers, body: { pages: r.pages.map(pageAnswer), delegateBooks } };
}

/** one page of the keybook answer: the same shape for the required book and for every delegate book */
function pageAnswer(x: RosterPage): unknown {
  return {
    url: x.url, version: x.version, keyHashes: x.keyHashes, delegates: x.delegates, threshold: x.threshold, rejectThreshold: x.rejectThreshold, responseThreshold: x.responseThreshold,
    entries: x.entries.map((e) => ({ ...(e.keyHash === null ? {} : { keyHash: e.keyHash }), ...(e.delegate === null ? {} : { delegate: e.delegate }) })),
  };
}

/** at most this many books in the delegation closure of one required book; more is unreadable, never a truncated closure */
export const MAX_DELEGATE_BOOKS = 64;

/**
 * DAX-F170 D3/D4: the roster of a required book AND of every book its delegation reaches. A delegate entry votes for its page only once ITS OWN book
 * decides (Accumulate block/sig_authority.go: the delegate's authority signature is produced when one of the delegate book's pages is ready,
 * block/transaction.go AuthorityWillVote 277-296 / SignerWillVote 297-383), so the Console needs each delegate book's pages, read as strictly as the
 * required book's, and theirs in turn: the transitive closure, each book read once (through the same read cache), keyed by the delegate url exactly as
 * an entry names it. A cycle (A -> B -> A; only self-delegation is refused, chain/update_key_page.go 162-166) closes on a book already read. ANY read
 * that fails (a node error, a missing account, an account that is not a key book, a page that breaks a rule) makes the whole roster unreadable.
 */
export async function rosterOf(reader: CountedReader, book: string): Promise<{ pages: RosterPage[]; delegateBooks: Map<string, RosterPage[]> } | null> {
  if (reader.keyBookPages === undefined) return null;
  const pages = await reader.keyBookPages(book);
  if (pages === null) return null;
  const delegateBooks = new Map<string, RosterPage[]>();
  const queue: string[] = [];
  const enqueue = (ps: RosterPage[]): void => {
    for (const p of ps) for (const d of p.delegates) if (!delegateBooks.has(d) && !queue.includes(d)) queue.push(d);
  };
  enqueue(pages);
  while (queue.length > 0) {
    const d = queue.shift()!;
    if (delegateBooks.size >= MAX_DELEGATE_BOOKS) return null;
    if (!BOOK.test(d) || /\/\d+$/.test(d)) return null; // a delegate that is not a key book URL cannot be read as one
    const dp = d === book ? pages : await reader.keyBookPages(d);
    if (dp === null) return null;
    delegateBooks.set(d, dp);
    enqueue(dp);
  }
  return { pages, delegateBooks };
}
