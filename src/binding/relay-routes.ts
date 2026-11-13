/**
 * The five relay routes the Console's reader needs (DAX4C-F5, DAX4C-F13; scope `chain` of the decision-service relay), GET only, read-only,
 * Accumulate API v3 only, strictly validated, served through the SAME read cache as the signer's own decision binding. The Console parses
 * each answer strictly (an unknown member, a missing member or a value of the wrong type makes its whole read unreadable): the answers below
 * are pinned against copies of its parsers in test/binding-console-contract.test.ts:
 *
 *   GET /relay/data/:account        -> { entries: [{ txId, time?, elements: [hex] }] }      chain order; `time` = chain time, Unix
 *                                                                                           seconds, omitted when the node record
 *                                                                                           carries none (never invented)
 *   GET /relay/authorities/:account -> { authorities: [url] }                                the authority key books NOW
 *   GET /relay/history/:account     -> { types: [string], incomplete: boolean }              the account's own main chain from its
 *                                                                                           creation; never an answer when the chain
 *                                                                                           could not be read back
 *   GET /relay/keybook/:book        -> { pages: [{ url, keyHashes: [64 hex], delegates: [url], threshold }] }
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
 * for the three CERTEN data accounts (certen-grants, certen-subjects, certen-acceptances); `authorities` for those and for an ADI
 * root; `keybook` for a key book URL. Anything else is 400. A fact the node could not give is 502 `unreadable`: never an empty
 * answer, never an allow. Every response carries `x-reader-queries`, `x-reader-cache-hits`, `x-reader-cache-misses` and
 * `x-reader-max-fact-age-ms` so a caller can measure what its read cost the node.
 */
import { isAccUrl, isAdiUrl } from '../core/grant-profile.js';
import type { CountedReader } from './read-cache.js';

export type AccountRoute = 'data' | 'authorities' | 'history' | 'keybook' | 'chainlen';

const DATA_ACCOUNT = /^acc:\/\/[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*\/certen-(?:grants|subjects|acceptances)$/;
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
    if (!DATA_ACCOUNT.test(account)) return refuse(400, 'account must be a certen-grants, certen-subjects or certen-acceptances data account');
  } else if (route === 'authorities') {
    if (!DATA_ACCOUNT.test(account) && !isAdiUrl(account)) return refuse(400, 'account must be a CERTEN data account or an ADI');
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
  const p = reader.keyBookPages === undefined ? null : await reader.keyBookPages(account);
  const headers = headersOf(reader);
  return p === null ? { status: 502, body: { error: 'unreadable' }, headers } : { status: 200, headers, body: { pages: p.map((x) => ({ url: x.url, keyHashes: x.keyHashes, delegates: x.delegates, threshold: x.threshold })) } };
}
