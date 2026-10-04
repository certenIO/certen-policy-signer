/**
 * The wrapper invariant, checked before every vote. Wrapper runbook, change 5.
 *
 * Trust Stamp's vote means "the person enrolled to this wrapper approved this exact transaction in a
 * live check". That is only worth anything if the wrapper still REQUIRES the vote — if some set of
 * signatures without Trust Stamp could satisfy it, our vote would decorate a decision already made.
 *
 * It holds by construction: changing a wrapper needs the wrapper's own vote, and therefore ours. So the
 * signer must (a) confirm it before each vote, and (b) refuse to co-sign any change that would break it.
 *
 * Wrapper book B with Trust Stamp's book T is valid when:
 *   1. B's authorities are exactly [B], not disabled. Another authority could govern B without us.
 *      (Changing authorities needs every authority, disabled ones included — `protocol/access_control.go:13`.)
 *   2. Every page of B has an entry whose delegate is T, with NO key hash. A key signature is matched to
 *      an entry by key hash alone (`protocol/keys.go:61`), so `{keyHash: K, delegate: T}` is a seat whoever
 *      holds K fills without us.
 *   3. On every page, acceptThreshold > entries − 1.
 *   4. B and all its pages are readable now. Unreadable is not "probably fine".
 *
 * ── NOT GUARDED HERE: THE UPDATEKEY RE-INDEX ───────────────────────────────────────────────────────
 *
 * A page counts votes by (key index, path) (`internal/database/signatures.go:20-41`), and `UpdateKey`
 * re-sorts the entry it changes without bumping the page version (`chain/update_key.go:183`,
 * `protocol/keys.go:72`). If the subscriber's entry sorts before T's, their book can vote, re-index with
 * `UpdateKey`, and vote again, meeting the 2-of-2 without us (reproduced on Kermit). That is a network
 * defect, to be fixed in accumulate-core (UpdateKey bumping the version clears the signature set). It is not
 * worked around here: a wrapper is accepted whatever its entry order, and Trust Stamp never signs a
 * transaction it was bypassed on, so it never attests one.
 */
import { RawAccumulateClient } from '../accumulate/raw-client.js';
import { PageEntry, PageState, pageStateOf } from '../ops/rotate.js';
import { GovernanceFact } from '../types.js';
import { sameUrl } from './path.js';

export interface BookState {
  authorities: Array<{ url: string; disabled: boolean }>;
  pageCount: number;
}

/** How the check reads the chain. `RawAccumulateClient`-backed in production (`chainWrapperReader`). */
export interface WrapperReader {
  readBook(url: string): Promise<BookState>;
  readPage(url: string): Promise<PageState>;
}

export type WrapperCheck =
  | { ok: true }
  /** `unreadable`: the state could not be confirmed. Still a refusal; but a retryable one. */
  | { ok: false; reason: string; unreadable?: boolean };

/**
 * Reads a book and its pages, refusing anything that is not the account type it should be — a record
 * that parses to nothing must not read as "a page with no entries and threshold one".
 */
export function chainWrapperReader(acc: RawAccumulateClient): WrapperReader {
  const account = async (url: string, type: string) => {
    const rec: any = await acc.query(url);
    const a = rec?.account ?? rec?.data ?? rec;
    if (a?.type !== type) throw new Error(`${url} is not a ${type} (got ${String(a?.type)})`);
    return a;
  };
  return {
    async readBook(url) {
      const a = await account(url, 'keyBook');
      const authorities = (Array.isArray(a.authorities) ? a.authorities : []).map((x: any) => ({ url: String(x?.url ?? ''), disabled: x?.disabled === true }));
      return { authorities, pageCount: Number(a.pageCount ?? 0) };
    },
    async readPage(url) {
      return pageStateOf(await account(url, 'keyPage'));
    },
  };
}

/** The pages of a book, in the network's naming: `<book>/1` … `<book>/<pageCount>`. */
export function pagesOf(book: string, pageCount: number): string[] {
  return Array.from({ length: pageCount }, (_, i) => `${book.replace(/\/+$/, '')}/${i + 1}`);
}

/** Conditions 1-3 over a state already read. Pure. */
/**
 * Entries in the network's key-page order (`protocol/keys.go:72-87` `AddKeySpec`): key hash bytes, an
 * empty one first; then an entry with no delegate first; then delegate URL as a lowercase string.
 */
export function networkOrder(entries: PageEntry[]): PageEntry[] {
  const cmp = (l: PageEntry, k: PageEntry): number => {
    const lh = l.keyHash ?? '';
    const kh = k.keyHash ?? '';
    if (lh !== kh) return lh < kh ? -1 : 1;        // lowercase hex compares as the bytes do
    if (l.delegate === null) return -1;
    if (k.delegate === null) return 1;
    const a = l.delegate.toLowerCase();
    const b = k.delegate.toLowerCase();
    return a < b ? -1 : a > b ? 1 : 0;
  };
  return [...entries].sort(cmp);
}

export function checkWrapperShape(B: string, T: string, book: BookState, pages: Array<{ url: string; state: PageState }>): WrapperCheck {
  if (book.authorities.length !== 1 || !sameUrl(book.authorities[0]!.url, B)) {
    return { ok: false, reason: `authorities must be exactly [${B}], found [${book.authorities.map((a) => a.url).join(', ')}]` };
  }
  if (book.authorities[0]!.disabled) return { ok: false, reason: `${B}'s own authority is disabled` };
  if (!(book.pageCount >= 1) || pages.length !== book.pageCount) return { ok: false, reason: `expected ${book.pageCount} page(s), have ${pages.length}` };
  for (const { url, state } of pages) {
    const n = state.entries.length;
    const t = state.entries.find((e) => e.delegate && sameUrl(e.delegate, T));
    if (!t) return { ok: false, reason: `${url} has no entry delegating to ${T}` };
    if (t.keyHash) return { ok: false, reason: `${url}'s ${T} entry also carries key hash ${t.keyHash}, which a key holder can fill without ${T}` };
    if (!(state.threshold > n - 1)) return { ok: false, reason: `${url} threshold ${state.threshold} with ${n} entries can be met without ${T}` };
  }
  return { ok: true };
}

/** Read B and every page, then check. Any read failure is a refusal, marked unreadable. */
export async function checkWrapper(r: WrapperReader, B: string, T: string, override?: { url: string; state: PageState }): Promise<WrapperCheck> {
  let book: BookState;
  const pages: Array<{ url: string; state: PageState }> = [];
  try {
    book = await r.readBook(B);
    for (const url of pagesOf(B, book.pageCount)) {
      pages.push({ url, state: override && sameUrl(override.url, url) ? override.state : await r.readPage(url) });
    }
  } catch (e) {
    return { ok: false, reason: `cannot read ${B}: ${(e as Error).message}`, unreadable: true };
  }
  return checkWrapperShape(B, T, book, pages);
}

/**
 * A page after an `UpdateKeyPage`, as the network would leave it. Mirrors accumulate-core
 * `chain/update_key_page.go:218-316` and `protocol/keys.go:49` — including the threshold clamp on removal
 * — so a change is judged on the page it really produces. An operation the network would reject fails
 * here too: such a transaction fails on chain, and we have no reason to co-sign it.
 *
 * Entries are matched the network's way (`findKeyPageEntry`): by key hash first, then by delegate.
 */
export function applyKeyPageOps(page: PageState, pageUrl: string, ops: GovernanceFact['operations']):
  { ok: true; page: PageState } | { ok: false; reason: string } {
  const entries: PageEntry[] = page.entries.map((e) => ({ ...e }));
  let threshold = page.threshold;
  // `EntryByDelegate` reads a page URL as its book (`protocol/authority.go:212-215`).
  const asBook = (u: string) => u.replace(/\/+$/, '').replace(/\/\d+$/, '');
  const find = (kh?: unknown, dg?: unknown) => {
    let i = typeof kh === 'string' && kh ? entries.findIndex((e) => e.keyHash === kh.toLowerCase()) : -1;
    if (i < 0 && typeof dg === 'string' && dg) i = entries.findIndex((e) => e.delegate !== null && sameUrl(e.delegate, asBook(dg)));
    return i;
  };
  const pageIndex = Number(/\/(\d+)$/.exec(pageUrl)?.[1] ?? 0);
  for (const op of ops) {
    if (op.unrecognized) return { ok: false, reason: `unrecognised operation ${op.type}` };
    switch (op.type) {
      case 'add': {
        if (find(op.keyHash, op.delegate) >= 0) return { ok: false, reason: 'add: duplicate entry' };
        entries.push({ keyHash: typeof op.keyHash === 'string' ? op.keyHash.toLowerCase() : null, delegate: typeof op.delegate === 'string' ? op.delegate : null });
        break;
      }
      case 'remove': {
        const i = find(op.keyHash, op.delegate);
        if (i < 0) return { ok: false, reason: 'remove: entry not found' };
        if (entries.length === 1 && pageIndex === 1) return { ok: false, reason: 'remove: last key of page 1' };
        entries.splice(i, 1);
        if (threshold > entries.length) threshold = entries.length;           // the network's clamp
        break;
      }
      case 'update': {
        const i = find(op.oldKeyHash, op.oldDelegate);
        if (i < 0) return { ok: false, reason: 'update: entry not found' };
        const j = find(op.newKeyHash, op.newDelegate);
        if (j >= 0 && j !== i) return { ok: false, reason: 'update: duplicate entry' };
        entries[i] = { keyHash: typeof op.newKeyHash === 'string' ? op.newKeyHash.toLowerCase() : null, delegate: typeof op.newDelegate === 'string' ? op.newDelegate : null };
        break;
      }
      case 'setThreshold': {
        const t = Number(op.threshold);
        if (!(t > 0 && t <= entries.length)) return { ok: false, reason: `setThreshold ${t} with ${entries.length} entries` };
        threshold = t;
        break;
      }
      // Reject/response thresholds and allowed-operation lists change who can REJECT or which types the
      // page signs, never who can approve without us. They do not touch the invariant.
      case 'setRejectThreshold':
      case 'setResponseThreshold': {
        const t = Number(op.threshold);
        if (!(t < entries.length)) return { ok: false, reason: `${op.type} ${t} with ${entries.length} entries` };   // update_key_page.go:279-292
        break;
      }
      case 'updateAllowed':
        break;
      default:
        return { ok: false, reason: `unknown operation ${op.type}` };
    }
  }
  const ordered = networkOrder(entries);
  return {
    ok: true,
    page: { ...page, threshold, entries: ordered, keyHashes: ordered.map((e) => e.keyHash).filter((h): h is string => Boolean(h)) },
  };
}

function isUnder(url: string, book: string): boolean {
  const u = url.toLowerCase().replace(/\/+$/, '');
  const b = book.toLowerCase().replace(/\/+$/, '');
  return u === b || u.startsWith(`${b}/`);
}

/** Is this transaction's principal the wrapper book itself or one of its pages? */
export function targetsWrapper(principal: string, B: string): boolean {
  return isUnder(principal, B);
}

/**
 * A transaction on the wrapper itself (principal B or one of its pages): co-sign it only if the wrapper
 * is still valid AFTER it executes.
 *
 *   UpdateKeyPage on a page of B → simulate, re-check. Adding a key without raising the threshold, or
 *                                  removing T, fails here.
 *   CreateKeyPage on B           → refuse: a new page starts at threshold 1 with no T
 *                                  (`chain/create_key_page.go:68`).
 *   UpdateAccountAuth on B       → refuse: it changes who governs B.
 *   UpdateKey on a page of B     → we are never asked (it needs only the initiator,
 *                                  `chain/update_key.go:92-140`). It is safe only because condition 3 holds:
 *                                  it can move an entry to the keyed region, never ahead of T. Re-checked on
 *                                  the current state.
 *   anything else on B           → refuse. A wrapper does one thing, and an unexpected body on it is
 *                                  not something to approve on a guess.
 */
export async function checkWrapperChange(
  r: WrapperReader, B: string, T: string,
  tx: { bodyType: string; account: string; governance?: GovernanceFact },
): Promise<WrapperCheck> {
  switch (tx.bodyType) {
    case 'updateKeyPage': {
      if (!tx.governance) return { ok: false, reason: 'updateKeyPage whose operations could not be read' };
      // A key page is the principal of UpdateKeyPage. Anything else under B (the book itself) is a body
      // that cannot execute, and is refused rather than reported as an unreadable page forever.
      if (!/\/\d+$/.test(tx.account.replace(/\/+$/, ''))) return { ok: false, reason: `updateKeyPage on ${tx.account}, which is not a page of ${B}` };
      let current: PageState;
      try {
        current = await r.readPage(tx.account);
      } catch (e) {
        return { ok: false, reason: `cannot read ${tx.account}: ${(e as Error).message}`, unreadable: true };
      }
      const after = applyKeyPageOps(current, tx.account, tx.governance.operations);
      if (!after.ok) return { ok: false, reason: `the change would fail on chain: ${after.reason}` };
      const res = await checkWrapper(r, B, T, { url: tx.account, state: after.page });
      return res.ok || res.unreadable ? res : { ok: false, reason: `after this change: ${res.reason}` };
    }
    case 'createKeyPage':
      return { ok: false, reason: `createKeyPage on ${B} would add a page at threshold 1 without ${T}` };
    case 'updateAccountAuth':
      return { ok: false, reason: `updateAccountAuth on ${B} changes who governs the wrapper` };
    case 'updateKey':
      return checkWrapper(r, B, T);
    default:
      return { ok: false, reason: `${tx.bodyType} on the wrapper itself is not something Trust Stamp co-signs` };
  }
}
