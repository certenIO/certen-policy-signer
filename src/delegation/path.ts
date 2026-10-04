/**
 * Which delegation paths Trust Stamp must sign on for one transaction. Wrapper runbook, change 2.
 *
 * ── WHY A PATH PER TRANSACTION ─────────────────────────────────────────────────────────────────────
 *
 * In the `delegate` model the path is fixed at boot (`[wallet.delegator_url]`). A wrapper's path is not:
 * Alice's wrapper `P/id/1` sits on the treasury page and on the board page, and her vote on a treasury
 * transaction travels `[P/id/1, treasury/1]` while one on a board transaction travels `[P/id/1, board/1]`.
 * Trust Stamp's vote must carry the SAME remaining path as hers, because votes on a page are counted per
 * delegation path (accumulate-core `block/transaction.go` `SignerWillVote`, `entry.PathHash()`). A vote
 * on any other path counts toward nothing.
 *
 * ── WHERE THE PATH COMES FROM ──────────────────────────────────────────────────────────────────────
 *
 * Not from the human's key signature. That one is recorded with whatever delegators it CLAIMS, before
 * any hop checks them (`block/sig_user.go`; the check is at `block/sig_authority.go:159`), and only on
 * the signer's own partition, so read at the principal it is invisible whenever the person's ADI sits on
 * another BVN (`internal/api/v3/load.go:184`, `internal/database/signatures.go:112-117`).
 *
 * From the AUTHORITY signature the person's book sends to the wrapper page once their own page reaches
 * its threshold, read at the wrapper book's partition. The network records it on the wrapper page only
 * after checking that the book is a delegate there, and its `delegator` list is the remaining path in hop
 * order, starting at the wrapper page — exactly what Trust Stamp's vote must carry, since our book's
 * authority signature arrives at the same page with the same list and the page counts both under one
 * path hash (`Path = Delegator[1:]`, `block/sig_authority.go:176-185`). Custody below the person needs no
 * special case: whatever hops came before the wrapper were consumed on the way up.
 *
 * ── WHAT IS DELIBERATELY NOT DECIDED HERE ──────────────────────────────────────────────────────────
 *
 * Whether the wrapper is still sound (Trust Stamp mandatory on every page) is `checkWrapper`'s job,
 * called per path before the policy decision. This module only answers "which paths", and
 * `isEnrolledWrapperPage` is the gate on which wrappers count at all.
 */
import { AuthorityVote } from '../accumulate/client.js';
import { sha256Hex } from '../accumulate/signing.js';

export interface WrapperPath {
  /** The enrolled wrapper page the human signature passed through: the first hop Trust Stamp signs on. */
  wrapperPage: string;
  /** Hop order (first hop first), starting at `wrapperPage`. What `buildPreimage` takes as `delegators`. */
  path: string[];
}

export interface ResolvePathOptions {
  /** Trust Stamp's book, e.g. `acc://0truststamp.acme/book` (named to sort first). Signatures made under it are ours, not a human's. */
  ourBook: string;
  /** Trust Stamp's page, e.g. `acc://0truststamp.acme/book/1`. */
  ourPage: string;
  /** Registry + on-chain check. Only a page this returns true for can start a path. */
  isEnrolledWrapperPage(page: string): Promise<boolean>;
}

/** The book a page URL belongs to: `acc://p.acme/id/1` → `acc://p.acme/id`. */
export function bookOf(page: string): string {
  return page.replace(/\/+$/, '').replace(/\/\d+$/, '');
}

/** Accumulate URLs compare case-insensitively, and a trailing slash names the same account. */
export function sameUrl(a: string, b: string): boolean {
  return norm(a) === norm(b);
}
function norm(u: string): string {
  return u.trim().replace(/\/+$/, '').toLowerCase();
}
function isUnderBook(page: string | undefined, book: string): boolean {
  if (!page) return false;
  const p = norm(page);
  const b = norm(book);
  return p === b || p.startsWith(`${b}/`);
}
function pathKey(path: string[]): string {
  return path.map(norm).join('>');
}

/**
 * Paths Trust Stamp must sign on for this tx: one per enrolled wrapper a human's book passed through.
 *
 * `votes` are the authority signatures read at the wrapper books (`getAuthoritySignatures`).
 *
 * 1. A vote counts when it is current (not historical), an ACCEPT, and comes from a book that is not
 *    ours. A person who rejected, abstained or suggested through their wrapper gives us nothing to
 *    co-sign: our vote means "this person approved", and they did not.
 * 2. It must have been recorded on an enrolled wrapper page: `delegators[0]`. Its path is `delegators`.
 * 3. One entry per distinct path. A path on which our book's own current accept already sits is dropped:
 *    we voted there, and an authority's vote is final (`block/sig_authority.go:113`). By BOOK, because
 *    what counts on the wrapper page is our book's authority signature, whichever page produced it.
 *
 * An enrolment lookup that throws propagates: the caller signs nothing for this transaction this cycle,
 * rather than signing on whichever paths it happened to check first.
 */
export async function resolveWrapperPaths(votes: AuthorityVote[], opts: ResolvePathOptions): Promise<WrapperPath[]> {
  const live = votes.filter((v) => !v.historical && v.vote === 'accept' && v.delegators.length > 0);
  const ours = new Set(live.filter((v) => sameUrl(v.authority, opts.ourBook)).map((v) => pathKey(v.delegators)));

  const enrolled = new Map<string, boolean>();
  const isEnrolled = async (page: string): Promise<boolean> => {
    const k = norm(page);
    let v = enrolled.get(k);
    if (v === undefined) {
      v = await opts.isEnrolledWrapperPage(page);
      enrolled.set(k, v);
    }
    return v;
  };

  const out: WrapperPath[] = [];
  const seen = new Set<string>();
  for (const v of live) {
    if (sameUrl(v.authority, opts.ourBook) || isUnderBook(v.origin, opts.ourBook)) continue;
    const page = v.delegators[0]!;
    if (!(await isEnrolled(page))) continue;                              // not a wrapper we serve
    const key = pathKey(v.delegators);
    if (seen.has(key) || ours.has(key)) continue;
    seen.add(key);
    out.push({ wrapperPage: page, path: [...v.delegators] });
  }
  return out;
}

/**
 * The store key for one unit of signing work. Wrapper runbook, change 2.
 *
 * Keyed by transaction alone, a transaction that needs Trust Stamp on TWO paths (Alice and Bob both sit
 * on the page that approves it) was voted once, and the second path was skipped as "idempotent". The
 * second wrapper then never reached its threshold and the transaction expired.
 *
 * With no path, or an empty one (a direct vote on our own page), the key is the bare transaction hash,
 * so every existing store, receipt and admin route keeps working unchanged.
 */
export function workKey(txHash: string, path?: string[]): string {
  if (!path || path.length === 0) return txHash;
  return `${txHash}:${sha256Hex(pathKey(path)).slice(0, 16)}`;
}
