/**
 * G-69: a human-only seat's request ends when ITS PAGE has signed -- as the chain counts it.
 *
 * A human-only seat (`wallet.human_scopes`) records the engine's decision as `awaiting_human` and casts
 * nothing: its page holds no key. People sign through officer intake. The request is NOT over when one
 * person's signature lands (review #2): a page with an accept threshold of 2 needs two. So this reads the
 * transaction's signature set from the chain and the page from the chain, and counts DISTINCT seats of that
 * page by vote:
 *
 *   - a direct signature whose signer is the page and whose key hash is an entry on it counts that key's seat;
 *   - a delegate seat (a book that is a delegate entry on the page) counts ONLY when that book has itself
 *     voted as Accumulate counts it: one of its pages reached its own threshold for that vote on the
 *     signatures that came through the page to it (security review 2026-10-02: one signature on a 2-of-3
 *     delegate page used to count the whole delegate seat). The delegate pages are read from the chain
 *     and counted the same way, recursively (a delegate of a delegate), to a depth of MAX_DELEGATION_DEPTH.
 *     A delegate page that cannot be read, a path deeper than that, or a delegate book that reached both
 *     thresholds at once does not count (fail closed: the request stays `awaiting_human`).
 *
 * Approvals reaching the page's accept threshold end the request `signed`; rejections reaching its reject
 * threshold (0 means the accept threshold, as the executor reads it) end it `rejected`. Until then the
 * request stays `awaiting_human` with every counted signature kept on it (`humanSignatures`), so the
 * partial signers are on the record.
 *
 * It is driven from two places, so a late landing is never lost (review #3): officer intake calls it when a
 * signature it submitted lands, and the orchestrator calls it on every poll of an `awaiting_human` request.
 * Either way the chain is the only input; when the chain or the page cannot be read nothing changes.
 *
 * A VOTE THAT CONTRADICTS THE ONE OWED (review #6). The receipt says which vote the policy decision needed
 * (`policyEvidence.awaitingHumanSignature.vote`). If the people's signatures end the request the other way,
 * that is what happened on chain and the status says so (`signed` for approvals, `rejected` for
 * rejections) -- but it is NOT recorded as fulfilling the decision: the request and the receipt carry
 * `humanOverride: { owed, cast }`, `lastError` names it, and it is logged at warn level.
 */
import { humanRecordId, type Store } from '../store/store.js';
import type { Logger } from '../logger.js';
import type { PageState } from '../ops/rotate.js';
import type { ChainSignature, TxSignatures } from '../accumulate/client.js';
import type { HumanSignature, SigningRequest } from '../types.js';

const norm = (u: string) => u.toLowerCase().replace(/\/+$/, '');
const bookOf = (page: string) => norm(page).replace(/\/\d+$/, '');

export interface HumanTallyDeps {
  store: Store;
  /** The chain's signature set for a transaction. Absent => nothing can be counted, nothing changes. */
  getTxSignatures?: (txHash: string, principal: string) => Promise<TxSignatures>;
  /** The page as the chain has it (entries, thresholds). Absent or failing => nothing changes. */
  readPage?: (page: string) => Promise<PageState>;
  logger?: Logger;
  now?: () => number;
}

/** How deep a delegation chain is followed below the human page. Deeper paths never count (fail closed). */
export const MAX_DELEGATION_DEPTH = 5;

type CountedVote = 'approve' | 'reject';
type ReadPage = (page: string) => Promise<PageState>;

/** A chain signature with the part of its delegation path still to walk (`rest[0]` is the page it is at). */
interface Walk { s: ChainSignature; rest: string[] }

/** The page a walk is at: its next delegator, or the page the signature was made on once the path is used up. */
const pageAt = (w: Walk): string | undefined => (w.rest.length ? w.rest[0] : w.s.signer);
const voteOf = (s: ChainSignature): CountedVote | 'abstain' => s.vote ?? 'approve';

/**
 * The seats of page `page` that cast `vote` on the signatures that reached it (`walks`, each positioned at `page`):
 * a key entry signed directly, or a delegate book that has itself reached its threshold for `vote` (recursively).
 * Returns the seat ids with the signature that represents each (the first seen).
 */
async function seatsVoting(page: string, st: PageState, walks: Walk[], vote: CountedVote, readPage: ReadPage | undefined, depth: number, seenPages: string[], unread: string[]): Promise<Map<string, ChainSignature>> {
  const keys = new Set(st.keyHashes.map((h) => h.toLowerCase()));
  const delegateBooks = new Set(st.entries.map((e) => e.delegate).filter((x): x is string => !!x).map(norm));
  const out = new Map<string, ChainSignature>();
  const below = new Map<string, Walk[]>();
  for (const w of walks) {
    if (w.rest.length === 0) {
      // Signed on this page itself: a key seat.
      const kh = w.s.publicKeyHash.toLowerCase();
      if (voteOf(w.s) === vote && w.s.signer && norm(w.s.signer) === norm(page) && keys.has(kh) && !out.has(`key:${kh}`)) out.set(`key:${kh}`, w.s);
      continue;
    }
    // Delegated through this page: the next page inward (or the signing page) names the delegate book.
    const next: Walk = { s: w.s, rest: w.rest.slice(1) };
    const inward = pageAt(next);
    if (!inward) continue;
    const book = bookOf(inward);
    if (!delegateBooks.has(book)) continue;
    const list = below.get(book) ?? [];
    list.push(next);
    below.set(book, list);
  }
  for (const [book, ws] of below) {
    if (await bookVotes(book, ws, vote, readPage, depth + 1, seenPages, unread)) out.set(`delegate:${book}`, ws.find((w) => voteOf(w.s) === vote)!.s);
  }
  return out;
}

/** Has delegate book `book` voted `vote` as Accumulate counts it (one of its pages reached that threshold)? */
async function bookVotes(book: string, walks: Walk[], vote: CountedVote, readPage: ReadPage | undefined, depth: number, seenPages: string[], unread: string[]): Promise<boolean> {
  if (depth > MAX_DELEGATION_DEPTH) { unread.push(`${book}: delegation deeper than ${MAX_DELEGATION_DEPTH}`); return false; }
  if (!readPage) { unread.push(`${book}: no page reader`); return false; }
  const pages = [...new Set(walks.map((w) => pageAt(w)).filter((x): x is string => !!x).map(norm))].filter((pg) => bookOf(pg) === book);
  for (const pg of pages) {
    if (seenPages.includes(pg)) { unread.push(`${pg}: delegation cycle`); continue; }
    let st: PageState;
    try { st = await readPage(pg); } catch (e) { unread.push(`${pg}: ${(e as Error).message}`); continue; }
    const here = walks.filter((w) => norm(pageAt(w) ?? '') === pg);
    const seats = await seatsVoting(pg, st, here, vote, readPage, depth, [...seenPages, pg], unread);
    const needed = vote === 'approve' ? st.threshold : (st.rejectThreshold || st.threshold);
    if (seats.size >= needed) return true;
  }
  return false;
}

/**
 * The signatures in `sigs` that count for `page`, one per seat (the first seen wins). A delegate seat counts only
 * when its book has reached its own threshold (see the header); `unread` collects what could not be counted.
 */
export async function countedSignatures(sigs: TxSignatures, page: string, st: PageState, readPage?: ReadPage, unread: string[] = []): Promise<HumanSignature[]> {
  // Signatures that reached the page: made on it directly, or delegated through it (it is the OUTERMOST delegator).
  const walks: Walk[] = [];
  for (const s of sigs.signatures) {
    if (s.delegators.length === 0) walks.push({ s, rest: [] });
    else if (norm(s.delegators[0]!) === norm(page)) walks.push({ s, rest: [...s.delegators] }); // rest[0] is the page itself
  }
  const byVote = new Map<CountedVote, Map<string, ChainSignature>>();
  for (const vote of ['approve', 'reject'] as const) {
    byVote.set(vote, await seatsVoting(page, st, walks, vote, readPage, 0, [norm(page)], unread));
  }
  const approve = byVote.get('approve')!;
  const reject = byVote.get('reject')!;
  const out: HumanSignature[] = [];
  const done = new Set<string>();
  // Page order of first appearance, as before: one record per seat.
  for (const s of sigs.signatures) {
    for (const [vote, seats] of [['approve', approve], ['reject', reject]] as const) {
      for (const [seat, rep] of seats) {
        if (rep !== s || done.has(seat)) continue;
        // A delegate book that reached BOTH thresholds is not a vote either way: neither is counted.
        if (seat.startsWith('delegate:') && approve.has(seat) && reject.has(seat)) { unread.push(`${seat}: reached both thresholds`); done.add(seat); continue; }
        done.add(seat);
        out.push({ seat, publicKeyHash: rep.publicKeyHash.toLowerCase(), type: rep.type, delegators: [...rep.delegators], vote });
      }
    }
  }
  return out;
}

/**
 * Read the chain and advance the `awaiting_human` request for (`txHash`, `page`): record the signatures that
 * count, and end it when a threshold is met. Returns the (possibly unchanged) request, or undefined.
 */
export async function advanceAwaitingHuman(d: HumanTallyDeps, txHash: string, page: string): Promise<SigningRequest | undefined> {
  const key = humanRecordId(txHash, page);
  const req = await d.store.get(key);
  if (!req || req.status !== 'awaiting_human') return req;
  if (!d.getTxSignatures || !d.readPage) return req;
  const sigs = await d.getTxSignatures(txHash, req.account || page).catch(() => undefined);
  if (!sigs || sigs.unavailable) return req;
  let st: PageState;
  try { st = await d.readPage(page); } catch { return req; }

  const unread: string[] = [];
  const counted = await countedSignatures(sigs, page, st, d.readPage, unread);
  if (unread.length) d.logger?.warn({ tx: txHash, page, unread }, 'human-only seat: some delegate seats could not be counted from the chain; they do not count');
  const approvals = counted.filter((s) => s.vote === 'approve');
  const rejections = counted.filter((s) => s.vote === 'reject');
  const accept = st.threshold;
  const reject = st.rejectThreshold || st.threshold;
  const cast: 'approve' | 'reject' | undefined = approvals.length >= accept ? 'approve' : rejections.length >= reject ? 'reject' : undefined;

  if (!cast) {
    if (JSON.stringify(counted) === JSON.stringify(req.humanSignatures ?? [])) return req;
    d.logger?.info({ tx: txHash, page, approvals: approvals.length, rejections: rejections.length, accept, reject }, 'human-only seat: signatures counted; threshold not yet met');
    return d.store.update(key, { humanSignatures: counted });
  }

  const receipt = await d.store.getReceipt(key);
  const owed = (receipt?.policyEvidence?.awaitingHumanSignature as { vote?: unknown } | undefined)?.vote;
  const override: { owed: 'approve' | 'reject'; cast: 'approve' | 'reject' } | undefined =
    (owed === 'approve' || owed === 'reject') && owed !== cast ? { owed, cast } : undefined;
  const decisive = cast === 'approve' ? approvals : rejections;
  const first = decisive[0]!;
  await d.store.saveReceipt({
    ...(receipt ?? { txHash, recordId: key }),
    vote: cast,
    submittedAt: (d.now ?? Date.now)(),
    signedBy: { page, signatureType: first.type, publicKeyHash: first.publicKeyHash, delegators: first.delegators },
    humanSignatures: counted,
    ...(override ? { humanOverride: override } : {}),
  });
  if (override) {
    d.logger?.warn({ tx: txHash, page, owed: override.owed, cast: override.cast }, 'human-only seat: the people signed the OPPOSITE of the vote the policy decision owed; recorded as an override');
  } else {
    d.logger?.info({ tx: txHash, page, cast, signatures: decisive.length }, 'human-only seat: the page\'s threshold is met on chain; request ended');
  }
  return d.store.update(key, {
    status: cast === 'approve' ? 'signed' : 'rejected',
    humanSignatures: counted,
    ...(override ? { humanOverride: override, lastError: `human_override: owed ${override.owed}, cast ${override.cast}` } : { lastError: undefined }),
  });
}
