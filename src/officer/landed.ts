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
import { finaliseHold } from '../store/pending-hold.js';

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

/* ------------------------------------------------------------------------------------------------------------------ */
/* AGT-F130: a KEYED seat's request held on the personal path ends when the people's authority has signed on chain.    */
/* ------------------------------------------------------------------------------------------------------------------ */

/**
 * One officer signature THIS signer's intake submitted to the network: who, how, and WHEN it was sent. Persisted per
 * prepare (intake state kind `submission`), so the time survives a restart between two officers' signatures.
 * `delegators` are in hop order (outermost last), as the intake prepared them.
 */
export interface IntakeSubmission {
  prepareId: string;
  txHash: string;
  keyHash: string;
  page: string;
  delegators: string[];
  vote: 'approve' | 'reject';
  /** ms since the epoch: the moment the intake sent the signature to the network. */
  submittedAt: number;
}

/** What officer intake reports when a signature it submitted on a TRANSACTION ref has landed. */
export interface LandedOfficerSignature {
  txHash: string;
  /** The page whose seat the signature satisfies: the outermost delegator, else the signing page. */
  authority: string;
  page: string;
  delegators: string[];
  keyHash: string;
  vote: 'approve' | 'reject';
  /** When this intake sent THIS signature to the network. */
  submittedAt: number;
  /** Every signature this intake has submitted on the transaction (this one included), from its persisted state. */
  submissions: IntakeSubmission[];
}

export interface PersonalPathDeps extends HumanTallyDeps {
  /** How long to wait for a policy poll to release the request's lock (default 60 s); past it the miss is logged as an error. */
  lockWaitMs?: number;
  lockPollMs?: number;
}

/** A keyed seat's request that has not been decided: the policy engine is still being asked (or was never answered). */
const UNDECIDED: ReadonlyArray<SigningRequest['status']> = ['discovered', 'awaiting_policy'];

const sameSet = (a: string[], b: string[]) =>
  JSON.stringify(a.map((x) => x.toLowerCase()).sort()) === JSON.stringify(b.map((x) => x.toLowerCase()).sort());

/** The intake submission that put chain signature `s` on the transaction, if this intake submitted it. */
const submissionOf = (s: ChainSignature, subs: IntakeSubmission[]): IntakeSubmission | undefined =>
  subs.find((x) => x.keyHash.toLowerCase() === s.publicKeyHash.toLowerCase() && x.vote === voteOf(s) && sameSet(x.delegators, s.delegators));

/** Does chain signature `s` reach `authority` (made on it directly, or delegated through it as the outermost delegator)? */
const reaches = (s: ChainSignature, authority: string) =>
  s.delegators.length ? norm(s.delegators[0]!) === norm(authority) : !!s.signer && norm(s.signer) === norm(authority);

/**
 * When did THIS intake send the signature that completed `authority`'s threshold for `vote`? Determined by replaying
 * the chain's signature set in this intake's submission order: the earliest submission at which the signatures sent up
 * to then reach the threshold (delegate books counted exactly as `countedSignatures` counts them).
 *
 * Every signature reaching the authority with that vote must be one this intake submitted; otherwise the order in which
 * they arrived is not known here and `undefined` is returned (the receipt then states no relay time rather than a
 * wrong one).
 */
async function completingSubmission(sigs: TxSignatures, authority: string, st: PageState, vote: CountedVote, needed: number, subs: IntakeSubmission[], readPage: ReadPage): Promise<IntakeSubmission | undefined> {
  const relevant = sigs.signatures.filter((s) => reaches(s, authority) && voteOf(s) === vote);
  const mine = relevant.map((s) => ({ s, sub: submissionOf(s, subs) }));
  if (mine.some((m) => !m.sub)) return undefined;
  const order = [...mine].sort((a, b) => a.sub!.submittedAt - b.sub!.submittedAt);
  for (let i = 0; i < order.length; i++) {
    const sentBy = new Set(order.slice(0, i + 1).map((m) => m.s));
    const subset: TxSignatures = { ...sigs, signatures: sigs.signatures.filter((s) => !relevant.includes(s) || sentBy.has(s)) };
    const counted = await countedSignatures(subset, authority, st, readPage);
    if (counted.filter((c) => c.vote === vote).length >= needed) return order[i]!.sub;
  }
  return undefined;
}

async function withLock<T>(d: PersonalPathDeps, key: string, fn: () => Promise<T>): Promise<T | 'locked'> {
  const wait = d.lockWaitMs ?? 60_000;
  const step = d.lockPollMs ?? 50;
  const until = Date.now() + wait;
  while (!d.store.tryLock(key)) {
    if (Date.now() >= until) return 'locked';
    await new Promise((res) => setTimeout(res, step));
  }
  try { return await fn(); } finally { d.store.unlock(key); }
}

/**
 * AGT-F130. A KEYED seat (its page holds the policy key) whose decision service answered `pending` because the payment
 * is approved by people signing with their OWN keys through officer intake (the personal path): the seat casts no
 * machine vote, and its request sat `awaiting_policy` for ever once the people's signatures executed the transaction,
 * with no receipt -- so nothing could say the signer relayed the people's act, or when.
 *
 * Called when a signature THIS intake submitted on a transaction ref lands. For each undecided keyed request on that
 * transaction whose page belongs to the same key book as the authority the people signed for (the book's authority is
 * satisfied by any one of its pages reaching its threshold), the chain is read -- the signature set and the authority's
 * page -- and counted exactly as `advanceAwaitingHuman` counts:
 *
 *   - threshold not met: the counted signatures are kept on the request (`humanSignatures`); it stays open, because
 *     partial signatures are not a decision;
 *   - accept threshold met: the request ends `signed`; reject threshold met: it ends `rejected`. The receipt states the
 *     PEOPLE's act, relayed by this signer: `vote` (the cast vote), `submittedAt` (when this intake sent the signature
 *     that completed the threshold -- never the moment the landing was noticed), `signedBy` (a decisive signature: the
 *     page its key sits on, its type, key hash and delegation path), `humanSignatures`, and
 *     `policyEvidence.personalSignature: { page, vote, ... }` so nobody reads it as a machine vote. Existing receipt
 *     fields are kept. No machine signature is ever cast.
 *   - a vote opposite to the one a prior receipt says was owed (the human-only marker, or the engine's own `decision`)
 *     is recorded as an override, exactly as `advanceAwaitingHuman` records one.
 *
 * The request's lock is taken (waiting for a policy poll of it to finish), so a poll in flight cannot write
 * `awaiting_policy` back over the ended request.
 */
export async function advancePersonalPath(d: PersonalPathDeps, r: LandedOfficerSignature): Promise<SigningRequest[]> {
  if (!d.getTxSignatures || !d.readPage) return [];
  const authorityBook = bookOf(r.authority);
  const candidates = (await d.store.listForTx(r.txHash)).filter((q) =>
    q.recordId === undefined && UNDECIDED.includes(q.status) && bookOf(q.signerUrl) === authorityBook);
  const out: SigningRequest[] = [];
  for (const cand of candidates) {
    const key = cand.workKey ?? cand.txHash;
    const res = await withLock(d, key, () => advanceOne(d, r, key));
    if (res === 'locked') {
      d.logger?.error({ tx: r.txHash, key, authority: r.authority }, 'personal path: the request stayed locked by a policy poll; the landed signature could not be recorded on it now');
      continue;
    }
    if (res) out.push(res);
  }
  return out;
}

async function advanceOne(d: PersonalPathDeps, r: LandedOfficerSignature, key: string): Promise<SigningRequest | undefined> {
  const req = await d.store.get(key);
  if (!req || !UNDECIDED.includes(req.status)) return req;
  const sigs = await d.getTxSignatures!(r.txHash, req.account || r.authority).catch(() => undefined);
  if (!sigs || sigs.unavailable) {
    d.logger?.warn({ tx: r.txHash, authority: r.authority }, 'personal path: the signature set could not be read; nothing recorded');
    return req;
  }
  let st: PageState;
  try { st = await d.readPage!(r.authority); } catch (e) {
    d.logger?.warn({ tx: r.txHash, authority: r.authority, err: (e as Error).message }, 'personal path: the authority page could not be read; nothing recorded');
    return req;
  }
  const pageCache = new Map<string, Promise<PageState>>();
  const readPage: ReadPage = (pg) => { const k = norm(pg); if (!pageCache.has(k)) pageCache.set(k, d.readPage!(pg)); return pageCache.get(k)!; };

  const unread: string[] = [];
  const counted = await countedSignatures(sigs, r.authority, st, readPage, unread);
  if (unread.length) d.logger?.warn({ tx: r.txHash, authority: r.authority, unread }, 'personal path: some delegate seats could not be counted from the chain; they do not count');
  const approvals = counted.filter((s) => s.vote === 'approve');
  const rejections = counted.filter((s) => s.vote === 'reject');
  const accept = st.threshold;
  const reject = st.rejectThreshold || st.threshold;
  const cast: CountedVote | undefined = approvals.length >= accept ? 'approve' : rejections.length >= reject ? 'reject' : undefined;

  if (!cast) {
    if (JSON.stringify(counted) === JSON.stringify(req.humanSignatures ?? [])) return req;
    d.logger?.info({ tx: r.txHash, authority: r.authority, approvals: approvals.length, rejections: rejections.length, accept, reject }, "personal path: signatures counted; the authority's threshold is not yet met");
    return d.store.update(key, { humanSignatures: counted });
  }

  const receipt = await d.store.getReceipt(key);
  const marker = (receipt?.policyEvidence?.awaitingHumanSignature as { vote?: unknown } | undefined)?.vote;
  const owed: CountedVote | undefined = marker === 'approve' || marker === 'reject'
    ? marker
    : receipt?.decision === 'approve' ? 'approve' : receipt?.decision === 'deny' ? 'reject' : undefined;
  const override = owed && owed !== cast ? { owed, cast } : undefined;
  const decisive = cast === 'approve' ? approvals : rejections;
  const first = decisive[0]!;
  // The page a decisive signature's key sits on (the signature's own signer), so `signedBy` can be compared with a page entry.
  const firstSig = sigs.signatures.find((s) => s.publicKeyHash.toLowerCase() === first.publicKeyHash && voteOf(s) === first.vote && sameSet(s.delegators, first.delegators));
  const completing = await completingSubmission(sigs, r.authority, st, cast, cast === 'approve' ? accept : reject, r.submissions, readPage);
  if (!completing) {
    d.logger?.warn({ tx: r.txHash, authority: r.authority, cast }, 'personal path: the threshold is met but not every signature that met it was submitted by this intake; the receipt records no relay time');
  }
  const t = (d.now ?? Date.now)();
  await d.store.saveReceipt({
    ...(receipt ?? { txHash: r.txHash, ...(req.workKey ? { workKey: req.workKey } : {}) }),
    ...(req.operationId && !receipt?.operationId ? { operationId: req.operationId } : {}),
    vote: cast,
    ...(completing ? { submittedAt: completing.submittedAt } : {}),
    signedBy: { page: firstSig?.signer ?? r.authority, signatureType: first.type, publicKeyHash: first.publicKeyHash, delegators: first.delegators },
    humanSignatures: counted,
    policyEvidence: {
      ...(receipt?.policyEvidence ?? {}),
      personalSignature: { page: r.authority, vote: cast, relayedBy: completing ? 'this-signer' : 'not-determined', ...(completing ? { completingKeyHash: completing.keyHash } : {}) },
    },
    ...(override ? { humanOverride: override } : {}),
  });
  if (override) {
    d.logger?.warn({ tx: r.txHash, authority: r.authority, owed: override.owed, cast: override.cast }, 'personal path: the people signed the OPPOSITE of the vote owed; recorded as an override');
  } else {
    d.logger?.info({ tx: r.txHash, authority: r.authority, cast, signatures: decisive.length, submittedAt: completing?.submittedAt }, "personal path: the people's authority met its threshold on chain; the seat's request ended with their act (no machine vote)");
  }
  return d.store.update(key, {
    status: cast === 'approve' ? 'signed' : 'rejected',
    humanSignatures: counted,
    ...finaliseHold(req, `personal:${cast}`, t),
    ...(override ? { humanOverride: override, lastError: `human_override: owed ${override.owed}, cast ${override.cast}` } : { lastError: undefined }),
  });
}

/**
 * The officer intake's `onLanded` hook, for the intake-only process AND the full signer (both build their intake with
 * `buildOfficerIntake`): a human-only seat's `awaiting_human` request (G-69) and a keyed seat's request held on the
 * personal path (AGT-F130) are each advanced from the chain.
 */
export function officerLandedHandler(d: PersonalPathDeps): (r: LandedOfficerSignature) => Promise<void> {
  return async (r) => {
    await advanceAwaitingHuman(d, r.txHash, r.authority);
    await advancePersonalPath(d, r);
  };
}
