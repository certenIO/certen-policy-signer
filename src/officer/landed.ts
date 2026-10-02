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
 *   - a delegated signature whose OUTERMOST delegator is the page counts the delegate seat it came through
 *     (the next book inward), when that book is a delegate entry on the page.
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
import type { TxSignatures } from '../accumulate/client.js';
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

/** The signatures in `sigs` that count for `page`, one per seat (the first seen wins). */
export function countedSignatures(sigs: TxSignatures, page: string, st: PageState): HumanSignature[] {
  const keys = new Set(st.keyHashes.map((h) => h.toLowerCase()));
  const delegateSeats = new Set(st.entries.map((e) => e.delegate).filter((x): x is string => !!x).map(norm));
  const seen = new Set<string>();
  const out: HumanSignature[] = [];
  for (const s of sigs.signatures) {
    let seat: string | undefined;
    if (s.delegators.length === 0) {
      if (s.signer && norm(s.signer) === norm(page) && keys.has(s.publicKeyHash.toLowerCase())) seat = `key:${s.publicKeyHash.toLowerCase()}`;
    } else if (norm(s.delegators[0]!) === norm(page)) {
      const inward = s.delegators.length > 1 ? bookOf(s.delegators[1]!) : s.signer ? bookOf(s.signer) : undefined;
      if (inward && delegateSeats.has(inward)) seat = `delegate:${inward}`;
    }
    if (!seat || seen.has(seat)) continue;
    seen.add(seat);
    out.push({ seat, publicKeyHash: s.publicKeyHash.toLowerCase(), type: s.type, delegators: [...s.delegators], vote: s.vote ?? 'approve' });
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

  const counted = countedSignatures(sigs, page, st);
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
