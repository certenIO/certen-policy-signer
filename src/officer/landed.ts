/**
 * G-69: a person's signature landing ends the request a human-only seat is holding.
 *
 * A human-only seat (`wallet.human_scopes`) records the engine's decision as `awaiting_human` and casts
 * nothing: its page holds no key. The person signs through officer intake. When that signature is on chain,
 * the request is over exactly as a keyed seat's is once its vote is cast -- `signed` for an approve,
 * `rejected` for a reject -- and the receipt says which key, on which page, through which delegators, made
 * it. Only a request that is `awaiting_human` FOR THE PAGE THE SIGNATURE SATISFIED is ended; anything else
 * (a keyed seat's request, a different page's, one already finished) is left exactly as it was.
 */
import { humanRecordId, type Store } from '../store/store.js';
import type { Logger } from '../logger.js';

const norm = (u: string) => u.toLowerCase().replace(/\/+$/, '');

export async function recordHumanSignature(
  store: Store,
  r: { txHash: string; authority: string; page: string; delegators: string[]; keyHash: string; vote: 'approve' | 'reject' },
  logger?: Logger,
): Promise<boolean> {
  const key = humanRecordId(r.txHash, r.authority);
  const req = await store.get(key);
  if (!req || req.status !== 'awaiting_human' || norm(req.signerUrl) !== norm(r.authority)) return false;
  const receipt = await store.getReceipt(key);
  await store.saveReceipt({
    ...(receipt ?? { txHash: r.txHash, recordId: key }),
    vote: r.vote,
    submittedAt: Date.now(),
    // Facts of the signature, as for a keyed vote (F4): the page whose key it was, its algorithm (officer
    // intake verifies ecdsaSha256 personal keys only), the key hash, and the seats it satisfied.
    signedBy: { page: r.page, signatureType: 'ecdsaSha256', publicKeyHash: r.keyHash, delegators: [...r.delegators] },
  });
  await store.update(key, { status: r.vote === 'approve' ? 'signed' : 'rejected', lastError: undefined });
  logger?.info({ tx: r.txHash, page: req.signerUrl, keyHash: r.keyHash, vote: r.vote }, 'human-only seat: the person\'s signature landed; request ended');
  return true;
}
