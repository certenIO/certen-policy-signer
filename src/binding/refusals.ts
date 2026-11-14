/**
 * The refusal receipt (DECISION.md section 8, DE-97, DE-98, DE-103): a decision the binding check refuses is recorded as a `binding.refused`
 * entry of the verified decision journal, `{ requestHash, seat, reason }` and, where they could be read, the `nonce` of the decision that
 * was refused and the `txHash`, each a 32-byte hash or the empty string.
 *
 * Attribution is the core's rule (`isAttributable`): a receipt attributes a refusal only when it names BOTH the request and the nonce. This
 * module builds the receipt from what the check could read, and the core's own `checkRefusalReceipt` validates it before it is journalled (a
 * receipt this signer builds and the core refuses is a defect, never written). A refusal changes nothing else: no signature, no vote, no
 * cancel, no consumed nonce, and no reservation is released by it (the signer holds none; the decision service's ledger never releases on a
 * refusal, DE-98).
 */
import { checkRefusalReceipt, type RefusalReceipt } from '../core/refusal-receipt.js';
import type { LogEntry } from '../core/log.js';
import { isHash } from '../core/decision-identity.js';
import { DecisionJournal } from './journal.js';

export class RefusalReceiptError extends Error {
  constructor(readonly reason: string, readonly member?: string) {
    super(member === undefined ? reason : `${reason} ${member}`);
  }
}

/** the receipt of a refusal, from the facts the check could read: an unreadable fact is the empty string */
export function refusalReceiptOf(a: { requestHash?: string | undefined; seat: string; reason: string; nonce?: string | undefined; txHash?: string | undefined }): RefusalReceipt {
  const requestHash = a.requestHash !== undefined && isHash(a.requestHash) ? a.requestHash : '';
  // a nonce without the request it was presented for names nothing, so it is not carried (the core would refuse the receipt)
  const nonce = requestHash !== '' && a.nonce !== undefined && isHash(a.nonce) ? a.nonce : '';
  const txHash = a.txHash !== undefined && isHash(a.txHash) ? a.txHash : '';
  return { requestHash, seat: a.seat, reason: a.reason.slice(0, 256), nonce, txHash };
}

export class RefusalReceipts {
  constructor(private readonly journal: DecisionJournal, private readonly nowSeconds: () => number) {}

  /** the entry is durable (written, fsync-ed, chained, pinned) before this returns; a write that cannot be made fails the caller (DE-47) */
  async record(receipt: RefusalReceipt): Promise<LogEntry> {
    const checked = checkRefusalReceipt({ receipt });
    if (!checked.ok) throw new RefusalReceiptError(checked.reason, 'member' in checked ? checked.member : undefined);
    return this.journal.append('binding.refused', this.nowSeconds(), { ...receipt });
  }
}
