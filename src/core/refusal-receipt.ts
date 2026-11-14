/**
 * The refusal receipt and what a signer refusal does to the ledger (DECISION.md section 8, finding DAX6C-F2, OQ-DAX6C-3;
 * DE-97, DE-98, DE-103). The signer's refusal is the `binding.refused` entry of its decision log: `{ requestHash, seat, reason }`
 * and, where they could be read, `nonce` (the nonce of the decision it refused) and `txHash`, each a 32-byte hash or the empty
 * string. A receipt is ATTRIBUTABLE only when it names the request it refused and the nonce of the decision it refused; one
 * that names neither, or only the request, attributes nothing and is never shown as the answer to any request.
 *
 * A refusal NEVER releases a reservation, attributable or not: the hold runs to its end, because another authority of the
 * account may still complete the transaction without this seat's signature, and a hold that returned capacity on one seat's
 * refusal would under-count an action that can still execute. The only releases are the failed or expired Accumulate
 * transaction, the tick at the hold end and the explicit release events of the ledger. So `refusalReceiptEffect` answers
 * `release: false` in every case and says why; it exists so that a caller has ONE function that names the answer and so that
 * a test can prove no path of the receipt reaches a release.
 *
 *   checkRefusalReceipt({ receipt, reservation? }) -> { ok: true, attributable } with no reservation, and with one
 *   `{ ok: true, release: false, reason, attributable? }`: refusal_never_releases (the receipt names this very reservation:
 *   same request, same decision nonce), receipt_other_request, receipt_unattributable, receipt_other_decision.
 *   A receipt of the wrong shape is receipt_malformed (with the member), anything else of the wrong shape
 *   receipt_input_malformed.
 */
import { isPlainObject } from './bytes.js';
import { isHash, isSeatId } from './decision-identity.js';

export interface RefusalReceipt { requestHash: string; seat: string; reason: string; nonce?: string; txHash?: string }
export type ReceiptCheck =
  | { ok: true; attributable: boolean }
  | { ok: true; release: false; attributable?: boolean; reason: 'refusal_never_releases' | 'receipt_other_request' | 'receipt_other_decision' | 'receipt_unattributable' }
  | { ok: false; reason: 'receipt_malformed'; member?: 'requestHash' | 'seat' | 'reason' | 'nonce' | 'txHash' }
  | { ok: false; reason: 'receipt_input_malformed' };

const hashOrEmpty = (v: unknown): v is string => v === '' || isHash(v);
const MAX_REASON = 256;

/** the receipt as a closed object, or the member that is wrong */
function readReceipt(v: unknown): RefusalReceipt | { bad: 'requestHash' | 'seat' | 'reason' | 'nonce' | 'txHash' | undefined } {
  if (!isPlainObject(v)) return { bad: undefined };
  const keys = Object.keys(v);
  for (const k of keys) if (!['requestHash', 'seat', 'reason', 'nonce', 'txHash'].includes(k)) return { bad: undefined };
  for (const k of ['requestHash', 'seat', 'reason']) if (!keys.includes(k)) return { bad: undefined };
  if (!hashOrEmpty(v['requestHash'])) return { bad: 'requestHash' };
  if (!isSeatId(v['seat'])) return { bad: 'seat' };
  if (typeof v['reason'] !== 'string' || v['reason'] === '' || v['reason'].length > MAX_REASON) return { bad: 'reason' };
  if ('nonce' in v && !hashOrEmpty(v['nonce'])) return { bad: 'nonce' };
  // a nonce without the request it was presented for names nothing: malformed
  if (v['requestHash'] === '' && typeof v['nonce'] === 'string' && v['nonce'] !== '') return { bad: 'nonce' };
  if ('txHash' in v && !hashOrEmpty(v['txHash'])) return { bad: 'txHash' };
  return v as unknown as RefusalReceipt;
}

/** attributable only when the receipt names the request and the nonce of the decision it refused (DE-97) */
export const isAttributable = (r: RefusalReceipt): boolean => r.requestHash !== '' && typeof r.nonce === 'string' && r.nonce !== '';

export function checkRefusalReceipt(input: unknown): ReceiptCheck {
  if (!isPlainObject(input)) return { ok: false, reason: 'receipt_input_malformed' };
  for (const k of Object.keys(input)) if (k !== 'receipt' && k !== 'reservation') return { ok: false, reason: 'receipt_input_malformed' };
  if (!('receipt' in input)) return { ok: false, reason: 'receipt_input_malformed' };
  const r = readReceipt(input['receipt']);
  if ('bad' in r) return r.bad === undefined ? { ok: false, reason: 'receipt_malformed' } : { ok: false, reason: 'receipt_malformed', member: r.bad };
  const attributable = isAttributable(r);
  if (!('reservation' in input)) return { ok: true, attributable };

  const res = input['reservation'];
  if (!isPlainObject(res)) return { ok: false, reason: 'receipt_input_malformed' };
  const keys = Object.keys(res);
  if (keys.length !== 2 || !keys.includes('requestHash') || !keys.includes('decisionNonce')) return { ok: false, reason: 'receipt_input_malformed' };
  if (!isHash(res['requestHash']) || (res['decisionNonce'] !== null && !isHash(res['decisionNonce']))) return { ok: false, reason: 'receipt_input_malformed' };

  // DE-98: whatever the answer, the refusal releases nothing; the reason says what the receipt is about
  if (r.requestHash !== res['requestHash']) return { ok: true, release: false, reason: 'receipt_other_request' };
  if (!attributable) return { ok: true, release: false, attributable: false, reason: 'receipt_unattributable' };
  if (res['decisionNonce'] === null || r.nonce !== res['decisionNonce']) return { ok: true, release: false, reason: 'receipt_other_decision' };
  return { ok: true, release: false, attributable: true, reason: 'refusal_never_releases' };
}
