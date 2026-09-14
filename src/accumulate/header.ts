/**
 * Read a pending transaction's HEADER out of the record Accumulate returned. Runbook Phase 2 task 2.5.
 *
 * Pure, and applied to every transaction whatever its body: a CERTEN intent, a plain WriteData
 * acceptance transaction (decision 0028), a token send. The header is the network's own record of who
 * the transaction acts on, which additional authorities it will wait for and when it dies — none of
 * which a payload decoder should be trusted to report.
 *
 * v3 JSON shape (Go `protocol.TransactionHeader`):
 *   { principal, initiator, memo, metadata, expire: { atTime: RFC3339 }, holdUntil: { minorBlock },
 *     authorities: ["acc://…/book", …] }
 */
import { TransactionHeaderInfo } from '../types.js';

export interface ExtractedHeader {
  header: TransactionHeaderInfo;
  /**
   * The header carries an expiry this function could not read. The caller must refuse to sign: a
   * deadline that cannot be read is a deadline nobody can show has not passed (decision 0031).
   */
  expiryUnreadable?: string;
}

/**
 * `fallbackPrincipal` is used only when the record has no readable `header.principal` — the client
 * already reported a principal and a request must always carry one.
 */
export function extractTxHeader(rawTransaction: unknown, fallbackPrincipal = ''): ExtractedHeader {
  const tx = rawTransaction && typeof rawTransaction === 'object' ? (rawTransaction as Record<string, unknown>) : {};
  const h = tx['header'] && typeof tx['header'] === 'object' ? (tx['header'] as Record<string, unknown>) : {};

  const principalRaw = h['principal'];
  const principal = typeof principalRaw === 'string' && principalRaw ? principalRaw : fallbackPrincipal;
  const header: TransactionHeaderInfo = { principal };

  // Authorities: exactly what was recorded. Only well-formed URL strings are kept; a malformed entry is
  // dropped, which can only make a required party look MISSING — the direction a required-party rule
  // (A2) turns into a deny, never into an approval.
  const auths = h['authorities'];
  if (Array.isArray(auths)) {
    const list = auths.filter((a): a is string => typeof a === 'string' && a.trim() !== '');
    if (list.length) header.authorities = list;
  }

  let expiryUnreadable: string | undefined;
  const expire = h['expire'];
  if (expire !== undefined && expire !== null) {
    const atTime = typeof expire === 'object' ? (expire as Record<string, unknown>)['atTime'] : undefined;
    if (atTime !== undefined && atTime !== null) {
      // Accumulate writes an RFC3339 string. Anything else — a number whose unit would have to be
      // guessed, an unparseable string — is refused rather than interpreted: guessing seconds versus
      // milliseconds on a deadline is inventing the deadline.
      const ms = typeof atTime === 'string' ? Date.parse(atTime) : NaN;
      if (Number.isFinite(ms)) header.expiresAt = new Date(ms).toISOString();
      else expiryUnreadable = `header.expire.atTime is not a readable timestamp: ${JSON.stringify(atTime).slice(0, 80)}`;
    } else if (typeof expire !== 'object') {
      expiryUnreadable = `header.expire is not an object: ${JSON.stringify(expire).slice(0, 80)}`;
    }
  }

  const memo = h['memo'];
  if (typeof memo === 'string' && memo !== '') header.memo = memo;

  return { header, ...(expiryUnreadable ? { expiryUnreadable } : {}) };
}

/**
 * Has the on-chain deadline passed at `nowMs`? Inclusive: at the deadline itself the transaction is
 * treated as dead, because a signature that took any time at all to land would arrive after it.
 */
export function headerDeadlinePassed(header: TransactionHeaderInfo, nowMs: number): boolean {
  if (!header.expiresAt) return false;
  return nowMs >= Date.parse(header.expiresAt);
}
