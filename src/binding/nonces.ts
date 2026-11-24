/**
 * The single-use nonce store (DE-02, DE-03): the set of decision nonces consumed or voided, folded from the verified journal.
 *
 * The check and the consumption are ONE step (`consumeWith`): inside the journal's exclusive section the caller's `decide`
 * sees the consumed set, and when it accepts a nonce the `decision.consumed` entry is appended, written and fsync-ed, BEFORE
 * the step returns, which is before the signer signs. Two decisions that present one nonce at once cannot both pass. If the
 * append fails the decision fails (back-pressure): nothing is signed and nothing is recorded as consumed that was not durable.
 * A crash between the append and the signature leaves the nonce spent: a fresh decision is needed.
 *
 * DAX-F191: the single-use guarantee is for a vote that was SUBMITTED. When the cast that followed a consumption signed nothing (or sent a
 * signature the chain, read, shows absent), `release` gives the nonce back in ONE journal entry, `recheck.result` with outcome
 * `decision_released`, which is also the failure record (the error, the transaction, what the chain said). A voided nonce is never released,
 * and only a nonce this journal consumed can be. The fold replays consumptions, voids and releases in journal order.
 */
import { voidNonces as coreVoidNonces } from '../core/decision-binding.js';
import { DecisionJournal, JournalError } from './journal.js';

export interface ConsumeDecision<T> {
  /** what `consumeWith` returns to its caller */
  result: T;
  /** when set, this nonce (of this request) is consumed before `consumeWith` returns */
  consume?: { requestHash: string; nonce: string; /** further members of the entry (the facts age): allowed by the log */ extra?: Record<string, unknown> };
}

/** DAX-F191: the `recheck.result` outcome of a released decision (the journal's free-form kind; no new log kind) */
export const RELEASED = 'decision_released';

export class NonceStore {
  private readonly spent = new Set<string>();
  /** DAX-F191: the nonces voided (never released), apart from the ones consumed */
  private readonly voided = new Set<string>();
  private order: string[] = [];

  constructor(private readonly journal: DecisionJournal, private readonly nowSeconds: () => number) {
    for (const e of journal.entries()) {
      if (e.kind === 'decision.consumed') this.add(String(e.payload['nonce']));
      else if (e.kind === 'recheck.result' && e.payload['outcome'] === RELEASED && typeof e.payload['nonce'] === 'string') this.drop(e.payload['nonce']);
      else if (e.kind === 'recheck.result' && Array.isArray(e.payload['voided'])) {
        for (const n of e.payload['voided'] as unknown[]) if (typeof n === 'string') { this.voided.add(n); this.add(n); }
        if (Array.isArray(e.payload['voidedConsumed'])) for (const n of e.payload['voidedConsumed'] as unknown[]) if (typeof n === 'string') this.voided.add(n);
      }
    }
  }

  private drop(n: string): boolean {
    if (!this.spent.has(n) || this.voided.has(n)) return false;
    this.spent.delete(n);
    this.order = this.order.filter((x) => x !== n);
    return true;
  }

  /**
   * DAX-F191: give back a consumed nonce whose vote was not cast, durable on return. `record` is the failure record carried in the same entry
   * (the transaction, the error, and what the chain said: `not_signed` when nothing left the signer, `absent` when a chain read showed none of
   * its keys on the transaction). Answers false, appending nothing, for a nonce that is not consumed here or was voided.
   */
  release(a: { nonce: string; requestHash: string; txHash: string; error: string; chain: 'not_signed' | 'absent'; seat: string }): Promise<boolean> {
    return this.journal.exclusive(async () => {
      if (!this.spent.has(a.nonce) || this.voided.has(a.nonce)) return false;
      this.journal.appendNow('recheck.result', this.nowSeconds(), { outcome: RELEASED, reason: 'vote_not_cast', requestHash: a.requestHash, nonce: a.nonce, txHash: a.txHash, seat: a.seat, chain: a.chain, error: a.error.slice(0, 1024) });
      this.drop(a.nonce);
      return true;
    });
  }

  private add(n: string): boolean {
    if (this.spent.has(n)) return false;
    this.spent.add(n);
    this.order.push(n);
    return true;
  }

  /** every nonce consumed or voided, in the order it was recorded */
  list(): string[] {
    return [...this.order];
  }

  has(nonce: string): boolean {
    return this.spent.has(nonce);
  }

  consumeWith<T>(decide: (consumed: string[]) => ConsumeDecision<T>): Promise<T> {
    return this.journal.exclusive(async () => {
      const d = decide(this.list());
      if (d.consume !== undefined) {
        const { requestHash, nonce, extra } = d.consume;
        if (this.spent.has(nonce)) throw new JournalError('decision_replayed', 'the nonce was consumed between the check and the append');
        this.journal.appendNow('decision.consumed', this.nowSeconds(), { ...(extra ?? {}), requestHash, nonce });
        this.add(nonce);
      }
      return d.result;
    });
  }

  /**
   * Marks nonces spent without a decision being accepted (the old nonce of a decision a recheck voided: reissue, deny,
   * expiry), so that the old decision cannot be used even by a seat that pins no policy. Idempotent; durable on return.
   */
  async voidNonces(nonces: string[], reason: string): Promise<{ voided: string[] }> {
    const checked = coreVoidNonces(
      { requireGrant: false, grantHeadHash: null, grantHeadSubject: null, expectedPolicyHash: null, authorizedApprovers: [], consumed: [], maxWindowSeconds: 1 },
      nonces,
    );
    if (!checked.ok) throw new JournalError(checked.reason, checked.detail);
    return this.journal.exclusive(async () => {
      const fresh = [...new Set(nonces)].filter((n) => !this.spent.has(n));
      // DAX-F191: a nonce consumed here and voided now must never be released afterwards: it is named too (`voidedConsumed`), durably
      const consumedNow = [...new Set(nonces)].filter((n) => this.spent.has(n) && !this.voided.has(n));
      if (fresh.length > 0 || consumedNow.length > 0) {
        this.journal.appendNow('recheck.result', this.nowSeconds(), { outcome: 'nonces_voided', reason, voided: fresh, ...(consumedNow.length > 0 ? { voidedConsumed: consumedNow } : {}) });
        for (const n of fresh) { this.voided.add(n); this.add(n); }
        for (const n of consumedNow) this.voided.add(n);
      }
      return { voided: fresh };
    });
  }
}
