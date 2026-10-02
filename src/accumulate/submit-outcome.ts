/**
 * What happened to a submitted signature, decided by the CHAIN -- never by the submit call's error.
 *
 * A submit that times out (or loses its connection, or gets a 5xx from a proxy) says nothing about whether
 * the network accepted the envelope: in the SP-10 run a submit timed out after 15 s while the officer's
 * signature landed and the payment was delivered, and the record said "refused". So every path that
 * submits a signature -- the machine vote, officer intake, governance -- asks the transaction's signature
 * set whether THIS key's signature (through these delegators) is there:
 *
 *   landed   it is: the submit succeeded, whatever the call said;
 *   absent   the chain answered, within the window, and it is not there;
 *   unknown  the chain could not be read at all -- the outcome is not known, and must never be reported
 *            as a refusal.
 *
 * The comparison is the one officer intake's landing poll has always used: the key hash, and the set of
 * delegators (order-insensitive, case-insensitive).
 */
import type { TxSignatures } from './client.js';

export type SubmitOutcome = 'landed' | 'absent' | 'unknown';

export interface OwnSignatureQuery {
  getTxSignatures?: (txHash: string, principal: string) => Promise<TxSignatures>;
  txHash: string;
  principal: string;
  keyHash: string;
  delegators: string[];
  /** How long to keep looking. */
  timeoutMs: number;
  pollMs?: number;
  now?: () => number;
}

/** Is this signature in the transaction's signature set? Polls until found or `timeoutMs` passes. */
export async function awaitOwnSignature(q: OwnSignatureQuery): Promise<SubmitOutcome> {
  if (!q.getTxSignatures) return 'unknown';
  const now = q.now ?? Date.now;
  const pollMs = q.pollMs ?? 2_000;
  const want = JSON.stringify(q.delegators.map((x) => x.toLowerCase()).sort());
  const key = q.keyHash.toLowerCase();
  const deadline = now() + q.timeoutMs;
  // Bounded by attempts as well as by the clock, so a clock that does not advance (a test clock, a stalled
  // timer source) cannot turn the wait into an endless loop.
  const maxAttempts = Math.max(1, Math.ceil(q.timeoutMs / pollMs) + 1);
  let answered = false;
  for (let attempt = 1; ; attempt++) {
    const sigs = await q.getTxSignatures(q.txHash, q.principal).catch(() => undefined);
    if (sigs && !sigs.unavailable) {
      answered = true;
      const hit = sigs.signatures.some((s) => s.publicKeyHash.toLowerCase() === key
        && JSON.stringify(s.delegators.map((x) => x.toLowerCase()).sort()) === want);
      if (hit) return 'landed';
    }
    if (now() + pollMs > deadline || attempt >= maxAttempts) return answered ? 'absent' : 'unknown';
    await new Promise((r) => setTimeout(r, pollMs));
  }
}
