/**
 * G-64: a seat must persist WHY it is holding.
 *
 * While a request is undecided the record says `awaiting_policy`, which is THAT the seat is holding. The
 * decision service also says WHY ("provider risk-score gave no answer (HTTP 503)") and under which
 * versions (A6: rule set, provider config, signer config). That answer used to be logged and discarded,
 * so neither an operator nor an evidence pack could show the reason. These pure helpers turn each
 * `pending` answer into a record kept on the request (src/store/store.ts persists it with the row, so it
 * survives a restart of a FileStore-backed signer):
 *
 *   pending       the CURRENT hold: latest reason and versions, when the hold began, when it was last
 *                 re-evaluated, how many times, and a bounded history of the distinct reasons seen.
 *   pendingFinal  the hold as it stood when the request was decided (or went away), with when and how it
 *                 ended. `pending` is cleared at that moment, so a decided request never reads as holding.
 *
 * WHAT IS KEPT, AND WHAT IS NOT. Only the reason text (policy text, by contract) and the three version
 * stamps. Never the decision's free-form `evidence`, which may carry provider facts or other data: the
 * version stamps are picked out of it by name and everything else is left behind. The reason is cut to a
 * fixed length, stripped of control characters, and anything shaped like a credential assignment
 * (`api_key=…`, `Bearer …`) is redacted, so a decision service that echoes a secret by mistake does not
 * get it written into the signer's state file.
 */
import type { Decision, FinalisedHold, HoldReason, HoldVersions, PendingHold, SigningRequest } from '../types.js';

/** How many distinct reasons a hold remembers. Oldest are dropped first. */
export const HOLD_HISTORY_MAX = 20;
/** Longest reason kept, in characters. */
export const HOLD_REASON_MAX = 1024;
const VERSION_MAX = 200;
const NO_REASON = '(the decision service gave no reason)';

const VERSION_KEYS = ['ruleSetVersion', 'providerConfigVersion', 'signerConfigVersion'] as const;

/**
 * Redact anything shaped like a credential. The reason is policy text; this is defence in depth against a
 * decision service that echoes a header or a URL with a key in it.
 */
export function sanitizeReason(raw: unknown): string {
  if (typeof raw !== 'string' || !raw.trim()) return NO_REASON;
  let s = raw.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  s = s
    .replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [redacted]')
    .replace(/\b([A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|passwd|authorization|credential|private[_-]?key|seed)[A-Za-z0-9_-]*)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&)]+)/gi, '$1$2[redacted]')
    .replace(/([?&][A-Za-z0-9_-]*(?:key|token|secret|sig)[A-Za-z0-9_-]*=)[^&\s]+/gi, '$1[redacted]');
  return s.length > HOLD_REASON_MAX ? `${s.slice(0, HOLD_REASON_MAX - 1)}…` : s;
}

/** The version stamps the decision returned (A6), by name only. Anything not a short printable string is dropped. */
export function holdVersions(evidence: Decision['evidence']): HoldVersions {
  const out: HoldVersions = {};
  if (!evidence || typeof evidence !== 'object') return out;
  for (const k of VERSION_KEYS) {
    const v = (evidence as Record<string, unknown>)[k];
    if (typeof v === 'string' && v.length > 0 && v.length <= VERSION_MAX && /^[\x20-\x7e]+$/.test(v)) out[k] = v;
  }
  return out;
}

const sameVersions = (a: HoldVersions, b: HoldVersions) => VERSION_KEYS.every((k) => (a[k] ?? null) === (b[k] ?? null));

/**
 * The request's hold after one more `pending` answer. Starts a hold when there is none (seeding its history
 * from the last finalised one, so a request that held, errored and held again keeps every reason), else
 * updates the latest reason and evaluation time and folds the reason into the history.
 */
export function recordHold(cur: Pick<SigningRequest, 'pending' | 'pendingFinal'> | undefined, decision: Pick<Decision, 'reason' | 'evidence'>, nowMs: number): PendingHold {
  const at = new Date(nowMs).toISOString();
  const reason = sanitizeReason(decision.reason);
  const versions = holdVersions(decision.evidence);
  const prev = cur?.pending;
  const history: HoldReason[] = (prev?.history ?? cur?.pendingFinal?.history ?? []).map((h) => ({ ...h, versions: { ...h.versions } }));

  const i = history.findIndex((h) => h.reason === reason && sameVersions(h.versions, versions));
  if (i >= 0) {
    const [h] = history.splice(i, 1);
    history.push({ ...h, lastSeenAt: at, count: h.count + 1 });
  } else {
    history.push({ reason, versions, firstSeenAt: at, lastSeenAt: at, count: 1 });
  }
  while (history.length > HOLD_HISTORY_MAX) history.shift();

  return {
    reason,
    versions,
    since: prev?.since ?? at,
    lastEvaluatedAt: at,
    evaluations: (prev?.evaluations ?? 0) + 1,
    history,
  };
}

/**
 * The patch that ends the current hold: `pending` cleared, the hold kept as `pendingFinal` with when and how
 * it ended. Empty when nothing was holding, so a request that was never held gains no fields.
 */
export function finaliseHold(cur: Pick<SigningRequest, 'pending'> | undefined, outcome: string, nowMs: number): Partial<SigningRequest> {
  if (!cur?.pending) return {};
  const ended: FinalisedHold = { ...cur.pending, endedAt: new Date(nowMs).toISOString(), outcome };
  return { pending: undefined, pendingFinal: ended };
}
