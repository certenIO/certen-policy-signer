/**
 * Parity policy engine — a REAL (non-stub) policy engine for examples/testing.
 *
 * Decision rule: EVEN transfer amount -> approve; ODD -> deny.
 *   - On approve the wallet signs an Accept vote and submits it.
 *   - On deny, with `behavior.submit_reject_vote: true` the wallet signs a Reject vote;
 *     otherwise it simply withholds its signature and the tx expires.
 * Fail-closed: if no amount can be parsed from the request, the engine denies.
 *
 * Usage:
 *   node scripts/parity-policy-engine.mjs                 # :9099 /decision (matches config.local.yaml)
 *   PORT=9099 node scripts/parity-policy-engine.mjs
 *   POLICY_HMAC_SECRET=s3cret node scripts/...            # optional: HMAC-sign responses (wallet auth: hmac)
 *
 * Contract (see src/types.ts): receives a PolicyRequest JSON, returns a Decision JSON
 *   { decision: 'approve'|'deny', reason, evidence }.
 * The pure helpers are exported so `test/parity-policy.test.ts` can exercise them without a socket.
 */
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const PORT = Number(process.env.PORT ?? 9099);
const HMAC = process.env.POLICY_HMAC_SECRET || '';
const RULE = 'even=approve/odd=deny';

/**
 * Decide a PolicyRequest by the parity of its transfer amount(s).
 * Multi-leg intents carry every leg amount in `req.values` and are gated ALL-OR-NOTHING:
 * approve only if EVERY leg is even; a single odd (or unparseable) leg denies the whole intent.
 * Single-amount requests fall back to `req.value` / the actionSummary.
 * @param {object} req - a PolicyRequest (see src/types.ts)
 * @returns {{decision:'approve'|'deny', reason:string, evidence:object}}
 */
export function decideByParity(req) {
  const legValues = Array.isArray(req?.values) && req.values.length ? req.values : null;
  if (legValues) {
    const parsed = legValues.map(toBigIntInteger);
    const badIdx = parsed.findIndex((p) => p === null);
    if (badIdx >= 0) {
      return { decision: 'deny', reason: `parity: leg ${badIdx} amount unparseable (fail-closed)`, evidence: { rule: RULE, legs: legValues, deny_leg: badIdx, gate: 'all-or-nothing' } };
    }
    const oddIdx = parsed.findIndex((p) => p % 2n !== 0n);
    if (oddIdx >= 0) {
      return { decision: 'deny', reason: `parity: leg ${oddIdx} amount ${parsed[oddIdx]} is odd -> deny (all-or-nothing)`, evidence: { rule: RULE, legs: legValues, deny_leg: oddIdx, gate: 'all-or-nothing' } };
    }
    return { decision: 'approve', reason: `parity: all ${legValues.length} leg(s) even -> approve`, evidence: { rule: RULE, legs: legValues, parity: 'all-even', gate: 'all-or-nothing' } };
  }

  const amount = parseAmount(req);
  if (amount === null) {
    return { decision: 'deny', reason: 'parity: no parseable amount (fail-closed)', evidence: { rule: RULE, amount: null, parity: 'unknown' } };
  }
  const even = amount % 2n === 0n;
  return {
    decision: even ? 'approve' : 'deny',
    reason: `parity: amount ${amount} is ${even ? 'even -> approve' : 'odd -> deny'}`,
    evidence: { rule: RULE, amount: amount.toString(), parity: even ? 'even' : 'odd' },
  };
}

/**
 * Pull the integer transfer amount from a PolicyRequest.
 * Prefers the structured `value` field, falling back to the first number in `actionSummary`.
 * @returns {bigint|null} the integer amount, or null if none can be parsed.
 */
export function parseAmount(req) {
  for (const candidate of [req?.value, firstNumber(req?.actionSummary)]) {
    const n = toBigIntInteger(candidate);
    if (n !== null) return n;
  }
  return null;
}

/** First number-ish run in a string (e.g. "Transfer 5,000 to acc://..." -> "5,000"). */
function firstNumber(s) {
  if (typeof s !== 'string') return null;
  const m = /(\d[\d,]*)/.exec(s);
  return m ? m[1] : null;
}

/** Parse an integer amount to BigInt, tolerating thousands separators and a fractional part. */
function toBigIntInteger(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim().replace(/,/g, '');
  // Parity is decided on the integer part; any fractional component is ignored.
  const m = /^(\d+)(?:\.\d+)?$/.exec(s);
  if (!m) return null;
  try { return BigInt(m[1]); } catch { return null; }
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return; }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let parsed = {};
    try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
    const decision = decideByParity(parsed);
    const bodyStr = JSON.stringify(decision);
    console.log(
      `[parity-policy] ${decision.decision.toUpperCase()} <- value=${parsed.value ?? '?'} ` +
      `"${parsed.actionSummary ?? ''}" (${decision.evidence.parity})`,
    );
    const headers = { 'content-type': 'application/json' };
    if (HMAC) {
      const ts = String(Date.now());
      // Sign the EXACT bytes sent below. The signer verifies the raw response body, not a reparse of it,
      // so any difference in serialization here would fail the MAC. Header names are the signer's
      // vendor-neutral defaults; override with policy.signature_header if your engine uses others.
      const mac = createHmac('sha256', HMAC).update(`${ts}.${bodyStr}`).digest('hex');
      headers['x-signer-timestamp'] = ts;
      headers['x-signer-signature'] = `t=${ts},v1=${mac}`;
    }
    res.writeHead(200, headers);
    res.end(bodyStr);
  });
});

// Listen only when run directly (so tests can import the pure helpers without a socket).
const isMain = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (isMain) {
  server.listen(PORT, () =>
    console.log(`[parity-policy] listening on :${PORT} — ${RULE}${HMAC ? ' (+HMAC responses)' : ''}`),
  );
}
