/**
 * Reference policy engine — `POST /decision`.
 *
 * THIS IS YOUR HALF OF THE INTEGRATION, and it is deliberately one small file with no dependencies.
 *
 * The signer sends one HTTP POST per pending transaction and reads a single field off the reply. It has
 * no idea, and no opinion, about what computed the answer — a biometric match, a rules engine, a Lambda,
 * a human clicking a button, a call to your existing approvals service. If it speaks HTTP and returns the
 * shape below, it works, and nothing else about your system has to change.
 *
 * Copy this file, replace ONE function (`checkPolicy`), and you are integrated.
 *
 * ── The contract ──────────────────────────────────────────────────────────────────────────────────────
 *
 *   Request  (signer → you):   POST <policy.url>   application/json
 *     {
 *       "requestId":     "…",              // unique PER REQUEST — regenerated on every poll. Not an id
 *                                          //   for the transaction. See the note on `pending` below.
 *       "txHash":        "…",              // the pending Accumulate transaction — STABLE across polls
 *       "operationId":   "…",              // your own id, if your payload carried one (optional)
 *       "account":       "acc://…/data",   // the account the transaction acts on
 *       "chain":         "ethereum-sepolia",
 *       "actionSummary": "Transfer 4000 wei to 0xBe00…9251",
 *       "target":        "0xBe00…9251",
 *       "value":         "4000",           // representative amount (first leg) — for display
 *       "values":        ["4000"],         // EVERY amount in the transaction — GATE ON THESE
 *       "expiresAt":     "2026-…Z"         // how long THIS REQUEST is valid, NOT the tx's on-chain deadline
 *     }
 *
 *   Reply  (you → signer):     200   application/json
 *     {
 *       "decision": "approve" | "deny" | "pending",   // the ONLY required field
 *       "reason":   "matched policy rule 12",         // optional, human-readable → stored in the receipt
 *       "evidence": { … }                             // optional, any JSON → stored VERBATIM in the receipt
 *     }
 *
 * ── The four outcomes (the part to read before a security review) ─────────────────────────────────────
 *
 *   "approve"      → the signer casts an ACCEPT vote with your key. The transaction executes.
 *   "deny"         → the signer casts a REJECT vote (or withholds — your config). The transaction dies.
 *   "pending"      → you have not decided yet. The signer signs NOTHING, leaves the transaction pending
 *                    on chain, and asks again next poll. Use this for anything out-of-band: a human
 *                    approval, a step-up auth challenge, a review queue.
 *   anything else  → the signer signs NOTHING and retries. "Anything else" means a non-2xx status, a body
 *                    that is not JSON, a missing or unrecognized `decision`, a timeout, an unreachable
 *                    endpoint, or a bad HMAC.
 *
 * The last two lines are the same behavior for different reasons, and that is the point: THE SIGNER IS
 * FAIL-CLOSED. An outage, a crash, a network blip, or an attacker taking this endpoint down can never
 * become an approval. Note the corollary — if you want a FAILED check to kill the transaction, you must
 * return `{"decision":"deny"}` explicitly. Throwing or timing out withholds instead, and the transaction
 * survives until it expires on chain.
 *
 * ── If you use `pending`, key your state on `txHash` ──────────────────────────────────────────────────
 *
 * `requestId` is regenerated on every poll; `txHash` is stable. Keying an open challenge on `requestId`
 * means opening a NEW challenge on every poll — texting your user a fresh prompt every 20 seconds. The
 * `pending` mode below demonstrates the correct keying.
 *
 * ── Run it ────────────────────────────────────────────────────────────────────────────────────────────
 *
 *   node examples/policy-engine.mjs            # listens on :9099, POST /decision
 *
 *   Point the signer at it:  policy.url = "http://127.0.0.1:9099/decision"
 *
 *   Drive every outcome against a running signer, before you have written any policy code:
 *     POLICY_MODE=approve node examples/policy-engine.mjs   # approve everything
 *     POLICY_MODE=deny    node examples/policy-engine.mjs   # reject everything
 *     POLICY_MODE=fail    node examples/policy-engine.mjs   # simulate an outage → watch it fail closed
 *     POLICY_MODE=pending node examples/policy-engine.mjs   # withhold a few polls, then approve
 *     POLICY_MODE=parity  node examples/policy-engine.mjs   # approve even amounts, deny odd — a visible
 *                                                           #   rule, so you can prove the gate is real
 *
 *   Authenticate the channel both ways (set policy.auth: "hmac" and the same secret on the signer):
 *     POLICY_HMAC_SECRET=<shared-secret> node examples/policy-engine.mjs
 */

import http from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 9099);
const HMAC_SECRET = process.env.POLICY_HMAC_SECRET || '';

// Header names for the signed channel. These are the signer's defaults; if you change
// policy.signature_header there, change it here too.
const SIG_HEADER = (process.env.POLICY_SIGNATURE_HEADER || 'x-signer-signature').toLowerCase();
const LEGACY_SIG_HEADER = 'x-certen-signature';

// Demo modes — see "Run it" above. Delete this and the modes it drives once your engine is wired in.
const MODE = process.env.POLICY_MODE || 'approve';
const CHALLENGE_POLLS = Number(process.env.POLICY_PENDING_POLLS ?? 3);
const openChallenges = new Map(); // txHash -> polls seen. Keyed on txHash, NOT requestId. See above.

/* ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *  THE ONLY FUNCTION YOU REPLACE.
 *
 *  Return { ok, reason, evidence }:
 *    ok        true  → approve (the signer signs)
 *              false → deny    (the signer rejects, killing the transaction)
 *    reason    a human-readable sentence — persisted in the signer's receipt, so it is what an auditor
 *              reads a year from now. Say WHY, not just what.
 *    evidence  any JSON — persisted verbatim. Put match scores, rule ids, reviewer identity, ticket
 *              numbers here. This is the durable link between "we decided X" and "here is what happened".
 *
 *  Decide on anything in `request`: values (amounts), target, chain, account, actionSummary, operationId.
 *
 *  GATE ON `request.values`, NOT `request.value`. `values` holds EVERY amount in the transaction;
 *  `value` is only the first, for display. A transaction can carry several — check them all, or one
 *  can slip past a limit the others satisfy. `checkAmountCeiling` below shows the all-or-nothing shape.
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════ */
function checkPolicy(request) {
  // ─── replace this body with a call to your engine ───────────────────────────────────────────────────
  if (MODE === 'parity') {
    // A deliberately visible rule, so you can watch the gate actually decide: even amounts approve,
    // odd amounts deny. Useful for a first end-to-end run; meaningless as a policy.
    const amounts = request?.values?.length ? request.values : [request?.value].filter((v) => v != null);
    const allEven = amounts.length > 0 && amounts.every((a) => BigInt(String(a)) % 2n === 0n);
    return {
      ok: allEven,
      reason: allEven ? 'all amounts are even' : 'an amount is odd',
      evidence: { rule: 'parity', amounts },
    };
  }

  const ok = MODE !== 'deny';
  return {
    ok,
    reason: ok ? 'demo mode: approved' : 'demo mode: denied',
    evidence: { demo: true, mode: MODE, requestId: request?.requestId },
  };
  // ────────────────────────────────────────────────────────────────────────────────────────────────────
}

/**
 * An all-or-nothing amount ceiling, as an example of gating on `values` correctly.
 *
 * Not called by default — wire it into checkPolicy if you want it. Two details that matter in real use:
 * compare as BigInt (at wei scale Number() silently rounds, and would wave through an amount just over
 * the limit), and treat an unparseable amount as a FAILURE rather than skipping it.
 */
export function checkAmountCeiling(request, ceiling) {
  const amounts = request?.values?.length ? request.values : [request?.value].filter((v) => v != null);
  if (amounts.length === 0) return { ok: true, reason: 'no amounts to check' };
  for (const a of amounts) {
    let n;
    try {
      n = BigInt(String(a).trim().split('.')[0]);
    } catch {
      return { ok: false, reason: `unparseable amount ${JSON.stringify(a)}`, evidence: { amounts } };
    }
    if (n > ceiling) {
      return { ok: false, reason: `amount ${a} exceeds the ${ceiling} ceiling`, evidence: { amounts, ceiling: String(ceiling) } };
    }
  }
  return { ok: true, reason: `all ${amounts.length} amount(s) within the ceiling`, evidence: { amounts } };
}

/* ────────────────────────────────────────────────────────────────────────────────────────────────────────
 *  Transport. You should not need to touch anything below this line.
 * ──────────────────────────────────────────────────────────────────────────────────────────────────────── */

const server = http.createServer((req, res) => {
  if (req.method !== 'POST' || new URL(req.url, 'http://x').pathname !== '/decision') {
    res.writeHead(404, { 'content-type': 'application/json' });
    return res.end('{"error":"POST /decision"}');
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const rawRequest = Buffer.concat(chunks).toString('utf8');

    // If a shared secret is configured, verify the request really came from your signer BEFORE trusting
    // it. A bad or absent signature ⇒ 401, which the signer treats as fail-closed: it signs nothing.
    if (HMAC_SECRET) {
      const header = req.headers[SIG_HEADER] ?? req.headers[LEGACY_SIG_HEADER];
      if (!verify(HMAC_SECRET, header, rawRequest)) {
        return send(res, 401, { error: 'unauthenticated request' });
      }
    }

    // Demo mode: simulate an outage, so you can SEE the signer fail closed (withhold and retry) rather
    // than take a failure for a decision. In production this branch does not exist.
    if (MODE === 'fail') {
      return send(res, 500, { error: 'simulated policy-engine outage' });
    }

    let request;
    try {
      request = JSON.parse(rawRequest || '{}');
    } catch {
      return send(res, 400, { error: 'request body is not JSON' });
    }

    // Demo mode: a real out-of-band challenge. Your engine cannot answer until a human finishes something,
    // so for the first few polls it returns NO decision — an explicit "pending" — and the signer withholds
    // and retries while the transaction stays pending on chain. Once the challenge completes we fall
    // through to checkPolicy(). Note the keying on txHash: keyed on requestId, this would open a brand new
    // challenge on every poll. "Not answered yet" is a withhold, never a deny.
    if (MODE === 'pending') {
      const seen = (openChallenges.get(request.txHash) ?? 0) + 1;
      openChallenges.set(request.txHash, seen);
      if (seen < CHALLENGE_POLLS) {
        log('PENDING', request, `challenge in progress (${seen}/${CHALLENGE_POLLS}) — awaiting the user`);
        return send(res, 200, {
          decision: 'pending',
          reason: `challenge in progress (${seen}/${CHALLENGE_POLLS})`,
        });
      }
    }

    const result = checkPolicy(request);
    const decision = {
      decision: result.ok ? 'approve' : 'deny',
      reason: result.reason,
      evidence: result.evidence,
    };
    log(decision.decision.toUpperCase(), request, decision.reason);
    send(res, 200, decision);
  });
});

function log(verdict, request, reason) {
  console.log(
    `[decision] ${String(verdict).padEnd(7)} tx=${String(request?.txHash ?? '?').slice(0, 16)} ` +
    `"${request?.actionSummary ?? ''}" — ${reason ?? ''}`,
  );
}

/** Send a JSON reply, signing it with the shared secret when one is configured (mirror of verify()). */
function send(res, status, body) {
  const raw = JSON.stringify(body);
  const headers = { 'content-type': 'application/json' };
  if (HMAC_SECRET) {
    const t = String(Date.now());
    // Sign the EXACT bytes sent below. The signer verifies the raw response body rather than a reparse
    // of it, so signing a re-serialized copy would fail the MAC — and a failed MAC is a policy failure,
    // which means it would silently never sign again.
    const mac = createHmac('sha256', HMAC_SECRET).update(`${t}.${raw}`).digest('hex');
    headers[SIG_HEADER] = `t=${t},v1=${mac}`;
  }
  res.writeHead(status, headers);
  res.end(raw);
}

/** Verify `<header>: t=<ms>,v1=<hex>` over "<t>.<rawBody>", fresh within 5 minutes. */
function verify(secret, header, rawBody) {
  const m = /t=(\d+),v1=([a-f0-9]+)/.exec(String(header ?? ''));
  if (!m) return false;
  if (Math.abs(Date.now() - Number(m[1])) > 5 * 60 * 1000) return false; // replay window
  const expect = createHmac('sha256', secret).update(`${m[1]}.${rawBody}`).digest('hex');
  const a = Buffer.from(expect);
  const b = Buffer.from(m[2]);
  // Constant-time: a plain !== leaks the expected MAC's prefix through timing.
  return a.length === b.length && timingSafeEqual(a, b);
}

server.listen(PORT, () => {
  console.log(`policy engine listening on :${PORT}  (POST /decision)`);
  console.log(`  mode: ${MODE}   HMAC: ${HMAC_SECRET ? `on (${SIG_HEADER})` : 'off'}`);
  console.log('  replace checkPolicy() with your engine; everything else stays.');
});
