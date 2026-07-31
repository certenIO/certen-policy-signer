/**
 * Reference policy adapter — point the signer at an approvals API you ALREADY HAVE.
 *
 * By default the signer sends its own JSON and expects `{"decision":"approve"}` back. That is a clean
 * contract, but it assumes you are writing a new endpoint for it. If you already run a rules engine, a
 * fraud API, or an approvals service, an adapter lets the signer speak *its* shape directly — no shim
 * service to deploy, no fork of this repo.
 *
 *   policy:
 *     url: "https://approvals.internal/api/v2/authorize"
 *     adapter_module: "./examples/policy-adapter.mjs"
 *
 * Both methods are optional. Supply `buildRequest` if their request shape differs, `parseResponse` if
 * their reply shape does, or both. Omit one and the signer's default is used for that direction.
 *
 * ── What the signer still guarantees, whatever you write here ────────────────────────────────────────
 *
 * 1. ONLY approve / deny / pending COUNT. `parseResponse` returning anything else — a different string,
 *    undefined, a stray object — is treated as a failure to decide, and a failure to decide withholds the
 *    signature. You cannot widen what counts as an approval from in here; you can only describe where to
 *    find one. Throwing has the same effect, so throwing on anything you do not recognize is correct.
 *
 * 2. THE HMAC STILL COVERS WHAT YOU BUILD. If `policy.auth: hmac` is set, the signer signs the exact
 *    bytes `buildRequest` returned and verifies the reply's MAC BEFORE `parseResponse` ever sees it. An
 *    adapter reshapes what a reply means; it has no say in whether the reply is authentic.
 *
 * 3. FAILURES ARE STILL FAIL-CLOSED. An adapter that throws withholds. It never falls back to the default
 *    shape — sending a request the engine will misread is worse than sending none.
 */

export default {
  name: 'acme-approvals-v2',

  /**
   * Turn the signer's decision request into whatever your API expects.
   *
   * Return `body` as an object and it is JSON-encoded; return a string to control the encoding exactly
   * (form-encoded, XML, a bespoke JSON layout). `headers` merge over the defaults — this is where an API
   * key or tenant header goes. `url` overrides `policy.url` for this one request, for an engine with a
   * per-account path.
   */
  buildRequest(req) {
    return {
      // Their API wants a flat "authorization request", not the signer's shape.
      body: {
        reference: req.operationId ?? req.txHash,
        description: req.actionSummary,
        // Send EVERY amount. `req.value` is only the first leg, carried for display — gating on it leaves
        // the rest ungated, and an over-limit amount rides along beside one that is fine.
        amounts: req.values ?? [],
        counterparty: req.target,
        network: req.chain,
        source_account: req.account,
      },
      headers: {
        'x-api-key': process.env.APPROVALS_API_KEY ?? '',
        'x-tenant': 'acme',
      },
      // url: `https://approvals.internal/api/v2/accounts/${encodeURIComponent(req.account)}/authorize`,
    };
  },

  /**
   * Read their reply. `body` is the RAW response text exactly as it arrived, and you are handed the
   * status too — some APIs answer 403 for "denied", and the signer deliberately does not decide that for
   * you.
   */
  parseResponse({ status, body }) {
    // Their API says "denied" with a 403 rather than a 200. Without this it would look like an outage,
    // and the transaction would sit pending instead of being killed.
    if (status === 403) return { decision: 'deny', reason: 'approvals API returned 403' };

    // A 202 means a human is reviewing. `pending` withholds and re-asks next poll — it does NOT cast a
    // reject vote, so a decision that takes an hour is still signed when it arrives.
    if (status === 202) return { decision: 'pending', reason: 'queued for manual review' };

    // Anything else non-2xx is a real failure. Throw: the signer withholds and retries.
    if (status < 200 || status >= 300) throw new Error(`approvals API HTTP ${status}`);

    const r = JSON.parse(body);

    // Map their vocabulary onto the signer's. Note the default case: an outcome we do not recognize
    // THROWS rather than guessing. A silent fallthrough to "approve" would be the worst bug in the file,
    // and a silent fallthrough to "deny" would kill transactions on a schema change.
    switch (r.outcome) {
      case 'ALLOW':
        return {
          decision: 'approve',
          reason: r.rule_name,
          // Everything here is persisted verbatim in the signer's receipt. Put your rule ids, scores,
          // reviewer identity, and ticket numbers in it — this is what an auditor reads a year from now.
          evidence: { ruleId: r.rule_id, score: r.risk_score, reviewer: r.reviewed_by },
        };
      case 'BLOCK':
        return { decision: 'deny', reason: r.rule_name, evidence: { ruleId: r.rule_id } };
      case 'REVIEW':
        return { decision: 'pending', reason: 'awaiting reviewer' };
      default:
        throw new Error(`unrecognized outcome: ${JSON.stringify(r.outcome)}`);
    }
  },
};
