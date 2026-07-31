/**
 * Reference receiver for the `webhook` notification channel.
 *
 * YOU PROBABLY DO NOT NEED THIS FILE. The signer sends text messages, email, and Slack itself — set
 * `notify.sms`, `notify.email`, or `notify.slack` and you are done. This is the escape hatch for
 * everything else: your pager, a ticket queue, an internal bus, a channel none of the built-ins speak.
 *
 * Copy this file, replace ONE function (`deliver`), and you have that.
 *
 *   # terminal 1
 *   node examples/notifier.mjs                 # :9098
 *   # in your config.yaml
 *   notify:
 *     webhook:
 *       url: "http://127.0.0.1:9098/events"
 *       hmac_secret: "env:NOTIFY_HMAC_SECRET"
 *
 * ── The contract ──────────────────────────────────────────────────────────────────────────────────────
 *
 *   POST <notify.url>   application/json
 *     {
 *       "event":         "pending.discovered",
 *       "at":            "2026-07-29T12:00:00.000Z",
 *       "orgId":         "your-org",
 *       "txHash":        "9c2b…",
 *       "operationId":   "PO-1043",              // present if your payload carried one
 *       "account":       "acc://acme.acme/orders",
 *       "actionSummary": "Transfer 4000 wei to 0xBe00…9251",   // the sentence — this is your message body
 *       "chain":         "ethereum-sepolia",
 *       "target":        "0xBe00…9251",
 *       "values":        ["4000"],
 *       "reason":        "matched rule 12",      // the policy engine's own words, on decision events
 *       "error":         "…"                     // on signature.failed
 *     }
 *
 * Five events — the webhook channel receives all of them unless you set `events: [...]` on it. (The
 * metered channels, sms and email, default to just `pending.discovered` and `signature.failed`.)
 *
 *   pending.discovered   a transaction naming your key book turned up and needs a decision. Fired ONCE per
 *                        transaction, on first sighting — not on every poll. THIS is the "you have work"
 *                        notification.
 *   decision.approved    signed an accept vote. The transaction executes.
 *   decision.denied      denied. `reason` carries why.
 *   signature.failed     you decided to vote and the vote could not be submitted. This is the one that
 *                        should page a human rather than fill a channel — nothing is wrong with the policy,
 *                        something is wrong with the signer or the network.
 *   signer.paused        someone hit the emergency stop. `signer.resumed` when they undo it.
 *
 * ── Two things to know before you rely on this ────────────────────────────────────────────────────────
 *
 * 1. DELIVERY IS BEST-EFFORT, and that is deliberate. Everywhere else the signer fails closed; here it
 *    does not. If this endpoint is down, slow, or returns a 500, the event is logged and DROPPED — the
 *    signer will not retry it and will not stop signing. A signer that refuses to sign because SMS is down
 *    would be a worse signer. So: do not build an audit trail out of these. The durable record is the
 *    receipt store (`GET /v1/requests`), which is not best-effort.
 *
 * 2. THERE IS NO "still waiting" EVENT. If your policy engine answers `pending` (a human approval, a
 *    biometric challenge), the signer keeps asking every poll and stays quiet — an event there would text
 *    you every 20 seconds for the life of the transaction. For a live work queue, poll
 *    `GET /v1/requests?status=awaiting_policy` on the admin API instead.
 */
import http from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 9098);
const SECRET = process.env.NOTIFY_HMAC_SECRET ?? '';

// ══════════════════════════════════════════════════════════════════════════════════════════════════════
//  REPLACE THIS FUNCTION. Everything above and below it is plumbing.
// ══════════════════════════════════════════════════════════════════════════════════════════════════════
async function deliver(e) {
  // Route by event. Most teams want the first one on a chat channel and the failure on a pager.
  switch (e.event) {
    case 'pending.discovered':
      // await twilio.messages.create({ to: ONCALL, from: FROM, body: `Approval needed: ${e.actionSummary}` });
      // await slack.chat.postMessage({ channel: '#approvals', text: `${e.actionSummary} — ${e.txHash}` });
      console.log(`[NOTIFY] approval needed — ${e.actionSummary}  (${e.txHash?.slice(0, 12)}…)`);
      break;
    case 'signature.failed':
      // await pagerduty.trigger({ summary: `Signer could not submit a vote: ${e.error}` });
      console.error(`[NOTIFY] SIGNATURE FAILED — ${e.error}  (${e.txHash?.slice(0, 12)}…)`);
      break;
    case 'signer.paused':
      console.warn('[NOTIFY] signing PAUSED');
      break;
    default:
      // decision.approved / decision.denied / signer.resumed — usually a log line, not a page.
      console.log(`[NOTIFY] ${e.event} — ${e.reason ?? e.actionSummary ?? ''}`);
  }
}

// ── plumbing ──────────────────────────────────────────────────────────────────────────────────────────

/** Verify the signer's MAC over the RAW bytes. Same scheme as the policy channel: HMAC-SHA256(secret,
 *  "<timestamp>.<raw body>"), sent as `t=<ms>,v1=<hex>`. Verify the wire bytes, never a re-serialized copy. */
function verify(raw, header) {
  const m = /t=(\d+),v1=([a-f0-9]+)/.exec(header ?? '');
  if (!m) return false;
  if (Math.abs(Date.now() - Number(m[1])) > 300_000) return false;   // 5-minute replay window
  const expect = createHmac('sha256', SECRET).update(`${m[1]}.${raw}`).digest('hex');
  const a = Buffer.from(expect), b = Buffer.from(m[2]);
  return a.length === b.length && timingSafeEqual(a, b);
}

http.createServer(async (req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return; }
  let raw = '';
  for await (const c of req) raw += c;

  if (SECRET && !verify(raw, req.headers['x-signer-signature'])) {
    console.error('[NOTIFY] rejected: bad signature');
    res.writeHead(401).end();
    return;
  }
  if (!SECRET) console.warn('[NOTIFY] NOTIFY_HMAC_SECRET unset — accepting unsigned events (dev only)');

  // Acknowledge FIRST, deliver after. The signer drops anything it cannot deliver in 5s, and a slow SMS
  // provider should not turn into a dropped event.
  res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
  try {
    await deliver(JSON.parse(raw));
  } catch (err) {
    console.error(`[NOTIFY] delivery threw: ${err.message}`);
  }
}).listen(PORT, () => {
  console.log(`notification receiver on :${PORT}  (POST /events)   signed=${Boolean(SECRET)}`);
});
