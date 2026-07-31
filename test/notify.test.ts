/**
 * Outbound notifications.
 *
 * The behaviour under test is mostly NEGATIVE: this is the one subsystem that must not fail closed, so the
 * cases that matter are "the receiver is broken and the signer carried on anyway". A regression here does
 * not look like a missing text message — it looks like a signer that stopped signing because a webhook was
 * down, which is a far worse failure than the one notifications were added to solve.
 */
import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { createHmac } from 'node:crypto';
import pino from 'pino';
import { buildNotifier, NULL_NOTIFIER, NotifyPayload, smsText, METERED_DEFAULT_EVENTS } from '../src/notify.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';

const silent = pino({ level: 'silent' });
const TX = 'cd'.repeat(32);
const SIGNER = 'acc://demo-org.acme/book/1';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A receiver that records what it was sent. `behave: 'fail'` makes every delivery 500. */
async function receiver(opts: { secret?: string; behave?: 'ok' | 'fail' | 'hang' } = {}) {
  const got: Array<{ body: NotifyPayload; sig?: string; raw: string }> = [];
  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    got.push({ body: JSON.parse(raw), sig: req.headers['x-signer-signature'] as string, raw });
    if (opts.behave === 'fail') return void res.writeHead(500).end();
    if (opts.behave === 'hang') return;                    // never responds
    res.writeHead(200).end('{}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return { got, url: `http://127.0.0.1:${port}/events`, close: () => server.close() };
}

/** The webhook channel alone, subscribed to every event — the shape most of these tests exercise. */
function webhook(url: string, secret?: string) {
  return buildNotifier({ webhook: { url, hmac_secret: secret } }, silent);
}

function pipeline(notifier = NULL_NOTIFIER, decision: 'approve' | 'deny' = 'approve') {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, {
    body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] },
    principal: 'acc://alice.acme/tokens',
  });
  const store = new MemoryStore();
  const orchestrator = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))),
    policy: new MockPolicyClient({ decision }), store, resolver: new Resolver(acc), logger: silent,
    notifier, orgId: 'demo-org',
    options: { submitRejectVote: true },
  });
  return { orchestrator, store };
}

describe('notifications', () => {
  it('emits discovered + approved for a signed transaction, with the decoded summary attached', async () => {
    const r = await receiver();
    try {
      const { orchestrator } = pipeline(webhook(r.url));
      await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      await sleep(150);

      expect(r.got.map((g) => g.body.event)).toEqual(['pending.discovered', 'decision.approved']);
      const first = r.got[0].body;
      expect(first.orgId).toBe('demo-org');
      expect(first.txHash).toBe(TX);
      // The summary is the whole point: a text message has to be readable without the transaction body.
      expect(first.actionSummary).toBeTruthy();
      expect(first.values).toEqual(['5000']);
    } finally { r.close(); }
  });

  it('emits decision.denied with the engine\'s stated reason', async () => {
    const r = await receiver();
    try {
      const { orchestrator } = pipeline(webhook(r.url), 'deny');
      await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      await sleep(150);
      expect(r.got.map((g) => g.body.event)).toContain('decision.denied');
    } finally { r.close(); }
  });

  it('fires pending.discovered ONCE, not on every poll', async () => {
    // A per-poll notification is a text message every 20 seconds for the life of the transaction. The
    // guard is the same first-sighting check the discovery log line uses.
    const r = await receiver();
    try {
      const { orchestrator } = pipeline(webhook(r.url));
      await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      await sleep(150);
      expect(r.got.filter((g) => g.body.event === 'pending.discovered')).toHaveLength(1);
    } finally { r.close(); }
  });

  it('signs the event with the same MAC scheme as the policy channel', async () => {
    const secret = 'notify-secret';
    const r = await receiver({ secret });
    try {
      const { orchestrator } = pipeline(webhook(r.url, secret));
      await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      await sleep(150);

      const { sig, raw } = r.got[0];
      const m = /t=(\d+),v1=([a-f0-9]+)/.exec(sig ?? '');
      expect(m).toBeTruthy();
      // Verified over the RAW bytes, not a re-serialized copy — same rule as the policy response.
      expect(createHmac('sha256', secret).update(`${m![1]}.${raw}`).digest('hex')).toBe(m![2]);
    } finally { r.close(); }
  });

  // ── the cases that actually matter ──────────────────────────────────────────────────────────────────

  it('STILL SIGNS when the receiver returns 500', async () => {
    const r = await receiver({ behave: 'fail' });
    try {
      const { orchestrator, store } = pipeline(webhook(r.url));
      const out = await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      expect(out.status).toBe('signed');
      expect((await store.getReceipt(TX))?.vote).toBe('approve');
    } finally { r.close(); }
  });

  it('STILL SIGNS, without waiting, when the receiver never responds', async () => {
    const r = await receiver({ behave: 'hang' });
    try {
      const started = Date.now();
      const { orchestrator } = pipeline(webhook(r.url));
      const out = await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
      // The emit is not awaited, so the pipeline must not have paid the notifier's timeout.
      expect(Date.now() - started).toBeLessThan(2_000);
      expect(out.status).toBe('signed');
    } finally { r.close(); }
  });

  it('STILL SIGNS when the notify URL does not resolve at all', async () => {
    const { orchestrator } = pipeline(webhook("http://127.0.0.1:1/events"));
    const out = await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
    expect(out.status).toBe('signed');
    await sleep(300);   // let the rejected delivery settle; it must not surface as an unhandled rejection
  });

  it('STILL SIGNS when the notifier itself throws synchronously', async () => {
    const exploding = { emit() { throw new Error('boom'); } };
    const { orchestrator } = pipeline(exploding);
    const out = await orchestrator.handle({ txHash: TX, signerUrl: SIGNER });
    expect(out.status).toBe('signed');
  });

  it('is disabled by default — no notifier configured means nothing is emitted and nothing breaks', async () => {
    const { orchestrator } = pipeline();
    expect((await orchestrator.handle({ txHash: TX, signerUrl: SIGNER })).status).toBe('signed');
  });

  it('an empty notify block builds no notifier at all', () => {
    expect(buildNotifier({}, silent)).toBe(NULL_NOTIFIER);
    expect(buildNotifier(undefined, silent)).toBe(NULL_NOTIFIER);
  });
});

/**
 * Event filtering. This is what keeps a metered channel from becoming a bill: SMS and email default to
 * the two events a human must act on, while webhook and Slack get everything.
 */
describe('notification event filtering', () => {
  const payload = (event: any): NotifyPayload => ({ event, at: '2026-07-29T00:00:00Z', orgId: 'demo-org' });

  it('SMS and email default to the metered subset, not everything', () => {
    const n: any = buildNotifier({
      sms: { to: ['+15550000000'], from: '+15551111111', account_sid: 'AC', auth_token: 't' },
      email: { to: ['ops@acme.test'], from: 'signer@acme.test', api_key: 'k' },
    }, silent);
    for (const { channel, events } of n.describe()) {
      expect(events, channel).toEqual(METERED_DEFAULT_EVENTS);
      expect(events, channel).not.toContain('decision.approved');
    }
  });

  it('webhook and slack default to every event', () => {
    const n: any = buildNotifier({
      webhook: { url: 'http://127.0.0.1:1/x' },
      slack: { webhook_url: 'http://127.0.0.1:1/y' },
    }, silent);
    for (const { channel, events } of n.describe()) {
      expect(events, channel).toContain('decision.approved');
      expect(events, channel).toContain('signer.paused');
    }
  });

  it('a per-channel events list overrides the default', () => {
    const n: any = buildNotifier({
      sms: { to: ['+1'], from: '+2', account_sid: 'AC', auth_token: 't', events: ['decision.denied'] },
    }, silent);
    expect(n.describe()[0].events).toEqual(['decision.denied']);
  });

  it('a global events list applies to channels that do not state their own', () => {
    const n: any = buildNotifier({
      events: ['signature.failed'],
      webhook: { url: 'http://127.0.0.1:1/x' },
      sms: { to: ['+1'], from: '+2', account_sid: 'AC', auth_token: 't' },
    }, silent);
    for (const { events } of n.describe()) expect(events).toEqual(['signature.failed']);
  });

  it('does not deliver an event a channel is not subscribed to', async () => {
    const r = await receiver();
    try {
      const n = buildNotifier({ webhook: { url: r.url, events: ['signature.failed'] } }, silent);
      n.emit(payload('decision.approved'));
      n.emit(payload('signature.failed'));
      await sleep(150);
      expect(r.got.map((g) => g.body.event)).toEqual(['signature.failed']);
    } finally { r.close(); }
  });
});

/**
 * The SMS body. It is read on a lock screen, and it is billed per 160-char segment, so "short and
 * readable" is a functional requirement rather than a preference.
 */
describe('smsText', () => {
  it('leads with the org and what happened, and carries the action', () => {
    const text = smsText({
      event: 'pending.discovered', at: '2026-07-29T00:00:00Z', orgId: 'acme',
      txHash: 'ab'.repeat(32), actionSummary: 'Transfer 4000 wei to 0xBe00',
    });
    expect(text).toContain('acme');
    expect(text).toContain('Approval needed');
    expect(text).toContain('Transfer 4000 wei');
  });

  it('stays inside one SMS segment even when the summary is enormous', () => {
    const text = smsText({
      event: 'pending.discovered', at: '2026-07-29T00:00:00Z', orgId: 'acme',
      txHash: 'ab'.repeat(32), actionSummary: 'x'.repeat(5_000),
    });
    expect(text.length).toBeLessThanOrEqual(160);
  });

  it('carries the error on a failure, since that is the actionable part', () => {
    const text = smsText({
      event: 'signature.failed', at: '2026-07-29T00:00:00Z', orgId: 'acme',
      error: 'insufficient credits',
    });
    expect(text).toContain('SIGNATURE FAILED');
    expect(text).toContain('insufficient credits');
  });
});
