/**
 * Outbound notifications — text messages, email, Slack, and a generic webhook.
 *
 * The signer sends these itself rather than handing you a webhook and wishing you luck. Every channel here
 * is a single HTTPS POST to a documented endpoint, so supporting them directly costs no dependencies and
 * saves every integrator from building the same relay: fill in a phone number and a Twilio credential and
 * you get a text message when something needs your signature.
 *
 * The `webhook` channel remains for anything not covered — your own paging system, a ticket queue, a
 * channel none of these speak. `examples/notifier.mjs` is a receiver for it.
 *
 * THE RULE THAT MATTERS: delivery is fire-and-forget and can never affect signing.
 *
 * Everywhere else in this codebase a failure withholds the signature. Here that instinct is wrong — a
 * signer that stops signing because Twilio is down is a worse signer. So emit() never throws, never blocks
 * the pipeline, and never retries: it logs the failure and drops the event. A missed notification is a
 * missed notification; the durable record of what happened is the receipt store, which is not best-effort.
 */
import axios from 'axios';
import { createHmac } from 'node:crypto';
import { Logger } from './logger.js';

/** Everything the signer will tell you about. Receivers should ignore names they do not recognize —
 *  new events may be added, and a receiver that throws on an unknown one breaks on upgrade. */
export type NotifyEvent =
  | 'pending.discovered'   // a tx naming our book turned up; nobody has decided anything yet
  | 'decision.approved'    // signed an accept vote
  | 'decision.denied'      // denied (and cast a reject vote, if configured)
  | 'signature.failed'     // we DECIDED to vote and could not submit it — the operator event
  | 'signer.paused'
  | 'signer.resumed';

export const NOTIFY_EVENTS: NotifyEvent[] = [
  'pending.discovered', 'decision.approved', 'decision.denied',
  'signature.failed', 'signer.paused', 'signer.resumed',
];

/**
 * What the metered channels send when you do not say otherwise.
 *
 * SMS costs money per message and interrupts a human, so defaulting it to every event would turn a busy
 * signer into a spam source and quietly run up a bill. These two are the ones a person actually needs to
 * act on: work has arrived, or a vote we decided to cast did not make it. Webhook and Slack default to
 * everything, because neither is metered and both are read by machines or scrolled past.
 */
export const METERED_DEFAULT_EVENTS: NotifyEvent[] = ['pending.discovered', 'signature.failed'];

/**
 * There is deliberately no "the engine said pending" event.
 *
 * It would fire on every poll for the life of the transaction — a text message every 20 seconds — and
 * de-duplicating it correctly means persisting per-tx notification state, which is a lot of machinery for
 * an event the engine that produced it already knows about. `pending.discovered` already told you the
 * transaction needs attention. Poll `GET /v1/requests?status=awaiting_policy` for the current queue.
 */

export interface NotifyPayload {
  event: NotifyEvent;
  at: string;                 // ISO
  orgId: string;
  txHash?: string;
  operationId?: string;
  account?: string;
  /** The decoded sentence — the same text the policy engine was shown, so a text message can be read. */
  actionSummary?: string;
  chain?: string;
  target?: string;
  values?: string[];
  /** The engine's own words, when it gave any. */
  reason?: string;
  error?: string;
}

export interface Notifier {
  emit(p: NotifyPayload): void;
}

/** The default when nothing is configured: does nothing, costs nothing. */
export const NULL_NOTIFIER: Notifier = { emit() {} };

// ── message rendering ───────────────────────────────────────────────────────────────────────────────

const HEADLINE: Record<NotifyEvent, string> = {
  'pending.discovered': 'Approval needed',
  'decision.approved': 'Signed',
  'decision.denied': 'Denied',
  'signature.failed': 'SIGNATURE FAILED',
  'signer.paused': 'Signing PAUSED',
  'signer.resumed': 'Signing resumed',
};

/**
 * One line, short enough for a single SMS segment.
 *
 * A text message is read on a lock screen, so the useful content is "what is it and how much" — not the
 * transaction hash, which nobody retypes off a phone. The hash goes last and is truncated; a recipient who
 * needs the full one opens the console. Kept under ~160 chars so a routine notification is one billed
 * segment rather than three.
 */
export function smsText(p: NotifyPayload): string {
  const bits = [`[${p.orgId || 'signer'}] ${HEADLINE[p.event]}`];
  if (p.actionSummary) bits.push(p.actionSummary);
  if (p.error) bits.push(p.error);
  else if (p.reason) bits.push(p.reason);
  let text = bits.join(': ');
  if (text.length > 140) text = `${text.slice(0, 137)}...`;
  if (p.txHash) text += ` (${p.txHash.slice(0, 8)})`;
  return text;
}

/** The same content with room to breathe — email bodies and Slack messages. */
export function longText(p: NotifyPayload): string {
  const lines = [`${HEADLINE[p.event]} — ${p.orgId || 'signer'}`, ''];
  if (p.actionSummary) lines.push(`Action:    ${p.actionSummary}`);
  if (p.account) lines.push(`Account:   ${p.account}`);
  if (p.chain) lines.push(`Chain:     ${p.chain}`);
  if (p.target) lines.push(`Target:    ${p.target}`);
  if (p.values?.length) lines.push(`Amounts:   ${p.values.join(', ')}`);
  if (p.reason) lines.push(`Reason:    ${p.reason}`);
  if (p.error) lines.push(`Error:     ${p.error}`);
  if (p.txHash) lines.push(`Tx:        ${p.txHash}`);
  lines.push(`At:        ${p.at}`);
  return lines.join('\n');
}

// ── channels ────────────────────────────────────────────────────────────────────────────────────────

/** One delivery target. Returns a promise the caller does NOT await — see MultiNotifier.emit. */
interface Channel {
  name: string;
  events: NotifyEvent[];
  send(p: NotifyPayload): Promise<void>;
}

export interface WebhookConfig { url: string; hmac_secret?: string; timeout_ms?: number; signature_header?: string; events?: NotifyEvent[]; }
export interface SmsConfig { to: string[]; from: string; account_sid: string; auth_token: string; events?: NotifyEvent[]; }
export interface EmailConfig { to: string[]; from: string; api_key: string; events?: NotifyEvent[]; }
export interface SlackConfig { webhook_url: string; events?: NotifyEvent[]; }

export interface NotifyConfig {
  events?: NotifyEvent[];      // global default for channels that do not state their own
  webhook?: WebhookConfig;
  sms?: SmsConfig;
  email?: EmailConfig;
  slack?: SlackConfig;
}

/** Generic signed webhook. Same MAC scheme as the policy channel, so an integrator verifies it with the
 *  code they already wrote for their policy engine. */
function webhookChannel(c: WebhookConfig, fallback: NotifyEvent[]): Channel {
  return {
    name: 'webhook',
    events: c.events ?? fallback,
    async send(p) {
      const body = JSON.stringify(p);
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (c.hmac_secret) {
        const ts = String(Date.now());
        const mac = createHmac('sha256', c.hmac_secret).update(`${ts}.${body}`).digest('hex');
        headers[c.signature_header ?? 'x-signer-signature'] = `t=${ts},v1=${mac}`;
      }
      const res = await axios.post(c.url, body, { headers, timeout: c.timeout_ms ?? 5_000, validateStatus: () => true });
      if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    },
  };
}

/**
 * Twilio. One form-encoded POST per recipient with HTTP basic auth — no SDK, and the API has been stable
 * for over a decade. Any Twilio-compatible gateway works: point `account_sid`/`auth_token` at it.
 */
function smsChannel(c: SmsConfig, fallback: NotifyEvent[]): Channel {
  return {
    name: 'sms',
    events: c.events ?? fallback,
    async send(p) {
      const text = smsText(p);
      const url = `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(c.account_sid)}/Messages.json`;
      // Sent per recipient, and a failure to ONE must not silently cancel the rest — allSettled, then
      // report only if every number failed. One bad entry in `to` should not mute the whole on-call list.
      const results = await Promise.allSettled(c.to.map((to) =>
        axios.post(url, new URLSearchParams({ To: to, From: c.from, Body: text }), {
          auth: { username: c.account_sid, password: c.auth_token },
          timeout: 8_000,
          validateStatus: (s) => s >= 200 && s < 300,
        })));
      const failed = results.filter((r) => r.status === 'rejected');
      if (failed.length === results.length) {
        throw new Error(`all ${results.length} recipient(s) failed: ${(failed[0] as PromiseRejectedResult)?.reason?.message}`);
      }
    },
  };
}

/** SendGrid. One JSON POST; a 202 means accepted for delivery. */
function emailChannel(c: EmailConfig, fallback: NotifyEvent[]): Channel {
  return {
    name: 'email',
    events: c.events ?? fallback,
    async send(p) {
      const res = await axios.post('https://api.sendgrid.com/v3/mail/send', {
        personalizations: [{ to: c.to.map((email) => ({ email })) }],
        from: { email: c.from },
        subject: `[${p.orgId || 'signer'}] ${HEADLINE[p.event]}${p.actionSummary ? ` — ${p.actionSummary}` : ''}`,
        content: [{ type: 'text/plain', value: longText(p) }],
      }, {
        headers: { authorization: `Bearer ${c.api_key}`, 'content-type': 'application/json' },
        timeout: 8_000,
        validateStatus: () => true,
      });
      if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    },
  };
}

/** Slack incoming webhook. The URL is the credential — treat it as a secret. */
function slackChannel(c: SlackConfig, fallback: NotifyEvent[]): Channel {
  return {
    name: 'slack',
    events: c.events ?? fallback,
    async send(p) {
      const res = await axios.post(c.webhook_url, {
        text: `*${HEADLINE[p.event]}* — ${p.orgId || 'signer'}`,
        blocks: [
          { type: 'section', text: { type: 'mrkdwn', text: `*${HEADLINE[p.event]}* — ${p.orgId || 'signer'}` } },
          { type: 'section', text: { type: 'mrkdwn', text: '```' + longText(p) + '```' } },
        ],
      }, { timeout: 8_000, validateStatus: () => true });
      if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
    },
  };
}

/** Build the configured channels. Returns NULL_NOTIFIER when none are set. */
export function buildNotifier(cfg: NotifyConfig | undefined, logger: Logger): Notifier {
  if (!cfg) return NULL_NOTIFIER;
  const all = cfg.events ?? NOTIFY_EVENTS;
  const metered = cfg.events ?? METERED_DEFAULT_EVENTS;
  const channels: Channel[] = [];
  if (cfg.webhook?.url) channels.push(webhookChannel(cfg.webhook, all));
  if (cfg.sms?.to?.length) channels.push(smsChannel(cfg.sms, metered));
  if (cfg.email?.to?.length) channels.push(emailChannel(cfg.email, metered));
  if (cfg.slack?.webhook_url) channels.push(slackChannel(cfg.slack, all));
  if (!channels.length) return NULL_NOTIFIER;
  return new MultiNotifier(channels, logger);
}

export class MultiNotifier implements Notifier {
  constructor(private readonly channels: Channel[], private readonly logger: Logger) {}

  /** Channel names and the events each is subscribed to — logged at boot so a misconfigured filter is
   *  visible then, rather than as a text message that never arrives. */
  describe(): Array<{ channel: string; events: NotifyEvent[] }> {
    return this.channels.map((c) => ({ channel: c.name, events: c.events }));
  }

  /** Synchronous by signature on purpose: a caller cannot accidentally `await` this into the hot path. */
  emit(p: NotifyPayload): void {
    for (const c of this.channels) {
      if (!c.events.includes(p.event)) continue;
      // Deliberately not awaited, and every rejection is caught here — an unhandled rejection from a
      // notification would take the process down, which is a spectacular way to fail at being optional.
      void c.send(p).catch((e: unknown) => {
        this.logger.warn({ channel: c.name, event: p.event, err: (e as Error).message }, 'notification delivery failed (dropped)');
      });
    }
  }
}
