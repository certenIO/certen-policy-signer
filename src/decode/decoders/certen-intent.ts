/**
 * REFERENCE ADAPTER — decoding an organization-specific intent payload.
 *
 * ─────────────────────────────────────────────────────────────────────────────────────────────────────
 *  This is the worked example to copy when writing a decoder for YOUR payload format. It is a real,
 *  in-production decoder (the Certen intent format), not a toy, and it is registered by default only
 *  because it is self-validating — it claims a transaction only when the payload genuinely is one.
 *  If you do not use this format, it will never match, and you can drop it from `resolver.decoders`.
 * ─────────────────────────────────────────────────────────────────────────────────────────────────────
 *
 * THE FORMAT. A `writeData` body whose entry carries four hex-encoded JSON blobs:
 *
 *     entry.data = [ hex(intent), hex(crossChain), hex(governance), hex(replay) ]
 *
 * `crossChain.legs[]` is the part that matters to a policy decision: each leg is a value movement, with
 * `amountWei` as its authoritative amount.
 *
 * THREE THINGS THIS EXAMPLE DOES THAT YOURS SHOULD TOO:
 *
 *  1. IT VALIDATES BEFORE CLAIMING. It decodes only if a blob actually parses as JSON, and declines
 *     otherwise. A decoder that claims anything shaped vaguely like its format will eventually hand the
 *     policy engine a description of a transaction that is not the one about to be signed.
 *
 *  2. IT SURFACES EVERY LEG IN `values`, not just the first. `value` stays leg 0 for display, but the
 *     value ceiling and any all-or-nothing policy gate read `values`. Report only leg 0 and a
 *     transaction can hide an over-limit amount in leg 2 and pass a ceiling it should have failed.
 *
 *  3. IT PREFERS THE PAYLOAD'S OWN ID as `operationId`. The intent's `intent_id` is stable across
 *     re-submissions in a way the transaction hash is not, so it is the id the policy engine can
 *     correlate against its own records.
 */
import { DecodeContext, DecodedAction, SummaryDecoder, TxBody } from '../types.js';

/** The four decoded blobs of an intent payload. */
export interface CertenIntent {
  intent?: Record<string, any>;
  crossChain?: { legs?: Array<Record<string, any>>; [k: string]: any };
  governance?: Record<string, any>;
  replay?: Record<string, any>;
}

/**
 * Decode the four blobs, or `undefined` if this is not a decodable intent.
 *
 * Self-validating: the payload counts as an intent only if the intent or crossChain blob parses as JSON.
 * Hex that decodes to garbage, an empty entry, or a different format all return undefined.
 */
export function decodeCertenIntent(body: { [k: string]: unknown }): CertenIntent | undefined {
  const entry = body?.entry as { data?: unknown[] } | undefined;
  const data = entry?.data;
  if (!Array.isArray(data) || data.length === 0) return undefined;

  const parseBlob = (hex: unknown): Record<string, any> | undefined => {
    if (hex == null) return undefined;
    try {
      const s = String(hex).startsWith('0x') ? String(hex).slice(2) : String(hex);
      return JSON.parse(Buffer.from(s, 'hex').toString('utf8'));
    } catch {
      return undefined;
    }
  };

  const [intent, crossChain, governance, replay] = [0, 1, 2, 3].map((i) => parseBlob(data[i]));
  if (!intent && !crossChain) return undefined;
  return { intent, crossChain, governance, replay };
}

export const certenIntentDecoder: SummaryDecoder = {
  name: 'certen-intent',

  decode(body: TxBody, _ctx: DecodeContext): DecodedAction | undefined {
    if (body.type !== 'writeData') return undefined;

    const intent = decodeCertenIntent(body);
    const legs = intent?.crossChain?.legs;
    const leg0 = legs?.[0];
    // No legs means no value movement to describe — decline and let a later decoder handle it.
    if (!leg0) return undefined;

    const symbol = leg0.asset?.symbol ?? '';
    const human = leg0.amountEth ?? leg0.amountWei ?? '?';
    const desc = intent?.intent?.description || intent?.intent?.intentType || 'Intent';

    // EVERY leg amount — this is what the value ceiling and the policy gate actually read.
    const values = legs!
      .map((l) => (l?.amountWei != null ? String(l.amountWei) : undefined))
      .filter((x): x is string => x != null);

    const legSuffix = legs!.length > 1 ? ` (+${legs!.length - 1} more leg${legs!.length > 2 ? 's' : ''})` : '';

    return {
      summary: {
        action: `${desc} — ${human} ${symbol} to ${leg0.to ?? '?'}${legSuffix}`.replace(/\s+/g, ' ').trim(),
        chain: leg0.chain,
        target: leg0.to,
        value: leg0.amountWei != null ? String(leg0.amountWei) : undefined,
        values,
        raw: { certenIntent: intent?.intent, legCount: legs!.length },
      },
      operationId: intent?.intent?.intent_id ?? ((body.operationId as string) || undefined),
    };
  },
};
