/** Built-in decoder: native Accumulate token transfers (`sendTokens`). */
import { DecodeContext, DecodedAction, SummaryDecoder, TxBody } from '../types.js';

export const sendTokensDecoder: SummaryDecoder = {
  name: 'send-tokens',

  decode(body: TxBody): DecodedAction | undefined {
    if (body.type !== 'sendTokens') return undefined;

    const to = body.to as Array<{ url?: string; amount?: string | number }> | undefined;
    if (!Array.isArray(to) || to.length === 0) return undefined;

    const first = to[0];
    if (!first?.url) return undefined;

    // Every recipient amount is gate-relevant: a value ceiling must see the whole transfer, not just the
    // first output, or a transaction could be split across outputs to slip under the limit.
    const values = to
      .map((o) => (o?.amount != null ? String(o.amount) : undefined))
      .filter((v): v is string => v != null);

    const more = to.length > 1 ? ` (+${to.length - 1} more output${to.length > 2 ? 's' : ''})` : '';

    return {
      summary: {
        action: `Transfer ${first.amount ?? '?'} to ${first.url}${more}`,
        chain: 'accumulate',
        target: first.url,
        value: first.amount != null ? String(first.amount) : undefined,
        values,
        raw: { to },
      },
      operationId: (body.operationId as string) || undefined,
    };
  },
};
