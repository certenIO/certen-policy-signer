/**
 * Built-in decoder: generic `writeData`.
 *
 * A data write carries an opaque payload — its meaning is defined by whoever wrote it, not by Accumulate.
 * This decoder therefore extracts only what a body states about ITSELF in plain fields, and never guesses
 * at an encoded payload. Register a decoder ahead of this one to understand your own format; see
 * decoders/certen-intent.ts.
 *
 * It runs LAST among the writeData decoders and always claims the body, so a data write is never described
 * to the policy engine as nothing at all.
 */
import { DecodeContext, DecodedAction, SummaryDecoder, TxBody } from '../types.js';

export const writeDataDecoder: SummaryDecoder = {
  name: 'write-data',

  decode(body: TxBody, ctx: DecodeContext): DecodedAction | undefined {
    if (body.type !== 'writeData') return undefined;

    // A body may describe itself in plain, unencoded fields. `crossChain` is a conventional envelope for
    // "this data write authorises an action on another chain"; both are read only if literally present.
    const cross = (body.crossChain as Record<string, unknown> | undefined) || undefined;
    const stated = (body.actionSummary as string) || (cross?.action as string) || undefined;
    const value = cross?.value != null ? String(cross.value) : undefined;

    // No decoder understood the payload. Say so plainly rather than inventing a description: the policy
    // engine is about to decide on this sentence, and "we could not read this" is the honest input — and
    // for most policies, grounds to deny.
    return {
      summary: {
        action: stated || `Unrecognized data write on ${ctx.principal || 'unknown account'}`,
        chain: (cross?.chain as string) || undefined,
        target: (cross?.target as string) || undefined,
        value,
        values: value !== undefined ? [value] : undefined,
        calldataDecoded: (cross?.calldataDecoded as string) || undefined,
        raw: cross ? { crossChain: cross } : undefined,
      },
      operationId: (body.operationId as string) || undefined,
    };
  },
};

/**
 * Terminal fallback. Claims anything still unclaimed so the policy engine always receives a description,
 * even for a body type this signer has never seen. The engine can still deny it — and for an unrecognised
 * body type, denying is usually the right policy.
 */
export const fallbackDecoder: SummaryDecoder = {
  name: 'fallback',

  decode(body: TxBody, ctx: DecodeContext): DecodedAction {
    return {
      summary: { action: `${body.type} on ${ctx.principal}` },
      operationId: (body.operationId as string) || undefined,
    };
  },
};
