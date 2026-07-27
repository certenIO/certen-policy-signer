/**
 * The intent-decoder seam.
 *
 * A pending Accumulate transaction is bytes. Before the policy engine can decide anything, someone has to
 * say what those bytes MEAN — "Transfer 4000 wei to 0xabc on ethereum" — because that sentence, and the
 * amounts beside it, are the entire basis of the decision.
 *
 * That translation is integration-specific. Your organisation's transactions carry your payload format,
 * and this signer cannot know it. So decoding is a registry of small, independent decoders rather than a
 * hardcoded switch: the built-ins understand plain Accumulate bodies, and you add one module that
 * understands yours. See docs/INTEGRATION.md §1 and src/decode/decoders/certen-intent.ts for a complete
 * worked example.
 */
import { ActionSummary } from '../types.js';

/** A raw Accumulate transaction body. `type` is the Accumulate body type (`sendTokens`, `writeData`, …). */
export type TxBody = { type: string; [k: string]: unknown };

/** What a decoder produces: the sentence + numbers the policy engine gates on. */
export interface DecodedAction {
  summary: ActionSummary;
  /**
   * Your own stable id for the business operation, if the payload carries one. Distinct from txHash:
   * it survives a re-submission and is what your policy engine most likely keys its own records on.
   */
  operationId?: string;
}

/** Everything a decoder knows besides the body itself. */
export interface DecodeContext {
  /** The account the transaction acts on. */
  principal: string;
}

export interface SummaryDecoder {
  /**
   * Stable identifier. This is what you list in `resolver.decoders` to enable or order this decoder,
   * and what appears in the log line recording which decoder claimed a transaction.
   */
  readonly name: string;

  /**
   * Decode the body, or return `undefined` to decline it and pass the transaction to the next decoder.
   *
   * DECLINE RATHER THAN GUESS. Returning a wrong summary is worse than returning none: the policy engine
   * would be deciding on a description that does not match what will actually execute, and an `approve`
   * is a real signature over the real bytes. Validate that the payload is genuinely yours — check a
   * discriminator field, confirm the blobs parse — and decline whenever you are unsure. A transaction no
   * decoder claims still reaches the policy engine, described generically, and can still be denied.
   *
   * Throwing is equivalent to declining: the registry catches it, logs it, and moves on. That keeps one
   * malformed payload from stalling every transaction, but it means a decoder that throws is invisible
   * unless you read the logs — prefer an explicit `undefined`.
   */
  decode(body: TxBody, ctx: DecodeContext): DecodedAction | undefined;
}
