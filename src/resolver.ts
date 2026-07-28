/**
 * Resolve a PendingRef into a fully-populated ResolvedTx, decoding what the transaction actually does.
 *
 * The decoding itself lives in src/decode/ as an ordered registry of decoders — see decode/types.ts for
 * why, and docs/INTEGRATION.md §1 for how to add one for your own payload format.
 */
import { AccumulateClient } from './accumulate/client.js';
import { ActionSummary, PendingRef, ResolvedTx } from './types.js';
import { DecoderRegistry, buildRegistry } from './decode/registry.js';
import { TxBody } from './decode/types.js';

export type ResolveResult =
  | { kind: 'resolved'; tx: ResolvedTx }
  /** We could not read the transaction. NOT a statement about whether it still exists — retry. */
  | { kind: 'unavailable'; error: string }
  | { kind: 'gone'; reason: 'not_found' | 'executed' | 'expired' };

export class Resolver {
  private readonly decoders: DecoderRegistry;

  /** `decoders` defaults to the built-in chain, which is what tests and single-format deployments want. */
  constructor(private readonly acc: AccumulateClient, decoders?: DecoderRegistry) {
    this.decoders = decoders ?? defaultRegistry();
  }

  async resolve(ref: PendingRef): Promise<ResolveResult> {
    const pend = await this.acc.getPendingTx(ref.txHash, ref.signerUrl);
    if (pend.unavailable) return { kind: 'unavailable', error: 'the node could not be queried' };
    if (!pend.found) return { kind: 'gone', reason: 'not_found' };
    if (pend.executed) return { kind: 'gone', reason: 'executed' };
    if (pend.expired) return { kind: 'gone', reason: 'expired' };

    const info = await this.acc.getSignerInfo(ref.signerUrl);
    const body = (pend.body ?? { type: 'unknown' }) as TxBody;
    const { summary, operationId } = this.decoders.decode(body, { principal: pend.principal ?? '' });

    return {
      kind: 'resolved',
      tx: {
        txHash: ref.txHash,
        account: pend.principal ?? '',
        signerUrl: ref.signerUrl,
        signerVersion: info.version,
        bodyType: body.type,
        operationId,
        summary,
        rawTransaction: pend.rawTransaction,
        lastUsedOn: info.lastUsedOn,
      },
    };
  }
}

let _default: DecoderRegistry | undefined;
/** The built-in decoder chain, built once. */
function defaultRegistry(): DecoderRegistry {
  return (_default ??= buildRegistry(undefined));
}

/**
 * Decode a transaction body with the built-in decoder chain.
 *
 * A convenience over the default registry, for tests and for tools that want a summary without a client.
 * A configured daemon uses its own registry (built in index.ts) so that decoders loaded from
 * `resolver.decoder_modules` are included — this function only ever sees the built-ins.
 */
export function decodeSummary(
  body: { type: string; [k: string]: unknown },
  principal: string,
): { summary: ActionSummary; operationId?: string } {
  const { summary, operationId } = defaultRegistry().decode(body as TxBody, { principal });
  return { summary, operationId };
}

// Re-exported so existing importers of `src/resolver.js` keep working.
export { decodeCertenIntent, type CertenIntent } from './decode/decoders/certen-intent.js';
export type { SummaryDecoder, DecodedAction, DecodeContext, TxBody } from './decode/types.js';
