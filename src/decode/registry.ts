/**
 * The decoder registry: an ordered chain, first claim wins.
 *
 * Order is the whole design. A specific decoder must run before a general one, or the general one claims
 * the transaction first and the specific one never sees it. The built-in `write-data` decoder matches
 * every data write, so anything that understands a particular data-write payload has to precede it — and
 * `fallback` is always last, so every transaction ends up described.
 */
import { DecodeContext, DecodedAction, SummaryDecoder, TxBody } from './types.js';
import { sendTokensDecoder } from './decoders/send-tokens.js';
import { writeDataDecoder, fallbackDecoder } from './decoders/write-data.js';
import { certenIntentDecoder } from './decoders/certen-intent.js';

/** Decoders shipped in the box, by name. */
export const BUILTIN_DECODERS: Record<string, SummaryDecoder> = {
  [sendTokensDecoder.name]: sendTokensDecoder,
  [certenIntentDecoder.name]: certenIntentDecoder,
  [writeDataDecoder.name]: writeDataDecoder,
};

/**
 * Default chain when `resolver.decoders` is not configured.
 *
 * `certen-intent` sits ahead of `write-data` because it is the specific case; it declines anything that
 * is not genuinely an intent payload, so its presence costs nothing if you use a different format.
 */
export const DEFAULT_DECODER_ORDER = [sendTokensDecoder.name, certenIntentDecoder.name, writeDataDecoder.name];

/** Minimal logging surface, so the registry does not depend on the concrete logger. */
export interface DecoderLog {
  warn(obj: Record<string, unknown>, msg: string): void;
  debug?(obj: Record<string, unknown>, msg: string): void;
}

export class DecoderRegistry {
  private readonly decoders: SummaryDecoder[];

  /** `decoders` run in order; the terminal fallback is appended automatically and cannot be removed. */
  constructor(decoders: SummaryDecoder[] = [], private readonly log?: DecoderLog) {
    this.decoders = [...decoders, fallbackDecoder];
  }

  /** Names in resolution order, including the implicit terminal fallback. For logs and /healthz. */
  names(): string[] {
    return this.decoders.map((d) => d.name);
  }

  /**
   * Walk the chain and return the first claim.
   *
   * A decoder that throws is treated as a decline: one malformed payload must not stall every other
   * transaction in the queue. The throw is logged at warn — a decoder failing silently on every
   * transaction would otherwise look exactly like a decoder that simply never matches.
   */
  decode(body: TxBody, ctx: DecodeContext): DecodedAction & { decodedBy: string } {
    for (const d of this.decoders) {
      let out: DecodedAction | undefined;
      try {
        out = d.decode(body, ctx);
      } catch (err) {
        this.log?.warn(
          { decoder: d.name, bodyType: body?.type, err: err instanceof Error ? err.message : String(err) },
          'decoder threw; treating as a decline and trying the next one',
        );
        continue;
      }
      if (out) return { ...out, decodedBy: d.name };
    }
    // Unreachable: fallbackDecoder always claims. Kept so a future edit to the chain cannot return null.
    return { summary: { action: `${body?.type ?? 'unknown'} on ${ctx.principal}` }, decodedBy: 'fallback' };
  }
}

/**
 * Build a registry from configured names plus any decoders loaded from external modules.
 *
 * An unknown name is a hard error rather than a warning: it almost always means a typo in the config or a
 * module that failed to register, and silently running with one fewer decoder would mean transactions
 * quietly reaching the policy engine described as "unrecognized" — a change in what gets signed, arrived
 * at by accident.
 */
export function buildRegistry(
  names: string[] | undefined,
  extra: SummaryDecoder[] = [],
  log?: DecoderLog,
): DecoderRegistry {
  const available: Record<string, SummaryDecoder> = { ...BUILTIN_DECODERS };
  for (const d of extra) available[d.name] = d;

  // Unlisted external decoders still run — loading a module IS the request to use it — and they go first,
  // ahead of the built-ins, because a custom decoder is by definition the more specific case.
  const order = names ?? [...extra.map((d) => d.name), ...DEFAULT_DECODER_ORDER];

  const chain = order.map((n) => {
    const d = available[n];
    if (!d) {
      throw new Error(
        `resolver.decoders: unknown decoder "${n}". Available: ${Object.keys(available).join(', ')}. ` +
          'Built-in names are fixed; a decoder from resolver.decoder_modules is registered under the ' +
          '`name` its module exports.',
      );
    }
    return d;
  });

  return new DecoderRegistry(chain, log);
}

/**
 * Load decoder modules named in `resolver.decoder_modules`.
 *
 * Each module default-exports either a SummaryDecoder or an array of them. Paths are resolved against the
 * process working directory, so a config can point at a file outside this repository — the whole point is
 * that you do not fork `src/` to add your own format.
 *
 * A module that fails to load is fatal. The alternative is booting without the decoder that understands
 * your payloads, which does not fail loudly: it fails as every transaction being described generically
 * and decided on that description.
 */
export async function loadDecoderModules(paths: string[] | undefined): Promise<SummaryDecoder[]> {
  if (!paths?.length) return [];

  const { pathToFileURL } = await import('node:url');
  const { resolve } = await import('node:path');
  const out: SummaryDecoder[] = [];

  for (const p of paths) {
    // A bare specifier ('@acme/decoder') resolves as a package; anything else as a path from cwd.
    const spec = /^[./]|^[A-Za-z]:[\\/]/.test(p) ? pathToFileURL(resolve(p)).href : p;
    let mod: { default?: unknown };
    try {
      mod = (await import(spec)) as { default?: unknown };
    } catch (err) {
      throw new Error(
        `resolver.decoder_modules: failed to load "${p}" — ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const exported = mod.default;
    const list = Array.isArray(exported) ? exported : [exported];
    for (const d of list) {
      if (!isDecoder(d)) {
        throw new Error(
          `resolver.decoder_modules: "${p}" must default-export a decoder — an object with a string ` +
            '`name` and a `decode(body, ctx)` method — or an array of them.',
        );
      }
      out.push(d);
    }
  }
  return out;
}

function isDecoder(d: unknown): d is SummaryDecoder {
  const c = d as SummaryDecoder | undefined;
  return !!c && typeof c.name === 'string' && c.name.length > 0 && typeof c.decode === 'function';
}
