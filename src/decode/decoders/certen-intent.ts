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

/**
 * ERC-20 calldata a leg may carry in `executionPayload.callData`.
 *
 * WHY THIS EXISTS. A leg's `amountWei` is the NATIVE value forwarded with the call. A contract call
 * that moves tokens — `transfer(to, 1_000_000 USDC)` on the token contract — forwards no native value,
 * so its `amountWei` is "0" and, before this decoder read calldata, the policy engine saw a zero-value
 * leg and any ceiling passed it. Native value was regulated; token value was not. Verified in code on
 * 2026-09-03 and fixed here: the three ERC-20 selectors that move or authorise value are decoded by
 * hand (selector + 32-byte words — no ABI library needed) and their amounts join `values`.
 *
 * A leg whose calldata is present but NOT one of these is an arbitrary contract call. Its native value is
 * still in `values`; whatever the call does internally is not something this signer can price. That is
 * reported as `opaqueCallLegs` in `raw` and in the action text rather than as `unpricedLegs`, because
 * counting it as unpriced would make the local guard refuse every proof-gated escrow call (`ship`,
 * `confirm`) that carries no value and moves no tokens — and those are exactly what this signer exists
 * to approve. An engine that wants to refuse opaque calls can read the count and do so.
 */
const ERC20_SELECTORS: Record<string, { name: string; params: string[]; amountIndex: number }> = {
  a9059cbb: { name: 'transfer', params: ['to', 'amount'], amountIndex: 1 },
  '23b872dd': { name: 'transferFrom', params: ['from', 'to', 'amount'], amountIndex: 2 },
  '095ea7b3': { name: 'approve', params: ['spender', 'amount'], amountIndex: 1 },
};

export interface DecodedErc20Call {
  fn: string;
  args: Record<string, string>;
  /** The token amount in the token's base units, as a decimal string. */
  amount: string;
  text: string;
}

/** Decode `transfer`, `transferFrom` or `approve` calldata, or `undefined` for anything else. */
export function decodeErc20Calldata(callData: unknown): DecodedErc20Call | undefined {
  if (typeof callData !== 'string') return undefined;
  const hex = (callData.startsWith('0x') ? callData.slice(2) : callData).toLowerCase();
  if (hex.length < 8 || !/^[0-9a-f]*$/.test(hex)) return undefined;
  const spec = ERC20_SELECTORS[hex.slice(0, 8)];
  if (!spec) return undefined;
  const body = hex.slice(8);
  // Exactly one 32-byte word per parameter. Trailing bytes would mean calldata this decoder does not
  // understand, and a wrong guess here is worse than declining.
  if (body.length !== spec.params.length * 64) return undefined;
  const args: Record<string, string> = {};
  spec.params.forEach((name, i) => {
    const word = body.slice(i * 64, i * 64 + 64);
    args[name] = name === 'amount' ? BigInt('0x' + word).toString() : '0x' + word.slice(24);
  });
  const amount = args[spec.params[spec.amountIndex]];
  const text = `${spec.name}(${spec.params.map((p) => `${p} = ${args[p]}`).join(', ')})`;
  return { fn: spec.name, args, amount, text };
}

/** Is there calldata on this leg at all? "0x" and "" are a native transfer. */
function hasCalldata(leg: Record<string, any>): boolean {
  const cd = leg?.executionPayload?.callData;
  return typeof cd === 'string' && cd.replace(/^0x/, '').length > 0;
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

    // EVERY amount — this is what the value ceiling and the policy gate actually read. Per leg that is
    // the native value (`amountWei`) AND, when the calldata is an ERC-20 transfer/transferFrom/approve,
    // the token amount. A token leg the bridge built from `tokenAddress` carries the same number in both
    // places, so equal amounts on one leg are listed once; a contract-call leg that moves tokens has
    // native "0" and a token amount, and the zero is dropped so a ceiling gates the amount that matters.
    const values: string[] = [];
    let pricedLegs = 0;
    let opaqueCallLegs = 0;
    const erc20ByLeg: (DecodedErc20Call | undefined)[] = [];
    for (const l of legs!) {
      const native = l?.amountWei != null ? String(l.amountWei) : undefined;
      const erc20 = decodeErc20Calldata(l?.executionPayload?.callData);
      erc20ByLeg.push(erc20);
      if (!erc20 && hasCalldata(l)) opaqueCallLegs++;
      const legValues: string[] = [];
      if (erc20) legValues.push(erc20.amount);
      if (native != null && !(erc20 && (native === '0' || native === erc20.amount))) legValues.push(native);
      if (legValues.length === 0) continue;
      pricedLegs++;
      values.push(...legValues);
    }

    // Legs we could NOT price at all: no native amount and no decodable token amount. `amountWei` is this
    // format's authoritative native amount, so a leg without one is malformed — it used to vanish here,
    // silently shortening `values`, and a ceiling then saw only the legs that happened to parse. Report
    // the count so the gate can tell a complete list from a partial one; the local guard refuses to sign
    // when it is > 0.
    const unpricedLegs = legs!.length - pricedLegs;
    const erc20_0 = erc20ByLeg[0];
    const tokenSuffix = erc20_0
      ? ` · ${erc20_0.fn} ${erc20_0.amount} token units on ${leg0.executionPayload?.target ?? leg0.asset?.contract_address ?? leg0.to ?? '?'}`
      : '';
    const opaqueSuffix = opaqueCallLegs > 0 ? ` · ${opaqueCallLegs} contract call${opaqueCallLegs > 1 ? 's' : ''} with undecoded calldata` : '';

    const legSuffix = legs!.length > 1 ? ` (+${legs!.length - 1} more leg${legs!.length > 2 ? 's' : ''})` : '';

    // WHO the intent is about, when it named someone. Promoted out of the blob so an engine reads one
    // documented field rather than digging through `raw`; the blob itself stays exactly as it was below.
    // A claim is taken only when it is an object carrying a non-empty `adi` — a bare string, or an object
    // with no identity in it, is a malformed claim and therefore no claim. The signer never invents one.
    const claimed = intent?.intent?.subject;
    const subject =
      claimed && typeof claimed === 'object' && typeof claimed.adi === 'string' && claimed.adi
        ? {
            adi: claimed.adi,
            ...(typeof claimed.keyBook === 'string' && claimed.keyBook ? { keyBook: claimed.keyBook } : {}),
            ...(typeof claimed.id === 'string' && claimed.id ? { id: claimed.id } : {}),
            ...(typeof claimed.assertedBy === 'string' && claimed.assertedBy ? { assertedBy: claimed.assertedBy } : {}),
          }
        : undefined;

    return {
      summary: {
        action: `${desc} — ${human} ${symbol} to ${leg0.to ?? '?'}${legSuffix}${tokenSuffix}${opaqueSuffix}`.replace(/\s+/g, ' ').trim(),
        chain: leg0.chain,
        target: leg0.to,
        value: leg0.amountWei != null ? String(leg0.amountWei) : undefined,
        values,
        ...(unpricedLegs > 0 ? { unpricedLegs } : {}),
        ...(erc20_0 ? { calldataDecoded: erc20_0.text } : {}),
        // Spread, not `subject`: absent must be an ABSENT KEY on the wire, not `subject: undefined`.
        ...(subject ? { subject } : {}),
        raw: {
          certenIntent: intent?.intent,
          legCount: legs!.length,
          ...(opaqueCallLegs > 0 ? { opaqueCallLegs } : {}),
          ...(erc20ByLeg.some(Boolean) ? { erc20: erc20ByLeg.map((e) => e ?? null) } : {}),
        },
      },
      operationId: intent?.intent?.intent_id ?? ((body.operationId as string) || undefined),
    };
  },
};
