/**
 * Reference intent decoder — teaching the signer to read YOUR payload format.
 *
 * WHY THIS EXISTS. A pending Accumulate transaction is bytes. Before your policy engine can decide
 * anything, something has to turn those bytes into a sentence and a set of amounts — because that is
 * literally what the decision is made on. Your payload format is yours, so this translation is the one
 * piece the signer cannot ship for you.
 *
 * You do NOT fork the repository to add it. Point `resolver.decoder_modules` at this file:
 *
 *     resolver:
 *       decoder_modules: ["./examples/custom-decoder.mjs"]
 *
 * and it is loaded at boot and runs ahead of the built-in decoders. Confirm it at startup — the signer
 * logs its whole chain:
 *
 *     "intent decoder chain (first claim wins)"  decoders: ["acme-purchase-order", "send-tokens", …]
 *
 * ── The contract ──────────────────────────────────────────────────────────────────────────────────────
 *
 *   Default-export an object (or an array of them):
 *
 *     {
 *       name: "acme-purchase-order",              // stable id — appears in config and logs
 *       decode(body, ctx) { … }                   // → a summary, or undefined to decline
 *     }
 *
 *   `body` is the raw Accumulate transaction body; `body.type` is the Accumulate body type
 *   ("writeData", "sendTokens", …). `ctx.principal` is the account the transaction acts on.
 *
 *   Return:
 *     {
 *       summary: {
 *         action:   "Purchase order PO-1043 — 25000 USDC to Northwind",  // the sentence your engine sees
 *         chain:    "ethereum",          // optional
 *         target:   "0xabc…",            // optional
 *         value:    "25000",             // representative amount, for display
 *         values:   ["25000", "500"],    // EVERY amount — this is what gets gated. See below.
 *         raw:      { … }                // optional, anything else you want carried along
 *       },
 *       operationId: "PO-1043"           // optional: your own id for the operation
 *     }
 *
 *   …or `undefined` to decline, passing the transaction to the next decoder in the chain.
 *
 * ── Three rules that matter ───────────────────────────────────────────────────────────────────────────
 *
 *  1. DECLINE RATHER THAN GUESS. Check a discriminator, confirm the payload parses, and return undefined
 *     whenever you are unsure. A wrong summary is worse than none: your engine would be approving a
 *     description that is not the transaction about to be signed, and the approval produces a real
 *     signature over the real bytes. A declined transaction still reaches your engine, described
 *     generically, and can still be denied.
 *
 *  2. PUT EVERY AMOUNT IN `values`. A ceiling or an all-or-nothing rule reads `values`; `value` is only
 *     the first one, for display. Report one amount out of three and the other two are ungated.
 *
 *  3. PREFER YOUR OWN ID as `operationId`. It survives a re-submission in a way the transaction hash
 *     does not, so it is what your engine can correlate against its own records.
 *
 * A decoder that throws is treated as a decline and logged — one malformed payload cannot stall the
 * queue — but prefer returning undefined explicitly, so a permanently broken decoder is not just a
 * warning nobody reads.
 */

export default {
  name: 'acme-purchase-order',

  decode(body, ctx) {
    // 1. Is this even ours? Decline anything we cannot positively identify.
    if (body.type !== 'writeData') return undefined;

    const payload = readJsonEntry(body);
    if (payload?.kind !== 'ACME_PURCHASE_ORDER') return undefined;

    // 2. Is it well-formed enough to describe honestly? If not, decline — do not half-describe it.
    const lines = Array.isArray(payload.lines) ? payload.lines : [];
    if (lines.length === 0) return undefined;

    // 3. Every amount, so nothing escapes the gate.
    const values = lines
      .map((l) => (l?.amount != null ? String(l.amount) : undefined))
      .filter((v) => v != null);

    const first = lines[0];
    const more = lines.length > 1 ? ` (+${lines.length - 1} more line${lines.length > 2 ? 's' : ''})` : '';

    return {
      summary: {
        action: `Purchase order ${payload.poNumber ?? '?'} — ${first.amount} ${payload.currency ?? ''} to ${first.vendor ?? '?'}${more}`.replace(/\s+/g, ' ').trim(),
        chain: payload.chain,
        target: first.vendor,
        value: first.amount != null ? String(first.amount) : undefined,
        values,
        raw: { poNumber: payload.poNumber, lineCount: lines.length },
      },
      operationId: payload.poNumber,
    };
  },
};

/**
 * Pull a JSON payload out of a writeData entry.
 *
 * Accumulate data entries carry opaque bytes; how yours are encoded is your convention. This helper
 * handles the common one — a single hex-encoded JSON blob — and returns undefined on anything it cannot
 * parse, which is what makes the decoder above safe to declare "not mine".
 */
function readJsonEntry(body) {
  const data = body?.entry?.data;
  if (!Array.isArray(data) || data.length === 0) return undefined;
  try {
    const hex = String(data[0]).startsWith('0x') ? String(data[0]).slice(2) : String(data[0]);
    return JSON.parse(Buffer.from(hex, 'hex').toString('utf8'));
  } catch {
    return undefined;
  }
}
