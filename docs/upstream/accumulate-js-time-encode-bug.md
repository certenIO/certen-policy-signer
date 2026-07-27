# accumulate.js: `Time.encode` corrupts `expire` / `holdUntil`, making expiring transactions unsignable

**Package:** `accumulate.js@0.12.0`
**File:** `lib/encoding/encodable.js`
**Severity:** any transaction that sets `header.expire` or `header.holdUntil` is rejected by the network as
`"transaction is not signed"`. The signature is valid; the transaction hash is not.
**Reported by:** Certen (policy-gated signing wallet). Reproduced on the Kermit testnet, 2026-07.

---

## Summary

`Time.encode` writes a **`uvarint` of fractional seconds**. Accumulate core writes a **signed varint of whole
Unix seconds**. The two disagree, so the transaction the SDK hashes is not the transaction the network hashes.
Every signature over such a transaction is therefore computed over the wrong preimage, and the network
rejects it as unsigned — pointing the developer at their signing code, which is not where the bug is.

**SDK (`lib/encoding/encodable.js`):**
```js
return uintMarshalBinary(value.getTime() / 1000);
```
Two defects in one line:
1. `uintMarshalBinary` — an **unsigned** varint, where core uses a **signed** one (`EncodeInt`).
2. `value.getTime() / 1000` — a **float** (`1751630000.123`), where core uses whole seconds.

**Core (`protocol`, Go):**
```go
// time.Time fields are marshalled as a signed varint of whole Unix seconds
writer.WriteInt(n, v.UTC().Unix())
```

A fractional value also throws outright inside the varint writer for some inputs, so depending on the
timestamp you either get an exception or — worse — a silently wrong hash.

## Reproduction

```js
import { Transaction } from 'accumulate.js/core';

const tx = new Transaction({
  header: {
    principal: 'acc://alice.acme/data',
    expire: { atTime: new Date('2026-07-13T12:00:00Z') },
  },
  body: { type: 'writeData', entry: { type: 'doubleHash', data: ['00'] } },
});

// Hash it, sign it, submit it -> the network answers: "transaction is not signed".
// The same transaction WITHOUT `expire` submits fine.
console.log(Buffer.from(tx.hash()).toString('hex'));
```

Observed on the Kermit testnet, both directions:

- **Unpatched:** submission fails with `"transaction is not signed"`, every time.
- **Patched (diff below):** the identical transaction submits (`ok: true`) and the network stores the
  expected `header.expire.atTime` — confirmed by reading the transaction back on chain.

(The marshalling helpers are private to the package, so the difference is easiest to observe at the
transaction level, as above, rather than by calling the encoders directly.)

## Fix

```diff
- return uintMarshalBinary(value.getTime() / 1000);
+ return intMarshalBinary(Math.floor(value.getTime() / 1000));
```

Signed varint (matching `EncodeInt`), whole seconds (matching `v.UTC().Unix()`).

Our stop-gap patch, applied at install time until this is released upstream:
`scripts/fix-accumulate-encoding.mjs` (idempotent; warns loudly if the upstream source shape changes).

## Why this is worth fixing promptly

The failure mode is maximally misleading. The developer sees `"transaction is not signed"`, concludes their
Ed25519 signing is wrong, and goes hunting through preimage construction — the one part that was correct. It
cost us a day. Anyone using transaction expiry (which is the natural way to bound a pending multi-signature
transaction) will hit it, and most will not think to suspect the SDK's time encoding.

Suggested regression test for the SDK: encode a `Time` and assert the bytes equal core's encoding for a known
instant — e.g. `2026-07-13T12:00:00Z` must encode as the **signed** varint of **`1783944000`** (whole Unix
seconds), and must not depend on the sub-second part of the `Date`.
