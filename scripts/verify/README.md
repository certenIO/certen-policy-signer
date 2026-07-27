# Live verification suite

These scripts run the **real signer** against a **real Accumulate network** and assert properties that
cannot honestly be proven offline: that the network accepts the signatures, that a rotation actually moved
your authority, that an outage does not release a signature.

They are not part of `npm test`. The offline suite covers logic; these cover reality.

## Running them

Each script **provisions its own throwaway identities** from a public test network's faucet. Nothing
pre-exists, nothing is shared between scripts, nothing needs cleaning up afterwards, and no real value is
involved.

```bash
npx tsx scripts/verify/resilience.ts

# against your own node, devnet, or private network
ACC=https://your-node.internal/v3 npx tsx scripts/verify/resilience.ts
```

Each takes roughly 3–8 minutes, most of it waiting for the network. `resilience.ts` and `faults.ts` use
independent ports and can run at the same time.

| Script | What it proves | Needs |
|---|---|---|
| [`resilience.ts`](resilience.ts) | The safety envelope: refuses to boot on the wrong key, survives a policy-engine outage, pause means pause, the HMAC channel works, an unreadable payload is not a blank cheque | — |
| [`faults.ts`](faults.ts) | Graceful degradation: a page with no credits fails cleanly rather than crashing; an unsigned transaction expires on chain | — |
| [`concurrency.ts`](concurrency.ts) | Three pending transactions at once, each voted on **exactly once** across many poll cycles | — |
| [`key-rotation.ts`](key-rotation.ts) | All three rotation modes, each confirmed on chain, plus continuity on the new key and that the old key can no longer act | — |
| [`multi-page.ts`](multi-page.ts) | One process watching several key pages signs each transaction with the **right** key | — |
| [`vault-custody.ts`](vault-custody.ts) | The production posture: the key is generated in Vault, never leaves it, and Vault signs the votes | a reachable Vault |
| [`deployed-container.ts`](deployed-container.ts) | **The acceptance test.** The shipped container image discovers, decides, and votes on its own | Docker |

New to this? Start with [`scripts/quickstart.ts`](../quickstart.ts) instead — it walks all four decision
outcomes in one run and explains each as it goes.

## Why these are worth running yourself

Every claim in the README is checkable here, on a network you choose, with keys you generated. Two are
worth calling out because they are the ones a security review actually turns on:

- **`resilience.ts` kills the policy engine mid-run.** The transaction stays pending. Nothing is signed.
  Watching a failure produce *no signature* is more convincing than any amount of documentation asserting
  it is fail-closed.
- **`key-rotation.ts` reads the key page back** after every rotation, rather than trusting that a
  submitted transaction succeeded. Accumulate executes asynchronously; that gap is where rotations go
  wrong, and it is deliberately not papered over.

## Verifying against your own payload format

By default these write transactions in the reference intent format that the built-in `certen-intent`
decoder understands. To exercise **your** format instead, pass your own bytes to `writeIntent({ data: … })`
and point the signer config at your decoder:

```yaml
resolver:
  decoder_modules: ["./decoders/my-format.mjs"]
```

That substitution is the whole extension seam, tested live. See
[`examples/custom-decoder.mjs`](../../examples/custom-decoder.mjs) and
[docs/INTEGRATION.md](../../docs/INTEGRATION.md) §2.

## A note on flakiness

A public test network is shared and occasionally slow. A script that fails on a timeout is usually the
network, not the signer — re-run it. A script that fails on an **assertion** (wrong final state, a
transaction voted twice, a rotation not confirmed) is a real finding; please open an issue with the output.
