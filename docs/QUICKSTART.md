# Quickstart

See the whole thing work, live, in about eight minutes.

```bash
npm install
npx tsx scripts/quickstart.ts
```

That is the entire setup. The script provisions its own throwaway identities on a public test network,
funds them from the faucet, runs the real signer as a child process against the real reference policy
engine, and walks one transaction through each of the four decision outcomes.

No real value is involved. Nothing pre-exists. Nothing needs cleaning up.

> Running against your own node, devnet, or private network:
> `ACC=https://your-node.internal/v3 npx tsx scripts/quickstart.ts`

---

## What you will see

Each scenario submits a transaction that **names the signer's key book as a required authority**.
Accumulate then holds it pending — it cannot execute until the signer acts. What the signer does depends
entirely on what the policy engine says.

### 1. Approve

The engine returns `{"decision":"approve"}`. The signer signs, submits the vote, and the transaction
**executes**.

### 2. Deny

The engine returns `{"decision":"deny"}`. The signer casts a **reject** vote and the transaction is
**rejected** — decided, not stalled.

### 3. Outage — the one to watch

The policy engine is down. The signer tries, fails, and **signs nothing**. The transaction is still
pending when the scenario ends.

This is the property everything else rests on. Taking the policy engine away — including an attacker doing
it deliberately — stalls transactions. It never releases a signature. There is no timeout after which the
signer decides to proceed anyway.

### 4. Pending

The engine answers `{"decision":"pending"}` for several polls, then approves. The signer withholds the
whole time, spending nothing, and signs only once a real approval arrives.

This is the shape of a human approval or a step-up auth challenge: the decision takes minutes, the
transaction waits on chain, and nothing is committed until someone actually says yes.

---

## Verifying it independently

Every result is a real transaction on a public ledger. The script prints each transaction hash, so you can
look them up yourself rather than taking its word:

```
tx 9c2b7f…    RESULT: DELIVERED   (expected DELIVERED)  ✅
```

The signatures are genuine Ed25519 signatures over the genuine Accumulate preimage. The **network**
decides whether to accept them — the script cannot fake a success, because a wrong signature is rejected
by consensus and the transaction simply would not execute.

---

## Then what

The reference engine you just watched is
[`examples/policy-engine.mjs`](../examples/policy-engine.mjs). It has exactly one function to replace:

```js
function checkPolicy(request) {
  //  ← call your engine here. Return { ok, reason, evidence }.
}
```

Point `policy.url` at your own service and you are integrated. Everything else — discovery, decoding,
signing, submission, receipts, idempotency — is already handled.

To run the signer yourself rather than under the quickstart script, give it a config file — or ask it
what it takes:

```bash
cp config.example.yaml config.yaml
npx tsx src/index.ts config.yaml     # or: certen-external-policy-signer config.yaml
npx tsx src/index.ts --help          # usage, environment, and the HTTP surface
```

The config path also comes from `$CONFIG_PATH`, and defaults to `./config.yaml`.

Read next:

- **[INTEGRATION.md](INTEGRATION.md)** — the full contract, the signed channel, answering asynchronously,
  and teaching the signer your own payload format.
- **[scripts/verify/](../scripts/verify/README.md)** — the live verification suite, if you want to check
  the safety claims yourself rather than trust them.
- **[DEPLOY.md](DEPLOY.md)** and **[OPERATIONS.md](OPERATIONS.md)** — when you are ready to run it for
  real.

---

## If something goes wrong

**A scenario times out or a result is "pending" when it should not be.** The public test network is shared
and occasionally slow. Re-run it; this usually settles.

**Faucet funding fails.** The faucet is rate-limited and sometimes busy. Wait a minute and re-run.

**A result is consistently wrong** — an approve that does not execute, a deny that does — that is a real
finding, not flakiness. Please open an issue with the output.
