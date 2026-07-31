# Integration guide

How to connect this signer to your own systems. There are three seams; most integrations use only the
first. Nothing here requires forking the repository.

```
   Accumulate                    THIS SIGNER                        YOUR SYSTEMS
   ──────────                    ───────────                        ────────────
   pending tx  ──discover──▶  ┌──────────────┐
                              │   decoder    │ ◀── SEAM 2: your payload format
                              │      ↓       │
                              │  "Transfer 25000 USDC to Northwind"
                              │      ↓       │
                              │ policy client│ ──POST /decision──▶  SEAM 1: your policy engine
                              │      ↓       │ ◀──approve/deny────
                              │   signer     │ ◀── your key (in-process or in Vault)
                              │      ↓       │
                              │ vote backend │ ◀── SEAM 3: how the vote reaches the chain
                              └──────┬───────┘
   vote + receipt  ◀────────────────┘
```

The invariant that holds across all of them: **nothing is ever signed without an explicit `approve`.**
Every failure mode — a timeout, a crash, malformed JSON, a bad MAC, an unreachable engine, an unreadable
payload — withholds the signature. This is not a policy you configure; it is how the code is written.

---

## Seam 1 — your policy engine (the decision)

**This is the integration.** Everything else is optional.

The signer sends one HTTP POST per pending transaction and reads one field off the reply. It has no
opinion about what computes the answer: a rules engine, a biometric check, a review queue, a human with
a button, a call to the approvals service you already run.

**There are two supported ways in, and neither is the fallback.** Pick by whether the endpoint exists yet.

| | **A — write an endpoint** | **B — use one you already have** |
|---|---|---|
| You have | no approvals endpoint yet, or you want one scoped to this | a rules engine / approvals API already deployed |
| You write | a handler speaking the contract below | an adapter module mapping to your API's shape |
| Config | `policy.url` | `policy.url` + `policy.adapter_module` |
| Start from | [`examples/policy-engine.mjs`](../examples/policy-engine.mjs) | [`examples/policy-adapter.mjs`](../examples/policy-adapter.mjs) |
| Effort | one function | one file, two functions, both optional |

Both end in the same place: an `approve` produces a signature and nothing else does. The fail-closed
guarantees are identical — they are enforced by the signer either way, not by the code you write.

**Path A** is the rest of this section: the request shape, the reply, the four outcomes. Read it even if
you are taking path B, because an adapter maps *onto* this contract and the semantics of `pending`, `deny`,
and `values` are the same on both sides.

**Path B** is [Pointing the signer at an API you already have](#pointing-the-signer-at-an-api-you-already-have),
below.

**Start here for A:** [`examples/policy-engine.mjs`](../examples/policy-engine.mjs) is a complete, runnable
implementation with a single function to replace. Run it against the signer before writing any code of
your own.

### Request

```jsonc
POST <policy.url>    content-type: application/json
{
  "requestId":     "a7f3…",           // unique PER REQUEST — regenerated on every poll
  "txHash":        "9c2b…",           // the pending transaction — STABLE across polls
  "operationId":   "PO-1043",         // your own id, if your payload carried one
  "account":       "acc://acme.acme/orders",
  "chain":         "ethereum",
  "actionSummary": "Purchase order PO-1043 — 25000 USDC to Northwind",
  "target":        "0xabc…",
  "value":         "25000",           // first amount only — for display
  "values":        ["25000", "500"],  // EVERY amount — gate on these
  "unpricedLegs":  0,                 // absent or 0 => `values` is complete. > 0 => it is NOT
  "expiresAt":     "2026-07-26T12:00:00Z"
}
```

**Gate on `values`, not `value`.** A transaction can move value in several legs. `value` is the first,
carried for display; `values` is all of them. Check one and the rest are ungated — an amount over your
limit can ride along beside one under it.

**Treat `unpricedLegs > 0` as a deny.** It means the decoder found legs that move value but could not read
their amounts, so `values` is a *partial* list. Every entry in it can sit under your limit while the leg
missing from it does not — "all the amounts I can see are fine" is not the same statement as "all the
amounts are fine". The signer's own value ceiling refuses to sign in this case; your engine should too,
unless you have another way to bound what you cannot see. A well-formed payload never sets it.

### Response

```jsonc
200 OK    content-type: application/json
{
  "decision": "approve" | "deny" | "pending",   // the only required field
  "reason":   "matched rule 12",                 // optional → stored in the receipt
  "evidence":  { "score": 0.98, "reviewer": "…" } // optional, any JSON → stored verbatim
}
```

`reason` and `evidence` are persisted in the signer's durable receipt alongside the transaction hash and
the vote. They are what an auditor reads later to connect *"we decided this"* to *"this happened on
chain."* Put your match scores, rule ids, reviewer identity, and ticket numbers in `evidence`.

### The four outcomes

| Reply | What the signer does |
|---|---|
| `approve` | Casts an **accept** vote with your key. The transaction executes. |
| `deny` | Casts a **reject** vote (or withholds — your `behavior.submit_reject_vote`). The transaction dies. |
| `pending` | **Signs nothing.** Leaves the transaction pending on chain and asks again next poll. |
| anything else | **Signs nothing**, retries. Covers non-2xx, non-JSON, unknown `decision`, timeout, unreachable host, bad MAC. |

Two consequences worth stating explicitly:

- **An outage cannot approve anything.** Taking this endpoint down — including an attacker doing so —
  stalls transactions. It never releases a signature.
- **If you want a failed check to *kill* a transaction, return `deny` explicitly.** Throwing or timing
  out withholds instead, and the transaction survives until it expires on chain. Failing loudly and
  failing closed are different behaviors; choose deliberately.

### Answering asynchronously with `pending`

If your decision needs a human, a step-up challenge, or a review queue, return `pending`. The signer
withholds and re-asks on its poll interval, indefinitely — this costs nothing and is not recorded as an
error.

> **Key your state on `txHash`, never on `requestId`.** `requestId` is regenerated on every poll;
> `txHash` is stable for the life of the transaction. Keyed on `requestId`, you would open a brand new
> challenge on every poll — texting your user a fresh prompt every 20 seconds.

The alternative designs are worse, and it is worth knowing why. Returning `deny` to mean "not yet" casts
a real reject vote and kills a transaction you might have approved a minute later. Holding the HTTP
response open until a human answers ties up the request until it times out — and a timeout is
indistinguishable from an outage.

### Pointing the signer at an API you already have

Everything above assumes you are writing a new endpoint for the signer. If you already run an approvals
service, a rules engine, or a fraud API, an **adapter** lets the signer speak its shape directly — no shim
service to deploy, no fork.

```yaml
policy:
  url: "https://approvals.internal/api/v2/authorize"
  adapter_module: "./adapters/our-approvals-api.mjs"
```

The module default-exports `{ name, buildRequest?, parseResponse? }`. Supply only the direction you need —
omit one and the default shape is used for it.

**Start here:** [`examples/policy-adapter.mjs`](../examples/policy-adapter.mjs).

```js
export default {
  name: 'acme-approvals-v2',
  buildRequest: (req) => ({
    body: { reference: req.operationId, amounts: req.values, counterparty: req.target },
    headers: { 'x-api-key': process.env.APPROVALS_API_KEY },
  }),
  parseResponse: ({ status, body }) => {
    if (status === 403) return { decision: 'deny', reason: 'blocked' };   // their API denies with a 403
    const r = JSON.parse(body);
    if (r.outcome === 'ALLOW') return { decision: 'approve', reason: r.rule_name, evidence: { ruleId: r.rule_id } };
    if (r.outcome === 'REVIEW') return { decision: 'pending' };
    throw new Error(`unrecognized outcome: ${r.outcome}`);               // unknown → withhold
  },
};
```

Being handed the status matters: some APIs answer `403` for "denied", and the default path treats every
non-2xx as a failure — which withholds and leaves the transaction pending rather than killing it. An adapter
decides what a status means; the signer does not guess on your behalf.

**Three properties hold no matter what you write in there**, and they are enforced rather than trusted:

1. **Only `approve`, `deny`, and `pending` count.** Returning anything else — a different string,
   `undefined`, a stray object — is a failure to decide, and a failure to decide withholds. You cannot widen
   what counts as an approval from inside an adapter; you can only describe where to find one. Throwing has
   the same effect, so throwing on anything unrecognized is the correct default.
2. **The MAC still covers the bytes you build**, and the response MAC is verified **before** `parseResponse`
   sees the body. An adapter reshapes what a reply *means*; it has no say in whether the reply is authentic.
3. **An adapter that throws withholds** and never falls back to the default shape — sending a request the
   engine will misread is worse than sending none.

A module that fails to load, or that defines neither method, **stops the boot**. Running on with the default
shape against an engine expecting another one fails as transactions quietly never being signed.

### Authenticating the channel

Set `policy.auth: hmac` with a shared secret and the signer will sign its request and **require** a valid
signature on your response:

```yaml
policy:
  auth: "hmac"
  hmac_secret: "env:POLICY_HMAC_SECRET"
  signature_header: "x-signer-signature"   # point at whatever your engine emits
  timestamp_header: "x-signer-timestamp"
```

`auth: hmac` with an empty secret — including an `env:` ref pointing at a variable that is not set — is
**refused at startup**. The signer will not run in a state where its own config says the channel is
authenticated and it is in fact signing nothing and verifying nothing. `auth: mtls` is refused for the
same reason: it is not implemented, so terminate mTLS in a proxy in front of your engine and use `none`.

The MAC is `HMAC-SHA256(secret, "<timestamp>.<raw body>")`, with a five-minute freshness window bounding
replay. **Sign the exact bytes you send.** The signer verifies the raw response body, not a re-parse of
it, so signing a re-serialized copy fails the MAC forever — and because a bad MAC is a policy failure,
the signer would then silently never sign again. `examples/policy-engine.mjs` does this correctly.

An unauthenticated decision channel means anything that can reach the signer's outbound path can
authorize a signature. Use `hmac` (or mTLS) outside a trusted network.

---

## Seam 2 — the intent decoder (what gets decided on)

A pending transaction is bytes. Before your engine can decide anything, something must turn those bytes
into the sentence and amounts in the request above — and your payload format is yours, so this is the one
translation the signer cannot ship for you.

**Start here:** [`examples/custom-decoder.mjs`](../examples/custom-decoder.mjs).

You do not fork `src/`. Point the config at a file or a package:

```yaml
resolver:
  decoder_modules: ["./decoders/my-format.mjs"]
```

Default-export an object with a `name` and a `decode(body, ctx)`. Return a summary, or `undefined` to
decline and pass the transaction along. Confirm it loaded — the signer logs its whole chain at startup:

```
intent decoder chain (first claim wins)   decoders: ["my-format","send-tokens","certen-intent","write-data","fallback"]
```

### Rules

1. **Decline rather than guess.** Check a discriminator; confirm the payload parses; return `undefined`
   whenever you are unsure. A wrong summary is worse than no summary: your engine would approve a
   description that is not the transaction about to be signed, and that approval produces a real
   signature over the real bytes. A declined transaction still reaches your engine — described
   generically — and can still be denied.
2. **Put every amount in `values`.** See Seam 1.
3. **Prefer your own id as `operationId`.** It survives a re-submission in a way `txHash` does not, so
   it is what you can correlate against your own records.

**Order matters — first claim wins.** A specific decoder must precede a general one. The built-in
`write-data` decoder claims *every* data write, so anything understanding a particular data-write payload
must run ahead of it. Loaded modules run first by default; state an explicit order with
`resolver.decoders` if you need something else. An unknown name there stops the boot rather than running
one decoder short — because running short does not fail loudly, it fails as transactions quietly arriving
at your engine described as "Unrecognized data write".

A decoder that throws is treated as a decline and logged, so one malformed payload cannot stall the
queue. Prefer returning `undefined` explicitly.

### Built-ins

| Name | Claims |
|---|---|
| `send-tokens` | Native Accumulate token transfers. Reports every output amount. |
| `certen-intent` | A four-blob cross-chain intent format. Self-validating — it never matches a payload that is not genuinely one. Kept as a **worked reference**: [`src/decode/decoders/certen-intent.ts`](../src/decode/decoders/certen-intent.ts) is real production code and a good model to copy. |
| `write-data` | Any data write. Reads only plain self-describing fields; never guesses at an encoded payload. |
| `fallback` | Always appended, always claims. Guarantees a transaction is never undescribed. |

---

## Seam 3 — the vote backend (how the vote reaches the chain)

Default is **direct**: the signer builds the Accumulate signature preimage itself and submits the
envelope to a v3 node. Self-contained, nothing else need exist. Most deployments never change this.

An optional adapter votes through the Certen api-gateway's external-signing seam instead
([`src/vote/adapters/certen-gateway.ts`](../src/vote/adapters/certen-gateway.ts)). Your key still never
leaves the process — the gateway computes what must be signed, hands over the bytes, and you decide
whether to sign them. Discovery and decoding stay local either way.

To add another backend, implement `VoteBackend` in [`src/vote/backend.ts`](../src/vote/backend.ts) — a
single `cast(tx, vote)` method — and wire it in `src/index.ts`.

> One Accumulate detail that surprises people: **the vote is fixed when the signing data is created.**
> Accumulate folds the vote into the signature metadata hash, so approve and reject are different
> preimages, not one preimage with a flag. A backend cannot sign first and choose the vote afterwards.

---

## Key custody

Two postures, set by `signer.provider`:

- **`vault-transit` (production).** The key is generated inside HashiCorp Vault and never leaves it;
  Vault performs the Ed25519 signature. This process never holds private key material.
- **`local` (pilot).** The key is held in this process's memory, injected via an `env:` ref or a mounted
  secret file. Simpler, and a deliberate documented tradeoff.

Either way **the key is yours.** This software is not custodial and cannot sign without an `approve` from
your engine. Details and the threat model: [DEPLOY.md](DEPLOY.md).

A startup self-check (SR6) refuses to boot unless the configured key is verifiably present on the
on-chain key page. The failure it prevents is quiet: a signer on the wrong key produces votes the network
rejects, and it would otherwise look healthy while nothing it did ever took effect.

---

## What you get for free

Once the seams are wired, these hold without further configuration:

- **Never votes twice.** Signing history is idempotent and durable across restarts (`store.path`).
  Set it — without it, history and receipts die with the process, and a restart can double-vote.
- **A receipt per decision**, carrying your `reason` and `evidence` verbatim.
- **Emergency stop.** `POST /v1/admin/pause` halts all signing immediately. It suppresses reject votes
  too — a reject is still a signature.
- **A local value ceiling** (`behavior.value_ceiling`), gating every amount as a big integer, as
  defense-in-depth behind your engine. A backstop for an engine bug, not a policy.
- **Health and metrics.** `/healthz` reports poller liveness; `/metrics` exposes decision and signing
  counts. Both are admin-authenticated by default.

---

## Integration checklist

1. Run [`examples/policy-engine.mjs`](../examples/policy-engine.mjs) and point `policy.url` at it.
2. Run the quickstart to watch approve, deny, outage, and pending end to end on a test network.
3. Replace `checkPolicy()` with a call to your engine. Gate on `values`.
4. If your transactions carry your own payload format, add a decoder (Seam 2) and confirm it in the
   startup log.
5. Turn on `policy.auth: hmac`.
6. Set `store.path` to a persistent volume.
7. Set `admin.api_key`, and verify the pause works before you need it.
8. Move to `vault-transit` custody for production.
9. Read [OPERATIONS.md](OPERATIONS.md) for key rotation, cutover, backup, and upgrades.
