# Deployment patterns

Four shapes this signer is deployed in. Find yours, copy the config, then read
[INTEGRATION.md](INTEGRATION.md) for the decision contract — that part is identical in all four.

Everything else in this repo describes pattern A, because it is the common one. If you are building
something that looks like B or C, the rest of the docs will read as though they are assuming things about
you that are not true. This page is the correction.

| | Shape | You are here if |
|---|---|---|
| **A** | One org, one key page, one engine | A policy check gates transactions naming your key book |
| **B** | One seat of an M-of-N panel | You are one voter in a multi-party approval, not the only one |
| **C** | Many identities, one process | You run a fleet — agents, tenants, desks — each with its own page |
| **D** | Delegated authority | Users delegate to your book rather than naming it directly |

---

## A — Single-org policy gate

One key page, one policy engine. A transaction names your key book; your engine decides; the signer signs.

```yaml
wallet:
  org_id: "your-org"
  accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"]
  signer_url: "acc://your-org.acme/book/1"
signer:
  provider: "local"
  local: { seed_file: "/run/secrets/signer_seed" }
policy:
  url: "https://policy.internal/decision"
```

**The thing that goes wrong:** your engine returns `deny` for "I need more time." That casts a real reject
vote and kills a transaction you would have approved a minute later. Return `pending` — the signer withholds
and re-asks, indefinitely, at no cost.

---

## B — One seat of an M-of-N panel

Your key page is one of several on a book with a threshold. You vote; the transaction executes when enough
seats have. Nothing in the config changes for this — the *page* is one seat and the *book* enforces the
threshold, so from the signer's point of view it is pattern A. What changes is your reasoning about it.

```yaml
wallet:
  signer_url: "acc://panel.acme/book/2"        # YOUR page on the shared book, not the book itself
behavior:
  submit_reject_vote: false                    # see below
```

To vote through the Certen gateway's co-signer seam instead of submitting to Accumulate directly — which is
what you want if the other seats are already coordinating there:

```yaml
gateway:
  enabled: true
  url: "https://gateway.kompendium.co"
  api_key: "env:GATEWAY_API_KEY"
  identity: "acc://panel.acme"
```

Your key still never leaves the process either way. The gateway computes the bytes to be signed and hands
them over; the decision to sign them is made here, by your engine.

**Where those two values come from.** `GATEWAY_API_KEY` and the panel ADI are the only things this pattern
needs that the rest of the signer does not, and the CLI produces both:

```bash
npm install -g @certen.io/cli
certen login          # approve this machine once in the portal; the key lands in ~/.certen/config.json
certen init           # creates the identity and waits until it can actually sign
certen whoami         # confirms which key and which gateway you are pointed at
```

`certen login` uses the device authorization grant, so the key is never displayed and never passes through
a clipboard or shell history — which matters more here than usual, because this one ends up in a config
file on a server. `certen auth status` shows only its prefix afterwards; feed the real value to the process
through the environment, as the `env:` prefix above expects.

If the identity already exists, `certen init` reuses it rather than creating a second one, and
`certen doctor` will say if it cannot sign or if its abstract account has no gas.

**Two things that go wrong.**

*Casting reject votes from a seat.* On a panel, a reject is not "I abstain" — depending on the book it can
kill a transaction the other seats were going to approve. `submit_reject_vote: false` (the default) withholds
instead, which is almost always what a single seat means by "no". Turn it on only when your seat is meant to
have a veto.

*Assuming your seat is the last one.* A `decision.approved` notification means you voted, not that the
transaction executed. The other seats may still be out. Watch the transaction, not your own vote.

---

## C — Many identities, one process

A fleet: one signer watching N key pages, each with its own key and its own custody. One poller per scope,
one shared decision pipeline, and a keyring that picks the key by page.

**Each scope carries its own rules.** The top-level `policy` and `behavior` blocks are the defaults; any
scope overrides either and states only what differs. A fleet of agents rarely shares one rulebook.

```yaml
wallet:
  org_id: "agent-fleet"
  accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"]
  # NOTE: scopes[] replaces signer_url and the top-level signer block. Setting both is a startup error.
  scopes:
    # Inherits everything below.
    - page: "acc://seller-bot.acme/book/1"
      key: { provider: "local", local: { seed_file: "/run/secrets/seller_seed" } }

    # Its own engine, its own secret, its own ceiling.
    - page: "acc://trading-agent.acme/book/1"
      key: { provider: "local", local: { seed_file: "/run/secrets/trading_seed" } }
      policy:
        url: "https://rules.internal/agents/trading/decide"
        hmac_secret: "env:TRADING_HMAC"
      behavior: { value_ceiling: "100000" }

    # High ceiling, and a deny here kills the transaction rather than quietly withholding.
    - page: "acc://treasury.acme/book/1"
      key: { provider: "vault-transit", vault: { addr: "https://vault:8200", key_name: "treasury", token: "env:VAULT_TOKEN" } }
      behavior: { value_ceiling: "5000000000", submit_reject_vote: true }

policy:
  url: "https://policy.internal/decision"     # the default every scope inherits
behavior:
  value_ceiling: "1000000"
```

Custody is per scope too, so a high-value seat lives in Vault while the routine ones do not.

**What this buys you beyond convenience: blast radius.** Each overriding scope gets its own policy client,
its own credential, and its own guard. A scope whose engine is unreachable stalls *that page* — every other
page keeps signing. One agent's compromised HMAC secret does not authorize decisions for the rest.

**Three things worth knowing before you build on it.**

*Overrides merge, they do not replace.* A scope stating only `value_ceiling` keeps the default engine, the
default timeout, the default secret. Field by field, not all-or-nothing.

*Unknown keys stop the boot.* `value_celing: "50"` is not ignored — it is a startup error naming the key. A
typo would otherwise silently mean "inherit", leaving that page running under rules its own config appears
to contradict, and nothing would ever log that it happened.

*Authentication is checked on the merged result.* A scope setting `auth: "hmac"` with no secret anywhere
refuses to start, exactly as the top-level block does. A scope cannot quietly downgrade itself to an
unauthenticated channel, and inheriting the default secret satisfies the requirement normally.

Full example, including an agent whose approvals live in a pre-existing system:
[`config.multi-scope.example.yaml`](../config.multi-scope.example.yaml).

**When to run separate processes anyway.** Per-scope rules cover divergent *policy*. They do not partition
the store, the admin credential, the pause switch, or the process itself — `POST /v1/admin/pause` stops
every scope. If a tenant needs its own operator, its own emergency stop, or genuine failure isolation, that
is a container boundary, not a config one.

---

## D — Delegated authority

Users' key pages delegate to your book, so your signature satisfies their authority without your book being
named on each transaction.

```yaml
wallet:
  signer_url: "acc://your-org.acme/book/1"
  attachment_model: "delegate"
  delegator_url: "acc://user.acme/book/1"
```

There is also `attachment_model: per_tx`, for authorities named in the transaction *header* rather than on
the account. Those are enforced by the network but do **not** appear in `Pending()` — the signer finds them
by walking the key book's signature chain (`listPendingViaSignatureChain` in
[`src/accumulate/raw-client.ts`](../src/accumulate/raw-client.ts)). You do not have to do anything to enable
that; it is worth knowing because "the transaction exists and my signer cannot see it" otherwise looks like
a bug in discovery.

---

## E — Per-user re-authentication

Your engine holds a binding per END USER — a biometric template, an MFA enrolment, a customer record —
and every transaction has to be answered for the right person. Nothing in the wallet config changes; what
changes is that you read one more field.

```js
// in your POST /decision handler
const adi = request.subject?.adi;              // the enrolled user's Accumulate ADI
if (!adi) return { decision: 'deny', reason: 'no subject' };
const user = await roster.get(adi);
if (!user) return { decision: 'deny', reason: `no enrolment for ${adi}` };
return await reauthenticate(user, request);    // your biometric / MFA / step-up check
```

`subject.adi` is the same identity your enrolment validated — see `examples/enrollment.mjs` for the other
end of it, and `checkEnrolledSubject` in `examples/policy-engine.mjs` for a runnable version of the above.
Key on `adi`, never on `subject.keyBook`: the book is a hint, and binding to it makes every key rotation a
re-enrolment.

**The thing that goes wrong, and it is not the obvious one.** The subject is *optional*. Intents written
before the field existed, third-party producers and custom decoders all carry none, and the temptation is
to `throw` when it is missing. Don't: a throw **withholds**, so the transaction stays alive on chain until
it expires while nobody is told why, and from the outside it is indistinguishable from your service being
down. If your engine requires a subject, answer `deny` and say so in `reason`.

**The second thing that goes wrong.** Trusting the claim unconditionally. The subject is asserted by
whoever wrote the intent, not proven by the user it names — see
[INTEGRATION.md](INTEGRATION.md#who-the-transaction-is-about). Pin the principal: accept a subject only
when `request.account` is an account belonging to a customer you have a relationship with. One line, and
it is the difference between trusting anyone who can reach your endpoint and trusting claims written under
an account you already agreed to trust.

---

## Applies to all four

- **Set `store.path`.** Without it, signing history and receipts die with the process, and a restart can
  double-vote.
- **Set `admin.api_key`.** Without it the emergency pause is unavailable — every admin route returns 403.
- **Turn on `policy.auth: hmac`** before the engine is reachable from anything you do not control.
- **Move to `vault-transit`** for production custody.

The full checklist is at the end of [INTEGRATION.md](INTEGRATION.md).
