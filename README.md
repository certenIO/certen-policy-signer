# certen-policy-signer

**A headless signer for [Accumulate](https://accumulatenetwork.io) that will not sign anything your
policy engine has not approved.**

You run it. You hold the key. It watches the chain for transactions that need your organization's
authority, asks *your* off-chain policy engine what to do, and signs only on an explicit approval.

```
   someone submits a transaction naming your key book as a required authority
                             │
   Accumulate holds it PENDING — it cannot execute without you
                             │
   this signer discovers it, decodes what it does, and asks YOUR policy engine
                             │
            approve ──▶ signs · deny ──▶ rejects · no answer ──▶ signs nothing
```

The last branch is the point. **Every failure mode withholds the signature** — a timeout, a crash,
malformed JSON, a bad MAC, an unreachable engine, an unreadable payload. An outage can never become an
approval. That is a property of the code, not a setting.

Certen builds and maintains this. It is **not custodial**: the key is generated and held by you, in your
process or in your Vault, and no one — including Certen — can make it sign without your engine's
approval.

---

## Is this for you?

Use it when a transaction on Accumulate needs a decision that lives **off** chain — a biometric re-auth,
a fraud rule, a compliance check, a spending limit, a human approval — and you want that decision
enforced cryptographically rather than by convention.

The user submitting the transaction names your key book as a required authority. From that moment the
transaction cannot execute without you, and this signer is what decides whether it does. **You do not
need to change how transactions are built** to put a policy gate on them.

New to Accumulate and Certen? **[docs/PRIMER.md](docs/PRIMER.md)** explains both networks in a page —
what an ADI, key book, and key page are, why a transaction sits pending, and how the proof cycle works.

---

## Quick start (10 minutes, no blockchain)

```bash
npm install                     # also applies a required accumulate.js patch — see docs/DEPLOY.md
npm test                        # 293 tests, no network needed
npm run smoke                   # prove the Ed25519 preimage is valid and deterministic
```

Now run the signer against the reference policy engine:

```bash
# terminal 1 — a policy engine that approves even amounts and denies odd ones
POLICY_MODE=parity node examples/policy-engine.mjs      # :9099

# terminal 2 — the signer
cp config.minimal.yaml config.yaml && $EDITOR config.yaml
npx tsx src/index.ts config.yaml
curl localhost:8080/healthz
```

**[`config.minimal.yaml`](config.minimal.yaml) is the whole config** — five fields, because everything else
has a working default. [`config.example.yaml`](config.example.yaml) is the same file with every option and
the reasoning behind it, for when you need one.

Then swap the engine for yours: **[`examples/policy-engine.mjs`](examples/policy-engine.mjs) has exactly
one function to replace.** That is the whole integration.

To watch all four outcomes against a real network, see [Quickstart](docs/QUICKSTART.md) — it provisions
throwaway testnet identities and runs approve, deny, engine-outage, and async-challenge end to end.

---

## The contract

One HTTP POST per pending transaction:

```jsonc
// signer → you
{ "txHash": "9c2b…", "actionSummary": "Purchase order PO-1043 — 25000 USDC to Northwind",
  "values": ["25000", "500"], "target": "0xabc…", "chain": "ethereum", "expiresAt": "…" }

// you → signer
{ "decision": "approve" | "deny" | "pending", "reason": "matched rule 12", "evidence": { … } }
```

| Reply | Result |
|---|---|
| `approve` | Signs an accept vote. The transaction executes. |
| `deny` | Signs a reject vote (or withholds). The transaction dies. |
| `pending` | Signs nothing, asks again next poll. For human approvals and step-up challenges. |
| anything else, or nothing | Signs nothing, retries. Fail-closed. |

`reason` and `evidence` are persisted verbatim in a durable receipt beside the vote — the audit trail
tying *"we decided this"* to *"this happened on chain."*

Full details, including the signed channel and how to answer asynchronously:
**[docs/INTEGRATION.md](docs/INTEGRATION.md)**.

---

## Extending it without forking

Five seams, all configuration rather than code changes to this repo:

| Seam | What it decides | How |
|---|---|---|
| **Policy engine** | Whether to sign | `policy.url` → your HTTP endpoint |
| **Policy adapter** | What that call looks like on the wire | `policy.adapter_module` → your module ([example](examples/policy-adapter.mjs)) |
| **Intent decoder** | What your engine is shown | `resolver.decoder_modules` → your module ([example](examples/custom-decoder.mjs)) |
| **Notifications** | Who gets told | `notify.sms` / `email` / `slack` / `webhook` |
| **Vote backend** | How the vote reaches the chain | `direct` (default), or an optional gateway adapter |

The decoder seam matters more than it looks. A pending transaction is bytes; something has to turn them
into *"Transfer 25000 USDC to Northwind"* before a policy decision means anything. Your payload format is
yours, so you supply that translation — a small module, loaded at boot, no fork required.

---

## Notifications

Get a text message when something needs your signature. Fill in a phone number and a Twilio credential:

```yaml
notify:
  sms:
    to: ["+15551234567"]
    from: "+15559876543"
    account_sid: "env:TWILIO_ACCOUNT_SID"
    auth_token: "env:TWILIO_AUTH_TOKEN"
```

Email (SendGrid), Slack, and a generic signed webhook are configured the same way, in any combination —
each is a single HTTPS POST, so none of them add a dependency. Five events:
`pending.discovered`, `decision.approved`, `decision.denied`, `signature.failed`, `signer.paused`.

SMS and email default to the two a human must act on — work arrived, or a vote failed to submit — because
they cost money per message and interrupt someone. Webhook and Slack get everything. Override per channel
with `events: [...]`. For anything these four do not cover, the webhook channel carries the same payload to
your own endpoint: [`examples/notifier.mjs`](examples/notifier.mjs).

**Delivery is best-effort, and it is the one thing here that does not fail closed.** An undeliverable
notification is logged and dropped; it never delays or changes a signing decision, because a signer that
stopped signing because Twilio was down would be a worse signer. The durable record is the receipt store.

For a live work queue rather than a push — "what is waiting on a human right now" — poll
`GET /v1/requests?status=awaiting_policy`.

---

## Already have an approvals API?

Point the signer at it. A **policy adapter** reshapes the request, the response, or both, so you do not
deploy a translating shim:

```yaml
policy:
  url: "https://approvals.internal/api/v2/authorize"
  adapter_module: "./adapters/our-approvals-api.mjs"
```

```js
export default {
  name: 'acme-approvals-v2',
  buildRequest: (req) => ({ body: { reference: req.operationId, amounts: req.values } }),
  parseResponse: ({ status, body }) => status === 403        // their API denies with a 403
    ? { decision: 'deny' }
    : { decision: JSON.parse(body).outcome === 'ALLOW' ? 'approve' : 'deny' },
};
```

The fail-closed rule is enforced around it, not delegated to it: only `approve`/`deny`/`pending` count, the
response MAC is verified before your parser sees the body, and an adapter that throws withholds. See
[`examples/policy-adapter.mjs`](examples/policy-adapter.mjs) and
[INTEGRATION.md](docs/INTEGRATION.md#pointing-the-signer-at-an-api-you-already-have).

---

## Security posture

Everything is fail-closed: the signer stops rather than signs when it cannot prove it should.

- **Key custody.** `vault-transit` — the key is generated in HashiCorp Vault and never leaves it; Vault
  signs. `local` — the key is held in-process from an `env:` ref or a mounted secret file; the pilot
  posture, a deliberate documented tradeoff.
- **Startup self-check (SR6).** The configured key must be *verifiably* on the on-chain key page.
  Mismatch, unreachable page, or unreadable key hashes → refuse to start. The failure it prevents is
  silent: a signer on the wrong key looks healthy while every vote it casts is rejected.
- **Admin routes are always authenticated.** They share the health listener, so `admin.api_key` — not a
  bind address — is what protects them. Without it, every admin route returns 403. Credentials are
  compared in constant time.
- **Refuses to boot on an unusable key config** rather than generating a random key and casting votes the
  network will reject.
- **Signs only after an `approve`**, optionally over an HMAC-authenticated channel with a replay window.
- **Value ceiling (SR4, optional).** Refuses to sign if *any* amount exceeds it, compared as a big
  integer — at wei scale, `Number()` silently rounds and would wave an over-limit amount through. It also
  refuses when a leg moves value the decoder could not price: an amount you cannot read is not an amount
  under the limit.
- **Emergency pause.** `POST /v1/admin/pause` halts signing immediately, including reject votes — a
  reject is still a signature.
- **Durable state.** Signing history and receipts survive restart, so it never double-votes and the audit
  trail is not lost with the process.

A note on discovery, since it trips people up: header authorities are enforced by the network but do
**not** appear in `Pending()`. This signer finds them by walking the key book's signature chain — see
`listPendingViaSignatureChain` in `src/accumulate/raw-client.ts`.

---

## Deploy

**Run the container.** It is the supported way to hold a key: pinned runtime, non-root user, a declared
volume for the durable store, a healthcheck, and the seed arriving as a mounted file rather than an
environment variable that `docker inspect` will happily print.

```bash
cd deploy
printf '%s' '<64-hex seed>' > signer-seed.txt && chmod 600 signer-seed.txt
cp .env.example .env          # ADMIN_API_KEY
$EDITOR config.pilot.yaml     # org_id + signer_url (your key page)
docker compose up -d
```

Images are published to `ghcr.io/certenio/certen-policy-signer`. **Pin a digest in production** — a tag can
be moved to different bytes, a digest cannot, and this container holds your signing key:

```bash
SIGNER_IMAGE=ghcr.io/certenio/certen-policy-signer@sha256:<digest> docker compose up -d
```

For the production key posture (key born in Vault, never leaves it):
`docker compose -f docker-compose.vault.yml up -d`.

A Helm chart is in [`deploy/helm`](deploy/helm) — set `image.digest` there for the same reason. It pins
`replicaCount: 1` and `strategy: Recreate` deliberately: two replicas sharing one state volume could both
vote on the same transaction.

The npm package is for evaluation and embedding — `npx certen-policy-signer config.yaml` to try it in two
minutes, or `import` the pieces into your own service. It gives you none of the custody posture above, so
it is not what you run in production.

- **[docs/](docs/)** — the documentation index, in reading order.
- **[docs/PATTERNS.md](docs/PATTERNS.md)** — the four deployment shapes: single-org gate, one seat of an
  M-of-N panel, a fleet of identities in one process, delegated authority. Read yours; the other docs
  assume the first.
- **[docs/DEPLOY.md](docs/DEPLOY.md)** — key posture, guardrails, and why the `prepare` hook exists
  (it patches a real `accumulate.js` encoding bug — **do not delete it**).
- **[docs/OPERATIONS.md](docs/OPERATIONS.md)** — key rotation, production cutover, backup and restore,
  upgrades, and the signing gap.

---

## Architecture

```
Trigger (poller/webhook) → Resolver+Decoder → Policy client → Signer → Vote backend → Accumulate v3
                                  \____ Store: receipts · idempotency ____/     Admin · Health · Metrics
```

| Module | Responsibility |
|---|---|
| `accumulate/signing.ts` | The exact signature preimage, `SHA256(sigMdHash‖txHash)` |
| `accumulate/raw-client.ts` | Accumulate v3 over raw JSON-RPC |
| `decode/` | The decoder registry and the built-in decoders |
| `policy/policy.ts` | HTTP policy client, HMAC request signing and response verification |
| `signer/` | `LocalSigner`, `VaultTransitSigner`, and the multi-page keyring |
| `vote/` | `DirectVoteBackend` and optional adapters |
| `orchestrator.ts` | The pipeline: resolve → decide → sign → submit → receipt |
| `poller.ts` · `server.ts` | Discovery; health, metrics, webhook, admin |

Two implementation decisions worth knowing:

- **Transport is raw JSON-RPC.** The typed SDK client has fragile internal circular dependencies under
  bundlers; raw JSON-RPC is version-independent.
- **The build is an esbuild bundle** (`dist/signer.cjs`) so the production artifact runs under plain
  `node` — `accumulate.js` uses extensionless imports that only a bundler resolves.

---

## Fleets — many pages, divergent rules, one process

One process can watch several key pages, each with its own key and its own custody. **Each page can also
carry its own rules**: the top-level `policy` and `behavior` blocks are defaults, and a scope states only
what differs.

```yaml
wallet:
  scopes:
    - page: "acc://seller-bot.acme/book/1"        # inherits everything
      key: { provider: "local", local: { seed_file: "/run/secrets/seller_seed" } }

    - page: "acc://trading-agent.acme/book/1"     # own engine, own secret, own ceiling
      key: { provider: "local", local: { seed_file: "/run/secrets/trading_seed" } }
      policy: { url: "https://rules.internal/trading/decide", hmac_secret: "env:TRADING_HMAC" }
      behavior: { value_ceiling: "100000" }

policy:
  url: "https://policy.internal/decision"
```

Each overriding scope gets its own policy client, credential, and guard — so an agent whose engine is down
stalls **that page only**, and a leaked per-agent secret does not authorize decisions for the rest. An
unknown key inside a scope's `policy`/`behavior` stops the boot rather than silently meaning "inherit".

Per-scope rules cover divergent *policy*. They do not partition the store, the admin credential, or the
pause switch — `POST /v1/admin/pause` stops every scope. A tenant needing its own operator or genuine
failure isolation is a container boundary, not a config one.

See [`config.multi-scope.example.yaml`](config.multi-scope.example.yaml) and
[docs/PATTERNS.md §C](docs/PATTERNS.md).

---

## Command line

The signer takes one argument — the config file — and `--help` describes the whole surface, including
the HTTP routes and which of them are admin-only:

```bash
npm install -g certen-policy-signer          # or: npx certen-policy-signer config.yaml
certen-policy-signer --help

npm install                                  # from a clone; builds dist/signer.cjs during install
node dist/signer.cjs --help                  # from a build, no global install
npx tsx src/index.ts --help                  # from source
docker run --rm certen/policy-signer --help
```

> Install from the registry or from a clone — not `npm install -g <git-url>`. npm prepares a git dependency
> by running `prepare` in a temp clone with no devDependencies, so the esbuild build fails there.
>
> `certen-external-policy-signer` remains installed as an alias for deployments that already call it that.

| | |
|---|---|
| `certen-policy-signer [config-path]` | Run. Config resolves from the argument, then `$CONFIG_PATH`, then `./config.yaml` |
| `--help`, `-h` | Usage, environment, and the HTTP surface |
| `--version`, `-v` | Package version |
| `$LOG_LEVEL` | Pino level; `info` by default |

An unrecognised flag exits `2` rather than being ignored — a flag that is silently dropped looks like
a setting that took effect.

---

## Scripts

| Command | What it does |
|---|---|
| `npm test` | The offline suite — no network, no key |
| `npm run test:vault` | Vault-Transit integration: boots a dev Vault, proves the production key path |
| `npm run typecheck` | `tsc` |
| `npm run smoke` | The signing golden pipeline |
| `npm run build` / `npm start` | Bundle to `dist/signer.cjs` and run |
| `npm run console` | The operator console (see [`console/`](console/)) |

Operator tool — rotate the signing key and confirm the change on chain:

```bash
npx tsx scripts/rotate-key.ts --config <cfg> --new-vault-key <key>
```

---

## License

Apache-2.0. See [LICENSE](LICENSE).
