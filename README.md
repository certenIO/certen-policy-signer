# certen-external-policy-signer

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

---

## Quick start (10 minutes, no blockchain)

```bash
npm install                     # also applies a required accumulate.js patch — see docs/DEPLOY.md
npm test                        # 207 tests, no network needed
npm run smoke                   # prove the Ed25519 preimage is valid and deterministic
```

Now run the signer against the reference policy engine:

```bash
# terminal 1 — a policy engine that approves even amounts and denies odd ones
POLICY_MODE=parity node examples/policy-engine.mjs      # :9099

# terminal 2 — the signer
cp config.example.yaml config.yaml && $EDITOR config.yaml
npx tsx src/index.ts config.yaml
curl localhost:8080/healthz
```

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

Three seams, all configuration rather than code changes to this repo:

| Seam | What it decides | How |
|---|---|---|
| **Policy engine** | Whether to sign | `policy.url` → your HTTP endpoint |
| **Intent decoder** | What your engine is shown | `resolver.decoder_modules` → your module ([example](examples/custom-decoder.mjs)) |
| **Vote backend** | How the vote reaches the chain | `direct` (default), or an optional gateway adapter |

The decoder seam matters more than it looks. A pending transaction is bytes; something has to turn them
into *"Transfer 25000 USDC to Northwind"* before a policy decision means anything. Your payload format is
yours, so you supply that translation — a small module, loaded at boot, no fork required.

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
  integer — at wei scale, `Number()` silently rounds and would wave an over-limit amount through.
- **Emergency pause.** `POST /v1/admin/pause` halts signing immediately, including reject votes — a
  reject is still a signature.
- **Durable state.** Signing history and receipts survive restart, so it never double-votes and the audit
  trail is not lost with the process.

A note on discovery, since it trips people up: header authorities are enforced by the network but do
**not** appear in `Pending()`. This signer finds them by walking the key book's signature chain — see
`listPendingViaSignatureChain` in `src/accumulate/raw-client.ts`.

---

## Deploy

```bash
cd deploy
printf '%s' '<64-hex seed>' > signer-seed.txt && chmod 600 signer-seed.txt
cp .env.example .env          # ADMIN_API_KEY
$EDITOR config.pilot.yaml     # org_id + signer_url (your key page)
docker compose up -d --build
```

For the production key posture (key born in Vault, never leaves it):
`docker compose -f docker-compose.vault.yml up -d --build`.

A Helm chart is in [`deploy/helm`](deploy/helm).

- **[docs/DEPLOY.md](docs/DEPLOY.md)** — key posture, guardrails, and why the `postinstall` hook exists
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

## Multi-page signing

One process can watch several key pages, each with its own key and its own custody — one poller per
scope, one shared decision pipeline, and a keyring that selects the key by page.
See [`config.multi-scope.example.yaml`](config.multi-scope.example.yaml).

---

## Command line

The signer takes one argument — the config file — and `--help` describes the whole surface, including
the HTTP routes and which of them are admin-only:

```bash
npm install -g certenIO/certen-external-policy-signer   # the install builds the bundle
certen-external-policy-signer --help

node dist/signer.cjs --help                # from a build
npx tsx src/index.ts --help                # from source
docker run --rm certen/external-policy-signer --help
```

| | |
|---|---|
| `certen-external-policy-signer [config-path]` | Run. Config resolves from the argument, then `$CONFIG_PATH`, then `./config.yaml` |
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
