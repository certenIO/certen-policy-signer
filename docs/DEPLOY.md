# Deploying the signer (standalone pilot)

You run two containers: the **signer** (holds your key, votes on Accumulate) and your **policy engine**
(decides approve/deny). Certen ships this image but never holds your key and cannot make it sign.

The signer is self-contained: it discovers pending transactions itself, straight from Accumulate, and
depends on no hosted service. Voting through the optional gateway adapter instead is a separate
configuration — see `INTEGRATION.md` §3.

## Prerequisites

- Docker + Docker Compose.
- The org's Accumulate identity, with a key page (`acc://<org>.acme/book/1`) that has **credits**.
- The **Ed25519 seed for a key on that page**. The signer's public key must already be on the page, or it
  refuses to start (SR6 self-check, see below).

## Deploy

```bash
cd deploy
printf '%s' '<64-hex-char seed>' > signer-seed.txt && chmod 600 signer-seed.txt   # the org's key (gitignored)
cp .env.example .env            # ADMIN_API_KEY — protects the admin routes and /metrics
$EDITOR config.pilot.yaml       # set signer.org_id and signer.signer_url (the org's key page)
docker compose up -d            # pulls ghcr.io/certenio/certen-policy-signer; add --build to build locally
curl localhost:8080/healthz     # 200 {"ok":true,...,"poller":{"healthy":true}}
docker compose logs -f signer   # expect "SR6 self-check OK" then "poller started"
```

For the production key posture (key generated in Vault, never leaving it), use
`docker compose -f docker-compose.vault.yml` instead. Operational procedures — rotation, production
cutover, backup, upgrades — are in `OPERATIONS.md`.

If the signer's key is not on the configured page, it **refuses to start** (SR6). That is the intended
behaviour: a signer signing with the wrong key produces votes the network silently discards, so it stops
instead of pretending to work.

From then on it is autonomous: every `poller.interval_seconds` it scans for transactions that name the org
as an authority, decodes the intent, `POST`s a decision request to the policy engine, and — on `approve` —
signs an Accept vote with the org's key and submits it. On `deny` it submits a Reject vote
(`behavior.submit_reject_vote: true`) or, if you set that to `false`, simply withholds its signature and
lets the transaction expire.

## Pin the image by digest

Images are published to `ghcr.io/certenio/certen-policy-signer` on every version tag — multi-arch, with
build provenance and an SBOM.

**In production, pin a digest rather than a tag.** A tag is a mutable pointer: `:0.1.0` can be repushed to
different bytes, and the thing those bytes hold is your signing key. A digest names the content itself.

```bash
docker pull ghcr.io/certenio/certen-policy-signer:0.1.0
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/certenio/certen-policy-signer:0.1.0

# compose
SIGNER_IMAGE=ghcr.io/certenio/certen-policy-signer@sha256:<digest> docker compose up -d

# helm — image.digest wins over image.tag when both are set
helm upgrade --install signer deploy/helm --set image.digest=sha256:<digest>
```

The release workflow refuses to publish when the git tag and `package.json` version disagree, and it
smoke-runs the built image (`--version`, `--help`) before pushing — so a broken bundle or a bad entrypoint
fails in CI rather than as a crash-looping container in your cluster.

**npm is not the deployment path.** `npx certen-policy-signer config.yaml` is for evaluating the signer in
two minutes and for embedding its pieces in your own service. It gives you no pinned runtime, no non-root
user, no declared state volume, and no healthcheck — none of the posture this page is about.

## Key posture

Two supported postures. **Pick deliberately, and say which one you are running.**

### Pilot — key in process, from a mounted secret file

```yaml
signer:
  provider: "local"
  local:
    seed_file: "/run/secrets/signer_seed"    # docker secret / k8s secret mount
```

The key is in the signer's memory. Supply it as a **file**, not `seed_hex: "env:..."` — environment
variables are readable via `docker inspect`, via `/proc/<pid>/environ`, and they leak into logs and crash
dumps. (The `env:` form still works, and is fine for a throwaway test; it is not what you deploy.)

This is a **deliberate pilot-only tradeoff**: compromise the signer host and you have the org's key.

### Production — Vault Transit, the key never leaves Vault

```yaml
signer:
  provider: "vault-transit"
  vault: { addr: "https://vault.internal:8200", key_name: "org-accum", token: "env:VAULT_TOKEN" }
```

The key is **generated inside Vault** and never leaves it. The signer sends a 32-byte preimage and receives
a signature; it holds no private key at all, so compromising the signer does not yield the key. The signer's
only secret is a Vault token — scope it to `transit/sign/org-accum` and use AppRole/k8s auth, not a root token.

**This is proven, not assumed:** `npx tsx scripts/verify/vault-custody.ts` generates the key in Vault, puts
*Vault's* public key hash on a a live test-network key page, and shows the network accepting votes that Vault signed.
See the production key posture in `OPERATIONS.md`, and key rotation to migrate an existing org from the pilot key to a Vault key.

### Fail-closed either way

No seed and no explicit `allow_ephemeral` → the signer **refuses to boot**, rather than generating a random
key and casting votes the network will silently reject. And SR6 refuses to start unless the key it holds
(or Vault holds) is verifiably on the configured page.

## State — and why the volume matters

The signer keeps its signing history and its **receipts** (what it decided, why, and the evidence the
policy engine gave) in `store.path`, on the `signer-state` volume. Two things depend on it:

- **Idempotency.** Each pending transaction is voted on exactly once. The in-process single-flight lock
  handles concurrency within a run; the store is what makes that hold *across a restart*.
- **The audit trail.** The receipts are the evidence that a signature was authorized. Delete the volume
  and you have not cleared a cache — you have destroyed the record of every decision the org made.

Run **one** signer per state volume. Two replicas sharing it could both vote on the same transaction; the
Helm chart enforces `replicaCount: 1` and `strategy: Recreate` for exactly that reason.

## Guardrails worth knowing

- **SR6 startup self-check (fail-closed)** — the signer's public key must be *verifiably* among the keys on
  the configured page. Mismatch, unreachable page, or unreadable key hashes → it refuses to start.
  `signer.allow_unverified_signer: true` downgrades this to a warning; you are then signing unverified.
- **Admin routes are always authenticated.** They share the public health listener, so `admin.api_key` is
  what protects them. **Unset ⇒ every admin route returns 403**, including SR8 pause — safe by default, but
  it means pause is unavailable in an incident. Set `ADMIN_API_KEY`.
- **SR8 emergency pause** — `POST /v1/admin/pause` (with `x-api-key`) halts all signing immediately.
- **`/metrics` is authenticated too** — it exposes the org's decision counts. It requires `x-api-key` unless
  you set `observability.metrics_public: true`, which you should only do when the port is already private
  (e.g. a ClusterIP scraped in-cluster).
- **Fail-closed policy** — if the policy engine is unreachable, times out, or returns something malformed,
  the signer does **not** sign. It retries on the next poll, backing off while the engine is down.
- **`/healthz` is honest** — 503 if the key provider is unreachable *or* the discovery poller has stalled.
  A signer that cannot see pending work is not healthy, even though its HTTP server is up.
- **SR4 value ceiling (optional)** — `behavior.value_ceiling` refuses to sign if **any leg** of an intent
  exceeds it, all-or-nothing. It is compared as a big integer, so wei-scale amounts do not overflow, and a
  leg whose amount could not be read at all is refused rather than skipped.
- **Optional HMAC** — set `policy.auth: hmac` + `POLICY_HMAC_SECRET` and the signer will only act on
  decisions it can authenticate as coming from the org's engine. Turning it on and leaving the secret
  empty **stops the boot**: the one thing worse than an unauthenticated channel is an unauthenticated
  channel whose config claims otherwise.

## Verifying a deploy

`scripts/verify/deployed-container.ts` is the acceptance test. It provisions a throwaway org and initiator on
the test network, brings up **this exact compose stack**, and asserts ten things end to end: the container boots and
passes SR6; `/healthz` reports the poller healthy; admin routes reject anonymous and wrong-key callers and
accept the right one; an even and an odd intent naming the org are both discovered unaided; the even one is
approved (delivered) and the odd one rejected; exactly two votes are cast; the receipts land on the volume
with the right decisions; and after `docker compose restart signer` the history is intact and **nothing is
re-voted**.

```bash
npx tsx scripts/verify/deployed-container.ts        # ~5 min against a live test network
npm run test:vault                          # proves the Vault-Transit key path (boots a dev Vault)
npm test                                    # 293 offline tests
```

## The `prepare` hook — do not delete it

`npm install` (in a clone) runs `scripts/fix-accumulate-encoding.mjs`, which patches a **real bug in
accumulate.js 0.12**:
it encodes `time.Time` transaction-header fields (`expire`, `holdUntil`) as an *unsigned* varint of
*fractional* seconds, while Accumulate core uses a *signed* varint of *whole* Unix seconds
(`EncodeInt(v.UTC().Unix())`). The header hash then disagrees with the network and any transaction carrying
an expiry is rejected as "not signed".

The patch is idempotent and warns loudly if upstream changes shape. It must run **before** the esbuild
bundle, since the bundle inlines accumulate.js — the Dockerfile therefore copies the script before `npm ci`,
and the runtime stage uses `--ignore-scripts` (the fix is already baked into `dist/signer.cjs`). Removing the
hook silently reintroduces the bug. Remove it only when accumulate.js fixes this upstream.

It lives in `prepare` rather than `postinstall` deliberately. npm runs `postinstall` for installed
*dependencies* too, so a consumer of the published package used to see it fire in their tree, find no
`node_modules/accumulate.js` to patch, and print a warning that read like a broken install. `prepare` runs on
a local install and before `npm publish`, but not on a registry install — which is correct, because the
published `dist/signer.cjs` already contains the patched code.
