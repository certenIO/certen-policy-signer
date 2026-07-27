# Operations

Procedures for running this signer in production. Each states the **problem**, the **procedure**, and how
you **confirm** it worked.

"Confirmed" throughout means confirmed by observing the network or the running system — not by a command
exiting 0. That distinction matters more here than in most software: Accumulate executes asynchronously,
so a submitted transaction is not a completed one, and the difference between those two is where key
rotations go wrong.

| | |
|---|---|
| [Deploy](#deploy) | Both key postures |
| [Rotate the signing key](#rotate-the-signing-key) | Three modes, and how to pick |
| [Emergency stop](#emergency-stop) | Pause and resume |
| [Production cutover](#production-cutover) | Moving off a test network |
| [Backup and restore](#backup-and-restore) | The state file is the audit trail |
| [Restart and upgrade](#restart-and-upgrade) | The signing gap, and why there is one replica |
| [Release checks](#release-checks) | What to run before shipping a change |

---

## Deploy

### Pilot posture — key in process

The key is held in the signer's memory, read from a **mounted secret file**.

> Use a file, not an environment variable. Env vars are readable via `docker inspect` and
> `/proc/<pid>/environ`, and they leak into logs and crash dumps.

```bash
cd deploy
printf '%s' '<64-hex-char seed>' > signer-seed.txt && chmod 600 signer-seed.txt   # gitignored
cp .env.example .env          # set ADMIN_API_KEY
$EDITOR config.pilot.yaml     # wallet.org_id + wallet.signer_url
docker compose up -d --build
```

**Confirm:** `SR6 self-check OK` in the logs (the key is verifiably on the page), `/healthz` returns 200
with `poller.healthy: true`, and `POST /v1/admin/pause` **without** `x-api-key` returns 401/403.

### Production posture — key in Vault

The key is generated inside Vault and **never leaves it**. The signer sends a 32-byte preimage and
receives a signature; compromising the signer does not yield the key.

1. Create the ed25519 transit key (once):
   ```bash
   vault secrets enable transit
   vault write -f transit/keys/org-accum type=ed25519
   ```
2. Read its **public** key and derive the Accumulate key hash — the only thing that ever leaves Vault:
   ```bash
   # public_key is base64; the key page carries sha256(public_key_bytes)
   vault read -format=json transit/keys/org-accum
   ```
3. Put that key hash on your Accumulate key page — at onboarding for a new identity, or by
   [rotating](#rotate-the-signing-key) an existing page onto the Vault key.
4. Give the signer a Vault **token**, never a key:
   ```bash
   cd deploy
   $EDITOR config.vault.yaml     # signer.vault.addr / key_name; org_id; signer_url
   VAULT_TOKEN=<token> ADMIN_API_KEY=<key> docker compose -f docker-compose.vault.yml up -d --build
   ```

**Confirm:** `SR6 self-check OK` — the signer proving *on chain* that the key on your page is Vault's
public key. If it is not, it refuses to start.

**Beyond the example stack:** a real Vault cluster (not `-dev`, which is in-memory and auto-unsealed); a
scoped policy granting only `transit/sign/<key>` and read on `transit/keys/<key>`; a short-lived token via
AppRole or Kubernetes auth; and Vault audit logging enabled — its log is then a second, independent record
of every signature you produced.

---

## Rotate the signing key

**When:** suspected compromise, staff turnover, scheduled rotation, or migrating from the pilot posture to
Vault.

**The critical point:** a submitted rotation is **not** a rotated key. Rotation must be confirmed by
reading the key page's listed key hashes. The tooling does this and refuses to report success otherwise.

### The page version is not cosmetic — it decides which mode you want

The key page's **version** is the network's key-state guard. A signature carries `signerVersion`, and
bumping the version resets the page's nonces, invalidating signatures made at the old version. Accumulate's
two rotation transaction types treat it differently, deliberately:

- **`UpdateKey`** — stores the update but does **not** change the page version. The key hash is swapped in
  place, nonces are not reset, and **signatures already made at the current version remain valid.**
- **`UpdateKeyPage`** — advances the version and resets all nonces, so **old-version signatures become
  invalid.**

**Consequence: for a compromised key, use `update` — not the default `updateKey`.** `updateKey` removes the
attacker's key from the page but does nothing about whatever they already signed at the current version.

### Choosing a mode

| Mode | Transactions | Version | Downtime | Use when |
|---|---|---|---|---|
| `updateKey` *(default)* | 1, atomic | unchanged | brief — restart onto the new key | **Routine, scheduled rotation.** Simplest; no window where the page holds both keys or neither. |
| `update` | 1, atomic | +1 (nonces reset) | brief | **Suspected compromise.** Also the right form when replacing one entry of a multi-key page. |
| `add-then-remove` | 2 | +2 | none | **Zero-downtime** planned migrations, e.g. pilot key → Vault. The page briefly holds both keys, so you bring the signer up on the new key *while the old one still works*, confirm it signs, then remove the old key. **Not for a compromised key** — it leaves the attacker's key valid throughout the window. Requires the page threshold to tolerate the extra key. |

### Suspected compromise — do this first, ask questions after

```bash
curl -XPOST -H "x-api-key: $ADMIN_API_KEY" localhost:8080/v1/admin/pause    # stop signing NOW
npx tsx scripts/rotate-key.ts --config <cfg> --new-vault-key org-accum-v2 --mode update
```

`--mode update` bumps the page version, resetting nonces and invalidating signatures the attacker may
already have produced. Then repoint the signer at the new key, restart, confirm `SR6 self-check OK`, and
resume.

Afterwards, **audit the receipts** in your state file against your policy engine's own log, and look for
any decision you did not expect. This is exactly what the receipts exist for.

### Routine rotation

```bash
# The tool reads the SIGNER'S config, so it signs with whatever posture is deployed (local or Vault).
npx tsx scripts/rotate-key.ts --config deploy/config.pilot.yaml --new-seed-hex <new 64-hex seed>

# Vault → Vault: create transit/keys/org-accum-v2 first, then:
npx tsx scripts/rotate-key.ts --config deploy/config.vault.yaml --new-vault-key org-accum-v2
```

It prints the page's current keys, asks for confirmation, submits, and **polls the page until the new key
hash is listed and the old one is gone**. It refuses to start if the current key is not on the page (you
could not sign the rotation) or if the new key is already there.

Then point the signer at the new key and restart:

- pilot: write the new seed to `deploy/signer-seed.txt`
- Vault: set `signer.vault.key_name: org-accum-v2`

**Confirm:** the signer boots and logs `SR6 self-check OK`. That is the real check — if the new key is not
the one on the page, it refuses to start rather than casting votes the network will reject.

### Zero-downtime rotation

```bash
npx tsx scripts/rotate-key.ts --config <cfg> --new-seed-hex <new seed> --mode add-then-remove
```

The tool adds the new key, confirms **both** are live, then removes the old one. For a true no-gap
cutover, run it in two halves: add the key; switch and restart the signer onto it; verify it signs a real
transaction; only then remove the old key.

**Never remove the old key until the page confirms the new one is listed.** If the rotation tool reports
failure, the old key may still be the only valid one — leave it in place and investigate.

### Rotating without shell access

`POST /v1/admin/key-page` performs the same operations over HTTP, gated by a **governance-admin
credential** that is separate from the admin API key, and unset (therefore 403) in every shipped config.

```bash
curl -XPOST localhost:8080/v1/admin/key-page \
  -H "x-api-key: $ADMIN_API_KEY" -H "x-governance-key: $GOV_KEY" \
  -d '{"op":"rotate-key","newKeyHash":"<64hex>","mode":"update"}'
# also: {"op":"add-key"|"remove-key","keyHash":…} and {"op":"set-threshold","threshold":N}
```

The signer **builds the transaction itself**, forces the principal to its own key page, signs what it
built, and confirms the change on chain before responding. It refuses to remove a page's last key or set a
threshold that could never be met.

There is deliberately **no endpoint that signs an arbitrary hash.** An earlier build had one; blind signing
means the signer cannot know what it authorized, and "sign these 32 bytes" could be any transaction at all,
including one moving your funds. The worst a stolen governance credential can now do is reorganize your own
key page — still serious, still audited, but bounded.

---

## Emergency stop

```bash
curl -XPOST -H "x-api-key: $ADMIN_API_KEY" localhost:8080/v1/admin/pause
curl -XPOST -H "x-api-key: $ADMIN_API_KEY" localhost:8080/v1/admin/resume
```

Pause halts **all** signing immediately, including reject votes — a reject is still a signature, and a
paused signer that goes on submitting rejections is not paused. Pending transactions stay pending; nothing
is lost. The poller keeps discovering, so when you resume, the backlog is handled.

Requires `admin.api_key`. Without it every admin route returns 403 and **the pause is unavailable** — set
it before you need it, and verify it works during deployment rather than during an incident.

---

## Production cutover

**The problem:** everything is proven on a test network. A production network differs in ways that matter —
real value to buy credits, a different credit oracle price, real money at risk, and no faucet to bail you
out.

1. **Key first.** Generate the key in Vault. Do not create a production identity with a key that has ever
   existed outside Vault.
2. Provision your identity, key book, and key page with the Vault key's hash. **Fund the page with
   credits** — the signer cannot vote without them, and it warns at boot when the page has none.
3. Point `wallet.accumulate_endpoints` at your production node.
4. **Set `behavior.value_ceiling`.** On a test network an over-value bug is embarrassing; in production it
   is a loss. It gates every amount, as a big integer.
5. **Deploy paused.** Start the signer, confirm `SR6 self-check OK`, then pause before any real transaction
   exists. Unpause only after watching a full poll cycle.
6. **Rehearse the incident path before you need it:** pause, resume, and rotate against a throwaway page on
   the production network.

**Confirm:** one real, low-value transaction end to end — discovered → decision → vote → executed. Then
check the stored receipt matches what your policy engine's own log says it decided.

---

## Backup and restore

**What the state is:** `store.path` holds the signing history — which transactions have been voted on,
which is what prevents double-voting — and the **receipts**: what was decided, why, and your engine's
evidence.

> Deleting this volume does not clear a cache. It destroys the record of every decision you have made,
> and lets the signer re-vote everything still pending.

**Backup:** snapshot the volume, or just copy the file. Writes are atomic (temp file, fsync, rename), so a
copy taken at any moment is a valid, complete state.

```bash
docker compose exec -T signer cat /data/signer-state.json > backup-$(date +%F).json
```

**Restore:** stop the signer, put the file back, start it. A corrupt file makes it **refuse to start**
rather than silently beginning with an empty history.

### The growth limit, stated honestly

`FileStore` rewrites the whole file on every mutation. At pilot volume — tens to hundreds of transactions —
this is irrelevant. In the thousands it is not: each vote costs an O(n) rewrite. There is currently no
compaction and no retention policy.

**Trigger to act:** state file over ~5 MB, or a poll cycle spending measurable time persisting.

**When it matters** (not before — it is not free):

- Move to SQLite. `Store` is a deliberately narrow interface — `get`, `create`, `update`, `saveReceipt`,
  `getReceipt`, `listNonTerminal`, `tryLock`, `unlock` — precisely so this swap stays contained.
- Retention: terminal rows (`signed`, `rejected`, `expired`) older than N days can move out of the hot
  store — but **archive them, do not delete them.** Keep receipts indefinitely. They are the audit trail.

---

## Restart and upgrade

**The constraint: exactly one signer may run against one state volume.** The single-flight lock that
prevents double-voting is in-process, so two replicas could both vote on the same pending transaction. The
Helm chart enforces this (`replicaCount: 1`, `strategy: Recreate`) and fails the render if you raise it.

**What that costs:** a restart is a brief gap in signing. It is *safe* — pending transactions stay pending,
the poller picks them up next cycle, and the durable store means nothing is re-voted — but during the gap
you are approving nothing. Size it: container start + self-check + first poll ≈ one poll interval.

**Upgrade:**

1. `POST /v1/admin/pause` — stop signing cleanly.
2. Wait for in-flight signing to finish (watch the logs; seconds).
3. `docker compose up -d --build`, or roll the Deployment. The state volume carries history across.
4. Confirm `SR6 self-check OK` and `/healthz` 200 with `poller.healthy: true`.
5. `POST /v1/admin/resume`.

---

## Release checks

Run before shipping a change. CI covers the offline tiers on every push; the live suites need a funded
identity on a test network and are run deliberately.

```bash
npm run typecheck
npm test                                   # the offline suite
npm run test:vault                         # the production key path (boots a dev Vault)
docker build -t certen/external-policy-signer .

# live, against a test network — see scripts/verify/README.md
npx tsx scripts/verify/deployed-container.ts   # the shipped container signs, end to end
npx tsx scripts/verify/vault-custody.ts        # a Vault-held key signs; no private key in process
npx tsx scripts/verify/key-rotation.ts         # all three rotation modes, confirmed on chain
npx tsx scripts/verify/concurrency.ts          # concurrent transactions, each voted exactly once
npx tsx scripts/verify/resilience.ts           # refuse-boot, engine-down recovery, pause, HMAC
npx tsx scripts/verify/faults.ts               # insufficient credits, expiry
```
