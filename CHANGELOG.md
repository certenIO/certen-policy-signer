# Changelog

Versions follow [semver](https://semver.org). For this package a **breaking change** means any of:

- a change to the policy decision contract (the request fields, the reply shape, or what a reply causes);
- a config key removed or given a different meaning — a *new optional* key is not breaking;
- an HTTP route removed, or one that starts requiring authentication it did not before;
- a change to what gets signed, or to the conditions under which a signature is withheld.

Anything in that list appears here with a migration note before it ships in a release.

## Unreleased

### Added

- **Outbound notifications, with the channels built in.** `notify.sms` (Twilio or compatible),
  `notify.email` (SendGrid), `notify.slack`, and `notify.webhook` — any combination, each a single HTTPS
  POST, no new dependencies. Six events: `pending.discovered`, `decision.approved`, `decision.denied`,
  `signature.failed`, `signer.paused`, `signer.resumed`. SMS and email default to the two a human must act
  on, since they are metered and interrupt someone; webhook and Slack get everything. Off unless
  configured. Delivery is best-effort by design and can never delay or change a signing decision — the one
  subsystem here that does not fail closed, for the reason given in `src/notify.ts`.
- **Policy adapters.** `policy.adapter_module` points the signer at an approvals API you already run,
  reshaping the request, the response, or both, instead of making you deploy a translating shim. The
  fail-closed rule is enforced around the adapter rather than delegated to it: only `approve`/`deny`/
  `pending` count as decisions, the response MAC is verified before the adapter's parser sees the body, and
  an adapter that throws withholds. A module that fails to load, or defines neither method, stops the boot.
  Worked example: `examples/policy-adapter.mjs`.
- **Per-scope `policy` and `behavior`.** A scope in `wallet.scopes[]` may override either block, stating
  only what differs from the top-level defaults; what it does not state, it inherits field by field. Each
  overriding scope gets its own policy client, credential, and value-ceiling guard, so one agent's engine
  being unreachable stalls that page alone and a leaked per-agent secret does not authorize decisions for
  the rest. This is what makes a fleet with divergent rulebooks expressible in one process. Overrides are
  `.strict()`: an unknown key stops the boot rather than silently meaning "inherit". `policy.auth` is
  validated on the *merged* result, so a scope cannot downgrade itself to an unauthenticated channel.
  Duplicate pages in `scopes[]` and non-numeric `value_ceiling` values are now startup errors too.
- **`GET /v1/requests?status=`** — filter the audit view by request status, comma-separated. Filtering
  happens before the limit, so `?status=awaiting_policy` is a usable work queue on a busy signer. An
  unknown status is a 400 rather than a silently ignored filter.
- **`config.minimal.yaml`** — the five fields that have no default, which is the whole required config.
- **`docs/PRIMER.md`** — Accumulate and Certen for readers with no blockchain background.
- **`docs/PATTERNS.md`** — the four deployment shapes (single-org gate, M-of-N panel seat, many identities
  in one process, delegated authority), each with a config skeleton. The rest of the docs assume the first.
- **`docs/README.md`** — documentation index, in reading order.
- **Console: "Waiting on a decision" panel** — the work queue, with how long each item has been waiting.
- **Per-scope discovery health.** `/healthz` gains a `scopes[]` breakdown (page, healthy, lastSuccess) and
  names stalled pages in `reasons` as `poller_stalled:<page>`. Present only when more than one page is
  watched — on a single-scope signer the aggregate already is the answer. On a fleet the aggregate boolean
  was not actionable: twelve agents reported as one value, so an operator learned that discovery stopped but
  not which agent stopped.
- **Console: fleet awareness.** A **Page** column on both decision tables, a page filter scoping every
  table, and a per-page discovery table in the status panel (stalled first). All three appear only when the
  signer watches more than one page, so a single-scope console is unchanged.

### Changed

- **Container images published to `ghcr.io/certen/certen-policy-signer`**, multi-arch, with provenance and
  an SBOM, via a `release` workflow triggered by a version tag. Docker is the primary artifact: this process
  holds a signing key, and the image is what carries the posture that needs — pinned runtime, non-root user,
  declared state volume, healthcheck, seed as a mounted file. Compose and the Helm chart now default to the
  published image and accept a **digest** (`SIGNER_IMAGE=…@sha256:…`, `image.digest`), which a tag cannot
  guarantee. The release workflow refuses to publish if the git tag and `package.json` version disagree,
  and smoke-runs both the built image and the packed npm tarball before publishing either.
- **Published to npm as `certen-policy-signer`.** The package was `private` and installable only by cloning.
  `certen-external-policy-signer` remains as a `bin` alias, so existing deployments are unaffected. npm is
  for evaluation and embedding; it provides none of the custody posture above.
- **The accumulate.js patch moved from `postinstall` to `prepare`.** npm runs `postinstall` for installed
  dependencies, so consumers of the published package saw it fire in their tree, find nothing to patch, and
  print a warning that read like a broken install. `prepare` runs on a local install and before publish, but
  not on a registry install — correct, because the published bundle already contains the patched code.
  No behavioral change in a clone or in Docker.

## 0.1.0

First pilot release.
