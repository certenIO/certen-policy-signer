# Changelog

Versions follow [semver](https://semver.org). For this package a **breaking change** means any of:

- a change to the policy decision contract (the request fields, the reply shape, or what a reply causes);
- a config key removed or given a different meaning — a *new optional* key is not breaking;
- an HTTP route removed, or one that starts requiring authentication it did not before;
- a change to what gets signed, or to the conditions under which a signature is withheld.

Anything in that list appears here with a migration note before it ships in a release.

## Unreleased

### Changed (breaking: pause)

- **The emergency pause is persisted and names a seat and a reason.** `POST /v1/admin/pause` and `/v1/admin/resume` now take
  `{"by":"seat:<name>","reason":"<at least 10 characters>"}` (a call without them is refused with `seat_required` or
  `reason_required`; before, a body-less call paused everything). `scope` (`seat` or `subject`) and `id` narrow it; without them
  it acts on every configured seat. The pause is written to disk before the call returns, read again before every signature (a reject
  vote included) and survives a restart (`pause-state.json` and a hash-chained `decision-journal.jsonl` beside `store.path`; without
  `store.path` it stays in memory). `GET /v1/admin/pause` shows who paused and why. Migration: add the body to every pause and resume
  call, the operator console now asks for both.
- **Receipts are append-only.** A second receipt for one unit of work is a second record (`getReceipt` is still the latest,
  `getReceipts` lists all) with a store-wide `seq` and `recordedAt`; a state file with a gap in `seq` refuses to start.
- `Receipt` gains `seq`, `recordedAt` and `binding`; `Decision` gains `record` (a Console that copies `src/types.ts` must re-sync).

### Added

- **G-69: human-only seats.** `wallet.human_scopes[]` runs a seat for a page with NO machine key: polled
  (account and header authority), resolved, stored and decided like a keyed scope, but never signed by this
  process. A decision that needs a signature is recorded with the new status `awaiting_human` (receipt and
  evidence kept); a person signs it through officer intake, and the landed signature ends the request
  (`signed` / `rejected`, with `signedBy`). The page must be in `officer_intake.human_pages` and may not also
  be a keyed scope. New request status `awaiting_human` (non-terminal).

- **AWS KMS Ed25519 in the `cloud-kms` key source.** An AWS key with `KeySpec: ECC_NIST_EDWARDS25519` now
  signs as `ed25519` (pure EdDSA over the preimage: `ED25519_SHA_512`, `MessageType: RAW`), with the raw
  32-byte public key (key hash = sha256 of it) and a local verification of every signature. The algorithm
  is read from the key's own `KeySpec`; any spec other than `ECC_NIST_P256` / `ECC_NIST_EDWARDS25519` is
  refused. The P-256 path is unchanged. `CloudKmsSigner.signatureType` is the key's own type once it has been read; for an AWS key it
  throws until then (as the Windows certificate-store signer does), so a guessed type can never reach signature
  metadata. Azure and GCP hold P-256 only and report `ecdsaSha256` from the start.

- **G-64: why a seat is holding is kept.** When the policy engine answers `pending`, the request record
  now stores `pending: { reason, versions: { ruleSetVersion, providerConfigVersion, signerConfigVersion },
  since, lastEvaluatedAt, evaluations, history[] }` (history: up to 20 distinct reasons, oldest dropped),
  updated on each re-evaluation and moved to `pendingFinal` (with `endedAt`, `outcome`) when the request
  is decided or goes away. Only the reason text (sanitised, length-capped, credential-shaped substrings
  redacted) and the three version stamps are stored -- never the decision's evidence. Persisted by the
  FileStore. Exposed on `GET /v1/requests` rows and at the top level of `GET /v1/requests/:tx`.

- **Rotation-safe reader, read cache and chain relay routes (DAX-4S round 2).** The Grant head and the subject are read by the core's ONLINE
  readers (no key page; the account authority rule and the account's main chain from its creation), the subject only through the
  grantor's registry and its own `certen-acceptances`. `binding.registry_principals` is REMOVED (nothing to list) and `binding.grantor_book`
  is required with `grantor_adi`. All node reads go through a cache keyed by account and main-chain length with a hard TTL of at most 30
  seconds, bounded concurrency and back-off (`reader` block). Relay clients with scope `chain` get GET `/relay/data|authorities|history|keybook/:account`.
  `PolicyRequest.binding` carries the ten members of the request to bind (a seat that requires binding only). `legCount` is derived from
  the legs and always supplied (a two-leg intent is `multi_leg_unsupported`). The request mapping refuses what the strict decoder refuses
  (checksum-case addresses, a missing 0x, a dirty address word). Pausing what is paused answers 200 `status: already_paused`.
- **`PolicyRequest.execution` (DAX-4S round 5, DAX7C-F1).** The bound request carries no calldata and no native value, so a decision service could
  not decode what executes. The request now also carries `execution` {chainId, source, target, value, calldata}, a SIBLING of `binding`, for a
  one-leg intent that maps to the ten request members (omitted, never null, otherwise). The signer authenticates it first: the core's single-call
  commitment keccak(chainid, target, value, keccak(calldata)) over it must equal the intent's stated `executionCommitment`; a mismatch sends no
  `binding` and no `execution` and a decision for it is refused `presented_malformed` (`execution_commitment_mismatch`). This tightens round 1's
  "the commitment is taken as stated": an intent whose stated commitment is not the single-call commitment of its own bytes is now refused.
  The shared core copy moves to 4ff146c (adds calldata-keccak, calldata-registry, calldata, calldata-display; the other 19 files are unchanged).
  A Console that copies `src/types.ts` must re-sync (`PolicyExecution`, `PolicyRequest.execution`).
- **`binding` carries `legCount` and the intent's `grantRef` (DAX-4S round 4).** `PolicyRequest.binding` had the ten members of the request hash and
  no `legCount`, and was sent for a one-leg transaction only, so a Console that requires `legCount` (DE-76) held every real request. It now
  always carries `legCount`, is sent for a several-leg intent too (the decision service refuses it by name, `multi_leg_unsupported`) and
  forwards blob 0 `grantRef` {grantId, version, grantHash} when the intent names a Grant. No `leafExpiry` is sent (no carrier on the wire).
  A Console that copies `src/types.ts` must re-sync (`PolicyBinding.legCount`, `PolicyBinding.grantRef`).
- **Reader settled on the real node (DAX-4S round 3).** A data entry has no timestamp on Accumulate v3: the reader now takes the entries of a
  data account from its MAIN chain (the data-chain query collapses byte-identical entries onto the later transaction) and dates each by the
  time of the minor block in `value.received` (one query per distinct block, remembered). `lastBlockTime` is no longer read as an entry time.
  `GET /relay/keybook/:book` now answers `{ pages:[{ url, keyHashes, delegates, threshold }] }` (delegate seats included; the quorum roster of
  the Console) and `GET /relay/chainlen/:account` answers `{ length }`. The shared core copy is at d9082fa (`block-time.ts`, `main-chain-entry.ts`).
  Read-only precheck on Kermit: head v3 and subject resolved, 20 node queries cold, 4 steady state (`scripts/verify/reader-live-precheck.ts`).
- **Decision binding (DAX-4S).** `binding` (top level or per scope) makes the signer accept a decision only when its certen.decision/v1
  `record` names the exact transaction about to be signed (the request hash is recomputed from the transaction, with the validator
  operation id recomputed from its four blobs), an authorised approver identity, this seat, the pinned policy hash, the head of the
  Grant (read from Accumulate, never the producer's claim) with its subject, and a nonce not used before. The nonce is journalled
  before the signature is made, so a replay inside the old 300-second window, after a restart or after a crash is refused. A refusal is
  named in the receipt and signs nothing. `POST /v1/admin/decisions/void` voids the nonces of a re-issued decision. The shared core
  (`src/core`) is a byte-for-byte copy of transaction-controls `packages/core`: `node scripts/sync-core.mjs`, `test/core-drift.test.ts`.

- **Human-only seats are seats (G-69 with DAX-4S).** A `wallet.human_scopes[]` entry takes the same `seat` and `binding` members as a
  `scopes[]` entry and is listed with the keyed seats: a top-level `binding` binds it, a pause with no scope pauses it, and its seat id
  can be named. A decision for a human-only seat that requires binding is checked (and its nonce consumed) before it is recorded as
  `awaiting_human`, and the receipt of that record carries the same `binding` members as a signed one; a replay, a mutated request or an
  unbound reply is refused by name and records nothing. A paused seat records no `awaiting_human` either. A human-only page and
  `attachment_model: wrapper` together are refused at boot: a wrapper vote travels a delegation path, a human-only page has none.
  Record keys: a human-only seat's records are keyed `<txHash>@<page>` (`recordId`), a wrapper path's `<txHash>:<path>` (`workKey`); the
  store files a row under `workKey ?? recordId ?? txHash`. `GET /v1/requests/<hash>:<path>` and `<hash>` both work.

- **Phase 8 key sources (FICTIONAL Business Transaction Controls lab).** `signer.provider: pkcs11` signs
  with a key in a PKCS#11 token: Ed25519 via `CKM_EDDSA`, P-256 via `CKM_ECDSA` with the output converted
  to DER. The key must be non-extractable and sensitive. The PIN is either process-held or released per
  signature by a PIN custodian (`pin_source`). `signer.provider: cloud-kms` signs with a P-256 key in AWS
  KMS, Azure Key Vault or Google Cloud KMS. `KeySigner.sign` takes an optional transaction context
  (`txHash`, `principal`, `page`), which existing providers ignore. A key source that throws while signing
  now makes the vote backend return `signing failed: …`; before, the exception propagated. Either way no
  signature is produced. See docs/KEY-SOURCES.md. `npm run test:pkcs11` (SoftHSM2) and `npm run test:kms`
  (LocalStack) exercise the real backends.

- **Phase 6 seat contract (FICTIONAL Business Transaction Controls lab).** ABI pins (`decoders.evm_abi[]`,
  `decoders.labels`) with a strict built-in ABI decoder; new PolicyRequest fields `bodyType`,
  `configVersion`, `assets`, `selfCall`, `targetKnown`, `governance`, `acceptance`; `configVersion` on
  every Receipt and at `GET /v1/config/version`; per-decision-service relay `/relay/*`
  (`admin.relay_clients[]`); built-in `governance` decoder.
  **Breaking (decision contract):** for a CERTEN intent `calldataDecoded` is now an array with one entry
  per contract-call leg (`{ legIndex, chainId, target, abi, function, signature, args }`) instead of a
  string, and is present for undecodable calls too (with `function: ""`). Migration: read
  `calldataDecoded[i].function` / `.args` instead of parsing the string.

- **`subject` on the policy decision request — WHO the transaction is about.** An optional object,
  `{ adi, keyBook?, id?, assertedBy? }`, carried whenever the payload named someone; the reference
  decoder reads it from blob 0 of a Certen intent, and the subject's ADI is written onto the receipt.
  It is what lets an engine holding a per-user binding — a biometric re-auth, an MFA enrolment — route a
  decision to the right enrolled person: `account` is the organisation's data account and `operationId`
  is per operation, so nothing on the request previously named a human.

  **Not breaking.** The field is optional at every layer. An engine that ignores it behaves exactly as
  today, and an intent that names nobody produces a request with **no `subject` key** — absence and
  "unknown" are the same wire state, and the signer never invents one.

  Two things an engine must be told, both documented in
  [`docs/INTEGRATION.md`](docs/INTEGRATION.md#who-the-transaction-is-about): the subject is an
  **assertion by the intent producer, not a proof by the user it names**, so pin `account` — the one
  field a submitter cannot forge — to a customer you have a relationship with; and if your engine
  requires a subject and does not get one it must return an explicit `deny`, because throwing merely
  withholds and looks identical to an outage. `docs/PATTERNS.md` pattern E and
  `examples/policy-engine.mjs` (`POLICY_MODE=subject`) show both.

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

- **SP-10: a submit with no answer is decided from the chain.** Officer intake (transaction refs as well
  as proposals), the machine vote and governance read the transaction's signature set for their own
  signature after a submit error and act on it (landed / absent / unknown); a timeout is never recorded as a
  refusal. New `wallet.submit_timeout_ms` (default 15000, unchanged) and `wallet.submit_outcome_timeout_ms`
  (default 30000). `SubmitResult.uncertain` marks a submit that got no answer. Officer intake answers
  `502 submit_outcome_unknown` (`onChain: "unknown"`) when it cannot tell.

- **cloud-kms review #10.** An AWS key's metadata is re-read before every signature and a changed type or
  public key (a re-pointed alias) is refused; the declared type never follows the alias. One extra
  `GetPublicKey` per signature. The previous "type changed" check could never fire and is gone.

- **G-65 review #5.** A reject/response threshold already above the entries (a v1 executor never lowers
  them) no longer blocks every key-page change: only a change that creates or worsens one is refused, so a
  rotation or a repair on such a page passes. The accept-threshold rule is unchanged.

- **G-69 review fixes.** A human-only seat's request is keyed by transaction AND page, so it never
  pre-empts a keyed seat acting on the same transaction (`GET /v1/requests/:tx` lists all as `seats`), and
  human-only pollers no longer take the gateway pending list. `awaiting_human` ends only when the page's
  accept (or reject) threshold is met by distinct seats on chain, read on every poll as well as when a
  signature lands; partial signers are kept (`humanSignatures`). A vote opposite to the one owed is flagged
  (`humanOverride`). `ChainSignature` gains `vote`.

- **G-39 (signer half): officer-intake prepares and proposals survive a restart.** They are kept in the
  store (MemoryStore / FileStore: new `saveIntakeRecord` / `deleteIntakeRecord` / `listIntakeRecords`) and
  restored by `OfficerIntake.restore()` at startup, with expiry and single use intact (a prepare is deleted
  from the store before its signature is checked; a failed write refuses). A submit that errors is checked
  against the chain before a proposal is given back; a proposal transaction on chain stays `submitted` /
  `landed`, and one whose fate cannot be read stays `submitting` until a later read settles it.

- **G-47: the gateway vote backend signs only a preimage it built itself.** It rebuilds the Accumulate
  signing preimage (buildPreimage, as the direct backend) from the resolved transaction hash, its own key,
  key type, page and vote, plus the gateway's signer version and timestamp, and signs that. A gateway
  `data_for_signature` that differs, an absent/empty/different `transaction_hash` (absent used to default
  to ours and skip the check), a different or missing `signer_url`, or an unusable version/timestamp is
  refused before anything is signed.

- **G-65: a key-page change that would brick the page is refused everywhere the signer touches one.**
  This changes the conditions under which a signature is withheld: the machine vote no longer approves a
  pending `updateKeyPage` whose operations, applied to the page as it reads on chain, would leave no
  entries or a threshold above the entries, or whose page cannot be read (the request stays
  `awaiting_policy`). Officer intake refuses an approve on such a change at prepare and at submit, and
  `POST /relay/governance`, `POST /relay/governance/proposal` and `POST /v1/admin/key-page` refuse it
  before anything is signed. Migration: a deployment wiring `createRelayClientsHandler` or `Orchestrator`
  itself must pass `readPage`; without it governance is refused as `page_unreadable` (fail closed).
  `PageState` gains optional `rejectThreshold` / `responseThreshold`. See docs/OPERATIONS.md.

- **Container images published to `ghcr.io/certenio/certen-policy-signer`**, multi-arch, with provenance and
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
