# Key sources: PKCS#11 tokens and cloud KMS

Phase 8 (K3) adds two `signer.provider` values. Both keep the private key where it was generated, inside an
HSM token or a cloud KMS, and both implement the same signer interface as `vault-transit`:

| | `publicKey()` | `signatureType` | `sign(preimage32)` |
|---|---|---|---|
| Ed25519 | raw 32 bytes | `ed25519` | 64-byte signature over the 32-byte preimage |
| P-256 | PKIX/SPKI DER, 91 bytes | `ecdsaSha256` | ASN.1 DER ECDSA over the preimage **as a digest** |

The preimage is already `sha256(sigMdHash ‖ txHash)` (S6). A device or KMS that signs a digest is handed
those 32 bytes. None of them is asked to hash again, because that produces a valid signature over the
wrong message, and the network then rejects it with an error that looks like a missing key.

Before a signature is returned, the provider checks it against its own public key over the exact preimage.
If a device signed with some other key, or over a re-hashed input, the provider fails at that point with
the reason named, and nothing reaches the network.

All names below (orchid-logistics, the bank, token and key labels) are **FICTIONAL**.

## `pkcs11`: an HSM, a smartcard, or SoftHSM

```yaml
signer:
  provider: pkcs11
  pkcs11:
    module: /usr/lib/softhsm/libsofthsm2.so
    token_label: "orchid-seat"
    key_label: "machine-orchid-logistics"
    key_type: ecdsa-p256              # or ed25519
    pin: "env:PKCS11_PIN"             # EITHER a process-held PIN (the party hosts its own signer, Mode 1)
    # pin_source:                     # OR a per-signature PIN from the key holder's cell (Mode 3)
    #   url: "http://pin-custodian:8080/v1/pin"
    #   hmac_secret: "env:PIN_CUSTODIAN_HMAC"
    #   timeout_ms: 5000
```

- **Mechanisms.** Ed25519 uses `CKM_EDDSA` over the preimage. P-256 uses `CKM_ECDSA` over the preimage,
  which is the digest. The raw `r ‖ s` result is converted to DER.
- **Key lookup.** The provider needs exactly one token with `token_label`. It then looks for exactly one
  public key and one private key with `CKA_LABEL = key_label`; the private key must have `CKA_SIGN`.
  `CKA_KEY_TYPE` must match `key_type`, and for P-256 `CKA_EC_PARAMS` must be prime256v1.
- **Refusal.** The provider refuses a private key unless the token reports `CKA_EXTRACTABLE = false` and
  `CKA_SENSITIVE = true`.
  - With `pin`, this check runs at startup: the SR6 self-check reads the public key, which logs in, checks
    and logs out. A key that fails stops the boot.
  - With `pin_source` there is no PIN at startup, and a token hides private objects until login. So startup
    checks the token and the public key. The private-key check runs after every login, before the token is
    asked to sign. A failing key never signs.
- **One session per signature, in both modes.** The provider opens a session, gets the PIN (from the
  custodian for `pin_source`), then runs `C_Login`, sign, `C_Logout` and closes the session. No session
  stays logged in between votes. PKCS#11 login state belongs to the application rather than the session,
  so signatures on one module run one at a time.
- **Credentials.** `pin` and `pin_source.hmac_secret` must be `env:` references. A literal value in the file
  refuses the boot, as does a reference to an unset variable.
- **`health()`** checks that the token and key are there. It never signs and never asks the custodian.

### `pin_source` and the PIN custodian (custody Mode 3)

For every signature the provider sends an authenticated request that names the transaction:

```
POST {url}
x-pin-auth: t=<unix ms>,v1=<hex hmac-sha256(hmac_secret, t + "." + body)>
{"txHash","principal","page","keyLabel","ts","nonce"}
```

The custodian answers `200 {"pin"}` or `403 {"reason"}`. It runs in the key holder's cell and releases the
PIN only for a transaction its own party approved (contract §2). **The custodian gates each PIN release on
the party's approval.**

> **What Mode 3 does not stop.** A SoftHSM token has one static user PIN. The bank controls the signer
> process, so a compromised or dishonest host can keep the PIN after a single release. Holding the token
> files, it can then sign without asking the custodian, or attack the token offline. The custodian cannot
> detect or prevent either. Protecting each individual use needs a per-signature credential, or an HSM
> that enforces party-authorised use: for example, a PIN the custodian rotates after every release, or an
> HSM key-use-authorisation mechanism. Until then Mode 3 is the weaker mode, as its label says.

**The provider fails closed.** Any of these produces no signature: a refusal, a timeout, a redirect
(`redirect: error`), a 5xx, a body that is not JSON, or a 200 without a PIN. The vote path records it as
`signing failed: …` and withholds the vote. The error carries only the custodian's `reason`, sanitised and
truncated, never the response body. A `pin_source` provider asked to sign without a transaction context
refuses.

**The PIN is never logged or cached.** Tests assert that it appears in no log line and no error message.
The raw response bytes are overwritten once the PIN has been read out.

> **Limit.** The PIN also exists briefly as a JavaScript string, which is the type pkcs11js `C_Login` takes.
> A JS string cannot be overwritten in place. It becomes unreachable once the signature is made, and the
> garbage collector reclaims it later. Only the response buffer is zeroed deterministically.

### The native addon: built explicitly, never by an install script

`pkcs11js` is an **optional** dependency, pinned to `2.1.6` in the lockfile by integrity. Installs use
`npm ci --ignore-scripts`, so the addon is not compiled by an install. Without the compiled addon the
provider refuses to start with a message pointing here. The addon is compiled by one script,
`scripts/build-pkcs11js.sh`, which runs only in the image build (`Dockerfile`) and the SoftHSM test image
(`test/docker/softhsm/Dockerfile`). These files were read before the build was trusted:

- **`package.json`.** Version 2.1.6 has no `preinstall`, `install` or `postinstall` script. Its `prepare`
  (`node-gyp configure build`) does not run for a registry dependency. Because a `binding.gyp` exists, npm
  would still run an implicit `node-gyp rebuild` on install, and `--ignore-scripts` suppresses that.
  Version 2.1.7 (2026-07-28) differs from 2.1.6 only in `package.json`: it adds an explicit
  `install: node-gyp rebuild` and bumps nyc. Its sources are identical, and the pin stays on 2.1.6.
- **`binding.gyp`.** One target, `pkcs11`, built from `src/dl.cpp`, `src/common.cpp` and `src/main.cpp`.
  `main.cpp` includes `const.cpp` and `pkcs11.cpp`, which includes `params.cpp` and `worker.cpp`. It uses
  the `includes/` directory (the OASIS PKCS#11 headers) and defines `NAPI_DISABLE_CPP_EXCEPTIONS`. There are
  no actions, downloads or extra libraries; the target builds against Node-API only.
- **`index.js`.** `require("./build/Release/pkcs11.node")` and `node:util`, plus error wrapping.

The script checks that the installed version is exactly 2.1.6. It then runs the `node-gyp` bundled with
the image's npm, with `--nodedir` pointing at the headers already in the `node:20` image, so the build
fetches nothing. It finishes by loading the addon once. In the runtime image only `index.js`,
`package.json` and `build/Release/pkcs11.node` are copied beside the bundle, where `pkcs11js` is external.
The code loads the package with a dynamic `import('pkcs11js')` rather than `createRequire`.

## `cloud-kms`: AWS KMS, Azure Key Vault, Google Cloud KMS

P-256 only. Every vendor adapter refuses a key that is not a P-256 signing key **before** anything is
signed. It normalises the signature to strict DER, where non-minimal encodings are refused, and verifies it
locally.

```yaml
signer:
  provider: cloud-kms
  cloud_kms:
    vendor: aws                     # aws | azure | gcp — and only that vendor's block may be present
    aws:   { region: "us-east-1", key_id: "alias/machine-orchid", endpoint: "http://kms-orchid:4566" }
    # azure: { vault_url: "https://orchid.vault.azure.net", key_name: "machine-orchid", key_version: "7f1c…", access_token: "env:AZURE_KV_TOKEN" }
    # gcp:   { key_version_name: "projects/orchid/locations/europe-west1/keyRings/tcl/cryptoKeys/machine/cryptoKeyVersions/1", access_token: "env:GCP_KMS_TOKEN" }
```

| Vendor | Public key | Refused unless | Sign | Returns |
|---|---|---|---|---|
| **AWS** (`@aws-sdk/client-kms`) | `GetPublicKey`, SPKI DER | `KeySpec = ECC_NIST_P256`, `KeyUsage = SIGN_VERIFY`, offers `ECDSA_SHA_256` | `Sign`, `MessageType: DIGEST`, `ECDSA_SHA_256` | DER |
| **Azure** (REST, `fetch`) | `GET /keys/{name}/{version}`, JWK → SPKI | `kty` EC/EC-HSM, `crv` P-256, `key_ops` has `sign`, enabled, `kid` is the pinned version | `POST …/sign` with `alg: ES256`, value = digest | raw `r ‖ s` → DER |
| **GCP** (REST, `fetch`) | `GET {version}/publicKey`, PEM | `algorithm = EC_SIGN_P256_SHA256`, `pemCrc32c` holds, `name` is the configured version | `POST {version}:asymmetricSign` with `digest.sha256` and `digestCrc32c` | DER; `verifiedDigestCrc32c` and `signatureCrc32c` must hold |

- **AWS credentials** come from the SDK's default provider chain: environment, web identity, an instance
  or task role. `endpoint` is for LocalStack or a VPC endpoint.
- **Azure and GCP** take a bearer token as an `env:` reference. Without one they use the platform identity:
  the Azure managed identity (IMDS), or the GCE/GKE metadata server. The Azure `key_version` is required
  because a floating "latest" would let a rotation in the vault silently change the key on the page.
- **Custody Mode 2.** The credential is issued by the **party's own** cloud account to an independent
  operator. The party can revoke it, and the bank never holds it.

## Tests

| Command | What runs |
|---|---|
| `npm test` | Every host, no Docker. DER↔raw helpers both ways against `@noble/curves`. The pkcs11 provider against an in-memory token: the call order around each signature, custodian refusal (no login, no signature, vote withheld), extractable and non-sensitive refusal, config rules. The PIN custodian client. Azure and GCP contract tests against recorded fixtures in `test/fixtures/cloud-kms/` (public API shapes, test-generated keys, no credentials). The SoftHSM and LocalStack suites skip. |
| `npm run test:pkcs11` | Builds `test/docker/softhsm` (node:20-bookworm, `softhsm2`, the explicit addon build) and runs it with `--network none`. `run.sh` generates throwaway PINs inside the container and initialises the token. `provision.mjs` generates the keys inside it. The Ed25519 and P-256 signatures verify by S6, extractable and non-sensitive keys are refused, `pin_source` works with a custodian stub, a refusal produces no signature, and the PIN appears in no log. |
| `npm run test:kms` | Starts `localstack/localstack:4.4.0` (kms) on host port 15466. The test creates the keys inside LocalStack, signs, verifies by S6, and checks refusal of `ECC_SECG_P256K1` and symmetric keys. The container is removed afterwards. |

CI runs the last two as the `pkcs11` and `kms` jobs.
