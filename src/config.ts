/** Config load + validation. Every field is documented in config.example.yaml; secrets use `env:NAME` refs. */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve as resolvePath } from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';
import { NOTIFY_EVENTS } from './notify.js';

/** Event names as a zod enum source — derived from the one list in notify.ts so the two cannot drift. */
const NOTIFY_EVENT_NAMES = NOTIFY_EVENTS as [string, ...string[]] as unknown as readonly [
  'pending.discovered', 'decision.approved', 'decision.denied', 'signature.failed', 'signer.paused', 'signer.resumed',
];

/** Resolve the local signer's 32-byte seed from `seed_hex` (already env-resolved) or a mounted `seed_file`. */
export function resolveLocalSeed(local?: { seed_hex?: string; seed_file?: string; allow_ephemeral?: boolean }): Uint8Array | undefined {
  const raw = local?.seed_hex ?? (local?.seed_file ? readFileSync(local.seed_file, 'utf8') : undefined);
  if (raw === undefined) return undefined;
  const hex = raw.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('local signer seed must be 64 hex chars (32 bytes) — is the env var or seed_file populated?');
  }
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Resolve an ECDSA P-256 private key from `private_key_der_hex` (already env-resolved) or a mounted
 * `private_key_der_file`. Hex-encoded DER either way — SEC1 or PKCS#8, both of which real PKI tooling
 * emits — because a PEM in a YAML string is a newline-mangling accident waiting to happen.
 */
export function resolveLocalEcdsaKey(local?: { private_key_der_hex?: string; private_key_der_file?: string }): Uint8Array | undefined {
  const raw = local?.private_key_der_hex ?? (local?.private_key_der_file ? readFileSync(local.private_key_der_file, 'utf8') : undefined);
  if (raw === undefined) return undefined;
  const hex = raw.trim();
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error('local ECDSA key must be hex-encoded DER — is the env var or key file populated?');
  }
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function resolveSecret(v: string | undefined): string | undefined {
  if (!v) return undefined;
  if (v.startsWith('env:')) return process.env[v.slice(4)];
  return v;
}

// A key source — reused for the single top-level `signer` and for each multi-scope `scopes[].key`.
const SignerSpecSchema = z.object({
  // `local-ecdsa-p256` is the same in-process posture as `local`, with a PKI key type rather than
  // Ed25519. It is deliberately a distinct provider name: a seed and a DER private key are not
  // interchangeable, and a wrong guess would produce signatures the network silently refuses.
  // `windows-cert-store` is the organisation's OWN PKI: a certificate already in the Windows
  // certificate store (Microsoft ADCS-issued, or a PIV/CAC card through its minidriver). Nothing is
  // enrolled or generated and NO key material appears in config — only which certificate to use.
  provider: z.enum(['vault-transit', 'local', 'local-ecdsa-p256', 'windows-cert-store']),
  // `key_type` is what Vault holds under `key_name`. It defaults to ed25519 -- every config written
  // before Runbook F Phase F2 meant that -- and VaultTransitSigner checks the default against Vault's
  // own answer on the first read, so a wrong one refuses rather than signing with a mismatched
  // algorithm the network then rejects for reasons that read like a missing key.
  vault: z.object({
    addr: z.string().url(),
    key_name: z.string(),
    token: z.string(),
    key_type: z.enum(['ed25519', 'ecdsa-p256']),
  }).partial().optional(),
  local: z.object({
    seed_hex: z.string(),          // 32-byte hex, or an `env:NAME` ref
    seed_file: z.string(),         // path to a file holding the 32-byte hex seed (docker/k8s secret mount)
    allow_ephemeral: z.boolean(),  // dev only: generate a throwaway key when no seed is configured
    private_key_der_hex: z.string(),   // local-ecdsa-p256: hex DER (SEC1 or PKCS#8), or an `env:NAME` ref
    private_key_der_file: z.string(),  // local-ecdsa-p256: path to a file holding that hex
  }).partial().optional(),
  // windows-cert-store. Note what is NOT here: any key material. The private key stays in the
  // key-storage provider — for a card it cannot be extracted at all — so this only says which
  // certificate, and where the agent that can reach it lives.
  windows: z.object({
    thumbprint: z.string(),   // the certificate's thumbprint; spaces and case are ignored
    agent_path: z.string(),   // path to certen-cert-agent (see agent/windows-cert-store)
    machine: z.boolean(),     // read LocalMachine\My rather than CurrentUser\My
    timeout_ms: z.number().int().positive(),  // a card with a PIN prompt waits on a person
  }).partial().optional(),
});
export type SignerSpec = z.infer<typeof SignerSpecSchema>;

/**
 * Treat a null config section as an absent one.
 *
 * Commenting out every key under a section but leaving the header behind — which is what you get by
 * disabling options one line at a time — makes YAML parse the section as `null`, not as missing. Zod's
 * `.default()` only fills in `undefined`, so that produced "Expected object, received null" against a
 * file that looks entirely reasonable. An empty section means "use the defaults".
 */
function section<T extends z.ZodTypeAny>(schema: T) {
  return z.preprocess((v) => (v === null ? undefined : v), schema);
}

/**
 * The per-scope forms of `policy` and `behavior`.
 *
 * Every field optional, because these are patches over the top-level blocks rather than replacements —
 * see `effectiveScopeRules`. `.strict()` on both: a misspelled key here silently means "inherit", and the
 * failure that produces is a scope quietly running under the wrong ceiling or against the wrong engine.
 * Better to refuse the boot and name the key.
 */
const PolicyOverrideSchema = z.object({
  url: z.string().url(),
  adapter_module: z.string(),
  auth: z.enum(['none', 'hmac', 'mtls']),
  hmac_secret: z.string(),
  signature_header: z.string(),
  timestamp_header: z.string(),
  timeout_ms: z.number(),
}).partial().strict();

const BehaviorOverrideSchema = z.object({
  submit_reject_vote: z.boolean(),
  max_bad_version_retries: z.number(),
  value_ceiling: z.string(),
}).partial().strict();

export type PolicyOverride = z.infer<typeof PolicyOverrideSchema>;
export type BehaviorOverride = z.infer<typeof BehaviorOverrideSchema>;

const Schema = z.object({
  wallet: z.object({
    org_id: z.string(),
    // A free-form label for logs and dashboards only — nothing branches on it. It was an enum of two
    // public networks, which locked out devnets and private deployments for no functional reason. When
    // omitted, the endpoint's host is logged instead, so an operator can always tell where they are.
    network: z.string().optional(),
    accumulate_endpoints: z.array(z.string().url()).min(1),
    // Single-scope form (back-compat): one page + the top-level `signer` key. Optional when `scopes` is set.
    signer_url: z.string().startsWith('acc://').optional(),
    // Multi-scope form: watch several key pages, each with the key that signs there. One Poller per scope,
    // one shared orchestrator; the keyring picks the key by page. `book` is derived from `page` if omitted.
    scopes: z.array(z.object({
      page: z.string().startsWith('acc://'),
      book: z.string().startsWith('acc://').optional(),
      key: SignerSpecSchema,
      // Further keys on the SAME page, addressed by a ref this deployment chooses -- Runbook F Phase
      // F2. A key page holds several keys with a threshold, so a roster page is one page with one seat
      // per approver. `key` above stays the key this wallet signs with when nobody is named.
      //
      // The ref is an opaque label and nothing here can check it against an identity. What binds it to
      // a person is the key page entry it resolves to, which is on chain rather than in this file.
      keys: z.record(z.string().min(1), SignerSpecSchema).optional(),
      /**
       * Whose behalf this scope's key is held on. Runbook F Phase F4.
       *
       * Set it when the page is inside a PERSON's identity and the key on it is the organisation's --
       * the arrangement Runbook F 0.4 accepts so a certificate can be rotated when it expires and a
       * leaver retired. The price of that arrangement is that the same key can approve a payment in
       * her name, and this is what lets the record say so.
       *
       * DECLARED, because it cannot be inferred. A key page entry is sha256(publicKey) for every key
       * type alike, so nothing on a page distinguishes a person's certificate from a software key
       * (RESEARCH-CONSOLE-AND-SIGNER.md section 5) -- and the algorithm is a heuristic that F2 already
       * made wrong by letting the organisation hold an ECDSA key. This is not a claim about the chain;
       * it is the deployment's statement about its own key, which only the deployment can make.
       *
       * Absent means the organisation is signing as itself, which is the ordinary case and stays
       * silent. An empty string is refused: "on behalf of somebody, and we did not say who" is not a
       * state anybody meant to configure, and it would reach a screen as a blank name beside an alarm.
       */
      acts_for: z.string().min(1, 'acts_for must name the person, or be omitted entirely').optional(),
      // Per-scope overrides, MERGED over the top-level blocks of the same name. A fleet of agents rarely
      // shares one rulebook: a trading bot and a treasury page belong on different engines, under
      // different ceilings, with different secrets. State only what differs — a scope that just needs a
      // lower ceiling does not restate the policy URL.
      //
      // The top-level `policy` remains required, and is the default every scope inherits. That is
      // deliberate: a scope with a typo'd override key would otherwise fall through to NO policy engine,
      // and "no engine configured" must never be a reachable state.
      policy: PolicyOverrideSchema.optional(),
      behavior: BehaviorOverrideSchema.optional(),
    })).optional(),
    attachment_model: z.enum(['authority', 'delegate', 'per_tx']).default('authority'),
    delegator_url: z.string().nullish(),
    // SR6: refuse to start unless our public key is verifiably on the signer page. Setting this true
    // downgrades that to a warning — only for pages whose key hashes the node will not expose.
    allow_unverified_signer: z.boolean().default(false),
  }),
  // Used ONLY in single-scope mode (ignored when wallet.scopes is set).
  signer: SignerSpecSchema.optional(),
  // How a transaction body is turned into the sentence + amounts the policy engine decides on.
  // See src/decode/types.ts and docs/INTEGRATION.md §1.
  resolver: section(z.object({
    // Decoder chain, in order — FIRST CLAIM WINS, so specific decoders must precede general ones.
    // Omit to use the built-in order. Names come from the built-ins or from a loaded decoder_module.
    // The terminal `fallback` is always appended and need not be listed.
    decoders: z.array(z.string()).optional(),
    // Modules to load your own decoders from, so you never have to fork src/. Each default-exports a
    // decoder (or an array). Relative paths resolve from the working directory; bare specifiers resolve
    // as packages. Loaded decoders run ahead of the built-ins unless `decoders` states an explicit order.
    decoder_modules: z.array(z.string()).optional(),
  }).default({})),
  policy: z.object({
    // Only sync mode is implemented: the wallet POSTs the decision request and waits. `async` (engine
    // calls back to /v1/decisions later) is NOT implemented — /v1/decisions only acknowledges. Accepting
    // it here would mean running synchronously while the operator believes otherwise, so it is rejected.
    url: z.string().url(),
    // Reshape the decision call to fit an API you already have, instead of deploying a translating shim.
    // A module (path or package name) default-exporting { name, buildRequest?, parseResponse? }.
    // The fail-closed rule is enforced around it: only approve/deny/pending count, whatever it returns.
    // See examples/policy-adapter.mjs and docs/INTEGRATION.md §1.
    adapter_module: z.string().optional(),
    mode: z.literal('sync').default('sync'),
    auth: z.enum(['none', 'hmac', 'mtls']).default('none'),
    hmac_secret: z.string().optional(),
    // Header names for the signed channel. Vendor-neutral by default; point these at whatever your
    // engine already emits and expects. The legacy `x-certen-signature` is always accepted on responses
    // (never sent), so an engine written against an earlier release keeps working.
    signature_header: z.string().default('x-signer-signature'),
    timestamp_header: z.string().default('x-signer-timestamp'),
    timeout_ms: z.number().default(10_000),
    async_ttl_seconds: z.number().default(900),
  }),
  // Optional: vote through the Certen api-gateway's external-signing seam instead of submitting to
  // Accumulate ourselves. The org's key still never leaves the wallet — the gateway hands us bytes to sign.
  // Discovery and intent-decoding stay OURS either way: the gateway's pending list carries no transaction
  // body (nothing for the policy engine to gate on) and its poller does not reliably see per-tx authorities.
  gateway: section(z.object({
    enabled: z.boolean().default(false),
    url: z.string().url(),
    api_key: z.string(),                 // ck_live_… — supports `env:NAME`
    identity: z.string().startsWith('acc://'),   // the org's ADI
    signer_url: z.string().optional(),   // defaults gateway-side to the identity's key page
    timeout_ms: z.number().default(20_000),
  }).partial({ url: true, api_key: true, identity: true }).default({ enabled: false })),

  // Outbound notifications. Configure any combination of channels; absent = disabled. Every channel is a
  // single HTTPS POST, so none of this adds a dependency. Delivery is best-effort and can never affect
  // signing — the one subsystem here that does not fail closed. See src/notify.ts.
  //
  // `events` filters what a channel sends. Omitted, webhook and slack get everything, while sms and email
  // default to the two a human must act on (pending.discovered, signature.failed) because they are metered
  // and interrupt someone.
  notify: section(z.object({
    events: z.array(z.enum(NOTIFY_EVENT_NAMES)).optional(),
    webhook: z.object({
      url: z.string().url(),
      hmac_secret: z.string().optional(),
      timeout_ms: z.number().default(5_000),
      signature_header: z.string().default('x-signer-signature'),
      events: z.array(z.enum(NOTIFY_EVENT_NAMES)).optional(),
    }).optional(),
    // Twilio, or any Twilio-compatible gateway.
    sms: z.object({
      to: z.array(z.string()).min(1),
      from: z.string(),
      account_sid: z.string(),
      auth_token: z.string(),
      events: z.array(z.enum(NOTIFY_EVENT_NAMES)).optional(),
    }).optional(),
    // SendGrid.
    email: z.object({
      to: z.array(z.string().email()).min(1),
      from: z.string().email(),
      api_key: z.string(),
      events: z.array(z.enum(NOTIFY_EVENT_NAMES)).optional(),
    }).optional(),
    // Slack incoming webhook. The URL is the credential — use an env: ref.
    slack: z.object({
      webhook_url: z.string().url(),
      events: z.array(z.enum(NOTIFY_EVENT_NAMES)).optional(),
    }).optional(),
  }).default({})),

  trigger: section(z.object({
    webhook: z.object({
      enabled: z.boolean().default(true),
      hmac_secret: z.string().optional(),
      signature_header: z.string().default('x-signer-signature'),
      bind: z.string().default('0.0.0.0:8081'),
    }).default({}),
    poller: z.object({ enabled: z.boolean().default(true), interval_seconds: z.number().default(20) }).default({}),
  }).default({})),
  behavior: section(z.object({
    submit_reject_vote: z.boolean().default(false),
    max_bad_version_retries: z.number().default(3),
    value_ceiling: z.string().optional(), // SR4 local guard (optional)
  }).default({})),
  // Admin routes are served on the SAME listener as health (there is one HTTP server, on `health.bind`).
  // There is no separate admin port, so `api_key` — not a bind address — is what protects them:
  // without it every admin route (incl. SR8 pause) returns 403.
  // Read-only relay (src/relay.ts; BTC runbook Phase 5.3, decision P2): lets another component in this
  // cell READ Accumulate, the gateway proof API and EVM RPCs through the signer, which stays the only
  // thing in the cell with a gateway client or a chain connection. Disabled by default. `.strict()`
  // throughout: a misspelled key must refuse the boot, not quietly widen or drop a restriction.
  relay: section(z.object({
    enabled: z.boolean().default(false),
    // Relay-only process: no signing scopes, no keyring, no poller, no votes. For a cell component that needs
    // chain/gateway READS but whose seat signer runs elsewhere (e.g. the bank payment hub). Requires `bind`.
    only: z.boolean().default(false),
    // Absent => served on the health/admin listener. Set => its own listener on this host:port.
    bind: z.string().regex(/^[A-Za-z0-9.\-\[\]:]+:\d{1,5}$/, 'relay.bind must be host:port').optional(),
    token: z.string().optional(),       // bearer token; `env:NAME`. Required when enabled.
    gateway: z.object({
      url: z.string().url(),
      api_key: z.string(),              // `env:NAME`
    }).strict().optional(),
    evm: z.array(z.object({
      chain_id: z.number().int().positive(),
      rpc_url: z.string(),              // http(s) URL or `env:NAME` (provider URLs often embed a key)
    }).strict()).default([]),
    timeout_ms: z.number().int().positive().default(15_000),
  }).strict().default({ enabled: false })),
  // Phase 6.1 ABI pins: a contract-call leg whose (chain_id, address) is listed here is decoded with that ABI
  // and counts as a KNOWN target; every other target is `targetKnown: false`. `.strict()`: a misspelled key
  // must refuse the boot rather than silently unpin a contract.
  decoders: section(z.object({
    evm_abi: z.array(z.object({
      chain_id: z.number().int().positive(),
      address: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'decoders.evm_abi[].address must be a 0x 20-byte address'),
      name: z.string().min(1),
      abi_file: z.string().optional(),   // JSON ABI (or an artifact with `abi`); relative to the config file
      abi: z.array(z.record(z.unknown())).optional(),
      asset: z.object({ symbol: z.string().min(1), decimals: z.number().int().min(0).max(36) }).strict().optional(),
    }).strict()).default([]),
    labels: z.record(z.string()).default({}),
  }).strict().default({})),
  admin: section(z.object({
    api_key: z.string().optional(),
    governance_admin_key: z.string().optional(),
    // Phase 6.4: one credential per decision service for /relay/* (x-relay-client + x-api-key).
    relay_clients: z.array(z.object({
      name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/, 'admin.relay_clients[].name must be 1-64 of [A-Za-z0-9._-]'),
      key: z.string(),                   // `env:NAME`
      scopes: z.array(z.enum(['proof', 'tx', 'pending', 'governance'])).min(1),
    }).strict()).optional(),
  }).default({})),
  health: section(z.object({ bind: z.string().default('0.0.0.0:8080') }).default({})),
  // Durable state: idempotency (never vote twice) + the receipt audit trail. Omit only for tests.
  store: section(z.object({ path: z.string().optional() }).default({})),
  observability: section(z.object({
    log_level: z.string().default('info'),
    metrics: z.boolean().default(true),
    // /metrics exposes decision counts and signing activity. It shares the public health listener, so it
    // is admin-authenticated by default. Set true only if the port is already private (e.g. a k8s
    // ClusterIP scraped by an in-cluster Prometheus).
    metrics_public: z.boolean().default(false),
  }).default({})),
});

export type Config = z.infer<typeof Schema> & {
  /** `sha256:` + hex of the canonical effective config, secrets removed (Phase 6.3). Set by loadConfig. */
  configVersion?: string;
};

/** Keys whose values are credentials (or may embed one) and never enter the config version. */
const SECRET_KEYS = new Set([
  'token', 'api_key', 'hmac_secret', 'seed_hex', 'private_key_der_hex', 'auth_token', 'account_sid',
  'webhook_url', 'governance_admin_key', 'rpc_url', 'key', 'password', 'secret',
]);

/** Canonical JSON: sorted object keys, no whitespace, `undefined` members dropped. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined ? 'null' : canonicalJson(x))).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
}

/**
 * Strip every secret value and every `env:` reference, recursively. A string-valued member under a secret
 * key name is removed (an object under one, e.g. a scope's `key` spec, is kept and stripped inside).
 */
export function stripSecrets(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripSecrets).filter((x) => x !== undefined);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (SECRET_KEYS.has(k) && (typeof x === 'string' || typeof x === 'number')) continue;
      const s = stripSecrets(x);
      if (s !== undefined) out[k] = s;
    }
    return out;
  }
  if (typeof v === 'string' && v.startsWith('env:')) return undefined;
  return v;
}

/** The config version of a parsed (not yet secret-resolved) config. Phase 6.3. */
export function computeConfigVersion(parsed: unknown): string {
  return 'sha256:' + createHash('sha256').update(canonicalJson(stripSecrets(parsed))).digest('hex');
}

/** The policy and behavior a given scope actually runs under: its overrides merged over the defaults. */
export interface EffectiveScopeRules {
  page: string;
  policy: Config['policy'];
  behavior: Config['behavior'];
  /** True when this scope differs from the process defaults — used to decide what is worth logging. */
  overridden: boolean;
}

/**
 * Resolve one scope's effective rules.
 *
 * A shallow merge is correct and a deep one would be wrong: these blocks are flat, and every field is a
 * single decision (which URL, which ceiling) rather than a structure to be combined. `undefined` values
 * from an absent override must not clobber a default, which is why the spread is over explicitly-present
 * keys rather than the raw object.
 */
export function effectiveScopeRules(
  cfg: Config,
  scope: { page: string; policy?: PolicyOverride; behavior?: BehaviorOverride } | undefined,
): EffectiveScopeRules {
  const present = <T extends object>(o: T | undefined): Partial<T> =>
    Object.fromEntries(Object.entries(o ?? {}).filter(([, v]) => v !== undefined)) as Partial<T>;
  const p = present(scope?.policy);
  const b = present(scope?.behavior);
  return {
    page: scope?.page ?? cfg.wallet.signer_url ?? '',
    policy: { ...cfg.policy, ...p },
    behavior: { ...cfg.behavior, ...b },
    overridden: Object.keys(p).length > 0 || Object.keys(b).length > 0,
  };
}

/**
 * The `policy.auth` sanity rules, applied to whatever block is in play.
 *
 * Factored out so a per-scope override is held to exactly the same standard as the top-level block. It
 * would be easy to validate only the default and let a scope quietly downgrade itself to an
 * unauthenticated channel — the override path is precisely where that mistake is least visible.
 */
function validatePolicyAuth(policy: { auth: string; hmac_secret?: string }, where: string): void {
  if (policy.auth === 'hmac' && !policy.hmac_secret) {
    throw new Error(
      `config: ${where} policy.auth is "hmac" but policy.hmac_secret is empty — set it, make sure the `
      + '`env:` ref it points at is populated, or set policy.auth: "none" to state plainly that the '
      + 'channel is unauthenticated',
    );
  }
  if (policy.auth === 'mtls') {
    throw new Error(
      `config: ${where} policy.auth "mtls" is not implemented — the decision request would go out `
      + 'unauthenticated. Use "hmac", or terminate mTLS in a proxy in front of your engine and set "none".',
    );
  }
}

/** Resolve `env:NAME` refs inside a key spec, in place. */
function resolveKeySecrets(spec: SignerSpec | undefined): void {
  if (!spec) return;
  if (spec.vault?.token) spec.vault.token = resolveSecret(spec.vault.token)!;
  if (spec.local?.seed_hex) spec.local.seed_hex = resolveSecret(spec.local.seed_hex);
  if (spec.local?.private_key_der_hex) spec.local.private_key_der_hex = resolveSecret(spec.local.private_key_der_hex);
}

export function loadConfig(path: string): Config {
  const raw = yaml.load(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const cfg: Config = Schema.parse(raw);
  loadAbis(cfg, dirname(resolvePath(path)));
  // Computed over the parsed config BEFORE any `env:` ref is resolved (so no secret value can reach the
  // hash), with ABI files inlined so a changed ABI is a changed version.
  cfg.configVersion = computeConfigVersion(cfg);

  // Signing scope: exactly one of the two forms. Multi-scope (wallet.scopes) takes precedence.
  const multi = (cfg.wallet.scopes?.length ?? 0) > 0;
  if (multi) {
    if (cfg.wallet.signer_url) throw new Error('config: set EITHER wallet.scopes[] OR wallet.signer_url, not both');
    const seen = new Set<string>();
    for (const s of cfg.wallet.scopes!) {
      resolveKeySecrets(s.key);
      // Two scopes on one page means two pollers racing on the same work and two entries competing in the
      // keyring. Duplicates are always a mistake — usually a copy-paste while adding an agent.
      const key = s.page.toLowerCase();
      if (seen.has(key)) throw new Error(`config: wallet.scopes has two entries for ${s.page} — each page may appear once`);
      seen.add(key);
      // A scope's own HMAC secret is a distinct credential from the default one, and gets the same
      // `env:` treatment and the same refusal to run under a stated-but-absent authentication.
      if (s.policy?.hmac_secret) s.policy.hmac_secret = resolveSecret(s.policy.hmac_secret);
    }
  } else if (cfg.relay.only) {
    // Relay-only: holding a key here would contradict the mode, so any signing configuration refuses the boot.
    if (cfg.wallet.signer_url || cfg.signer) throw new Error('config: relay.only must not configure wallet.signer_url or a signer');
    if (!cfg.relay.enabled || !cfg.relay.bind) throw new Error('config: relay.only requires relay.enabled and relay.bind');
  } else {
    if (!cfg.wallet.signer_url) throw new Error('config: set wallet.signer_url (+ a top-level signer), or wallet.scopes[]');
    if (!cfg.signer) throw new Error('config: single-scope mode requires a top-level `signer` block');
    resolveKeySecrets(cfg.signer);
  }

  // resolve remaining secret refs
  if (cfg.gateway.api_key) cfg.gateway.api_key = resolveSecret(cfg.gateway.api_key);
  if (cfg.gateway.enabled && (!cfg.gateway.url || !cfg.gateway.api_key || !cfg.gateway.identity)) {
    throw new Error('gateway.enabled requires gateway.url, gateway.api_key and gateway.identity');
  }
  if (cfg.policy.hmac_secret) cfg.policy.hmac_secret = resolveSecret(cfg.policy.hmac_secret);

  // `policy.auth` states an intent, and a stated intent must not silently downgrade to no protection.
  //
  // The shipped example writes `auth: "hmac"` with `hmac_secret: "env:POLICY_HMAC_SECRET"`. If that
  // variable is unset the ref resolves to undefined, and the signer would then neither sign its requests
  // nor verify the replies — while the operator reads `auth: "hmac"` and believes the channel is
  // authenticated. Anything on the network path could return `{"decision":"approve"}` and be obeyed.
  // Refuse to start instead; this is the same rule the gateway block already follows.
  validatePolicyAuth(cfg.policy, 'top-level');

  // Every scope is validated on its EFFECTIVE rules, not on its override in isolation. A scope that sets
  // only `auth: "hmac"` inherits the default secret and is fine; a scope that sets a different `url` but
  // no secret inherits the default secret and is also fine — but one that sets `auth: "hmac"` while the
  // default has no secret is not, and checking the patch alone would miss both directions.
  for (const s of cfg.wallet.scopes ?? []) {
    const eff = effectiveScopeRules(cfg, s);
    validatePolicyAuth(eff.policy, `scope ${s.page}:`);
    if (eff.behavior.value_ceiling !== undefined && !/^\d+$/.test(eff.behavior.value_ceiling)) {
      throw new Error(`config: scope ${s.page}: behavior.value_ceiling must be a whole number as a string, got ${JSON.stringify(eff.behavior.value_ceiling)}`);
    }
  }
  if (cfg.behavior.value_ceiling !== undefined && !/^\d+$/.test(cfg.behavior.value_ceiling)) {
    throw new Error(`config: behavior.value_ceiling must be a whole number as a string, got ${JSON.stringify(cfg.behavior.value_ceiling)}`);
  }
  // Notification credentials. Unlike the policy channel, an unauthenticated notification is not a security
  // failure — the receiver is being TOLD what happened, not asked what to do, and nothing it says comes
  // back. So a missing webhook secret warns at boot (in index.ts) rather than refusing to start.
  //
  // A channel credential that resolves to nothing is a different matter: it is not "unsigned", it is
  // "will fail on every send". Refuse to start, the same way an empty policy HMAC does — a notification
  // channel that silently never delivers is worse than one that was never configured, because the operator
  // believes they are covered.
  if (cfg.notify.webhook?.hmac_secret) cfg.notify.webhook.hmac_secret = resolveSecret(cfg.notify.webhook.hmac_secret);
  if (cfg.notify.sms) {
    cfg.notify.sms.account_sid = resolveSecret(cfg.notify.sms.account_sid) ?? '';
    cfg.notify.sms.auth_token = resolveSecret(cfg.notify.sms.auth_token) ?? '';
    if (!cfg.notify.sms.account_sid || !cfg.notify.sms.auth_token) {
      throw new Error('config: notify.sms is configured but account_sid or auth_token resolved to nothing — check the env: refs, or remove the block');
    }
  }
  if (cfg.notify.email) {
    cfg.notify.email.api_key = resolveSecret(cfg.notify.email.api_key) ?? '';
    if (!cfg.notify.email.api_key) {
      throw new Error('config: notify.email is configured but api_key resolved to nothing — check the env: ref, or remove the block');
    }
  }
  if (cfg.notify.slack) {
    cfg.notify.slack.webhook_url = resolveSecret(cfg.notify.slack.webhook_url) ?? '';
    if (!cfg.notify.slack.webhook_url) {
      throw new Error('config: notify.slack is configured but webhook_url resolved to nothing — check the env: ref, or remove the block');
    }
  }
  if (cfg.trigger.webhook.hmac_secret) cfg.trigger.webhook.hmac_secret = resolveSecret(cfg.trigger.webhook.hmac_secret);
  if (cfg.admin.api_key) cfg.admin.api_key = resolveSecret(cfg.admin.api_key);
  if (cfg.admin.governance_admin_key) cfg.admin.governance_admin_key = resolveSecret(cfg.admin.governance_admin_key);
  for (const c of cfg.admin.relay_clients ?? []) c.key = resolveSecret(c.key) ?? '';
  validateRelay(cfg);
  validateRelayClients(cfg);
  return cfg;
}

/**
 * Inline each `decoders.evm_abi[].abi_file` as `abi`, and refuse duplicate pins or an entry with neither or
 * both sources. Exported for tests.
 */
export function loadAbis(cfg: Pick<Config, 'decoders'>, baseDir: string): void {
  const seen = new Set<string>();
  for (const e of cfg.decoders.evm_abi) {
    const key = `${e.chain_id}:${e.address.toLowerCase()}`;
    if (seen.has(key)) throw new Error(`config: decoders.evm_abi pins ${key} twice`);
    seen.add(key);
    if (!!e.abi_file === !!e.abi) throw new Error(`config: decoders.evm_abi ${e.name}: set exactly one of abi_file or abi`);
    if (e.abi_file) {
      let parsed: unknown;
      try { parsed = JSON.parse(readFileSync(resolvePath(baseDir, e.abi_file), 'utf8')); }
      catch (err) { throw new Error(`config: decoders.evm_abi ${e.name}: cannot read abi_file ${e.abi_file} (${(err as Error).message})`); }
      const list = Array.isArray(parsed) ? parsed : (parsed as { abi?: unknown })?.abi;
      if (!Array.isArray(list)) throw new Error(`config: decoders.evm_abi ${e.name}: abi_file must hold a JSON ABI array or an artifact with \`abi\``);
      e.abi = list as Array<Record<string, unknown>>;
    }
  }
}

/**
 * Per-decision-service relay credentials (Phase 6.4). Each key must resolve, be at least 16 characters,
 * be unique, and differ from the admin, governance and hub relay credentials. Exported for tests.
 */
export function validateRelayClients(cfg: Pick<Config, 'relay' | 'admin'>): void {
  const names = new Set<string>();
  const keys = new Set<string>();
  const others = [cfg.admin.api_key, cfg.admin.governance_admin_key, cfg.relay.token].filter(Boolean);
  for (const c of cfg.admin.relay_clients ?? []) {
    if (names.has(c.name)) throw new Error(`config: admin.relay_clients lists ${c.name} twice`);
    names.add(c.name);
    if (!c.key) throw new Error(`config: admin.relay_clients ${c.name}: key resolved to nothing — check the env: ref`);
    if (c.key.length < 16) throw new Error(`config: admin.relay_clients ${c.name}: key must be at least 16 characters`);
    if (others.includes(c.key)) throw new Error(`config: admin.relay_clients ${c.name}: key must be its own secret, not an admin or relay credential`);
    if (keys.has(c.key)) throw new Error(`config: admin.relay_clients ${c.name}: key is shared with another client`);
    keys.add(c.key);
  }
}

/**
 * Resolve and check the relay block. Exported for tests. A relay that is enabled must be authenticated
 * by its OWN token (A6: each seat its own secret) — never missing, never empty, never shared with an
 * admin credential, since the relay's caller is a different component than the operator.
 */
export function validateRelay(cfg: { relay: Config['relay']; admin: { api_key?: string; governance_admin_key?: string } }): void {
  const r = cfg.relay;
  if (!r.enabled) return;
  r.token = resolveSecret(r.token) ?? '';
  if (!r.token || r.token.trim() === '') {
    throw new Error('config: relay.enabled requires relay.token (a bearer token, e.g. `env:RELAY_TOKEN`) — it is missing or resolved to nothing');
  }
  if (r.token.length < 16) throw new Error('config: relay.token must be at least 16 characters');
  if (r.token === cfg.admin.api_key || r.token === cfg.admin.governance_admin_key) {
    throw new Error('config: relay.token must be its own secret, not an admin credential');
  }
  if (r.bind) {
    const port = Number(r.bind.slice(r.bind.lastIndexOf(':') + 1));
    if (!(port >= 1 && port <= 65535)) throw new Error('config: relay.bind port must be 1..65535');
  }
  if (r.gateway) {
    r.gateway.api_key = resolveSecret(r.gateway.api_key) ?? '';
    if (!r.gateway.api_key) throw new Error('config: relay.gateway.api_key resolved to nothing — check the env: ref, or remove relay.gateway');
  }
  const seen = new Set<number>();
  for (const c of r.evm) {
    if (seen.has(c.chain_id)) throw new Error(`config: relay.evm lists chain_id ${c.chain_id} twice`);
    seen.add(c.chain_id);
    c.rpc_url = resolveSecret(c.rpc_url) ?? '';
    let ok = false;
    try { ok = /^https?:$/.test(new URL(c.rpc_url).protocol); } catch { ok = false; }
    // Never echo the URL: a provider RPC URL usually carries its key.
    if (!ok) throw new Error(`config: relay.evm chain_id ${c.chain_id}: rpc_url must resolve to an http(s) URL`);
  }
}

export function parseBind(bind: string): { host: string; port: number } {
  const i = bind.lastIndexOf(':');
  return { host: bind.slice(0, i) || '0.0.0.0', port: Number(bind.slice(i + 1)) };
}
