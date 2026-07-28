/** Config load + validation (SPEC §11). Secrets resolved from env via `env:NAME` refs. */
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { z } from 'zod';

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

function resolveSecret(v: string | undefined): string | undefined {
  if (!v) return undefined;
  if (v.startsWith('env:')) return process.env[v.slice(4)];
  return v;
}

// A key source — reused for the single top-level `signer` and for each multi-scope `scopes[].key`.
const SignerSpecSchema = z.object({
  provider: z.enum(['vault-transit', 'local']),
  vault: z.object({ addr: z.string().url(), key_name: z.string(), token: z.string() }).partial().optional(),
  local: z.object({
    seed_hex: z.string(),          // 32-byte hex, or an `env:NAME` ref
    seed_file: z.string(),         // path to a file holding the 32-byte hex seed (docker/k8s secret mount)
    allow_ephemeral: z.boolean(),  // dev only: generate a throwaway key when no seed is configured
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
  admin: section(z.object({ api_key: z.string().optional(), governance_admin_key: z.string().optional() }).default({})),
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

export type Config = z.infer<typeof Schema>;

/** Resolve `env:NAME` refs inside a key spec, in place. */
function resolveKeySecrets(spec: SignerSpec | undefined): void {
  if (!spec) return;
  if (spec.vault?.token) spec.vault.token = resolveSecret(spec.vault.token)!;
  if (spec.local?.seed_hex) spec.local.seed_hex = resolveSecret(spec.local.seed_hex);
}

export function loadConfig(path: string): Config {
  const raw = yaml.load(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const cfg = Schema.parse(raw);

  // Signing scope: exactly one of the two forms. Multi-scope (wallet.scopes) takes precedence.
  const multi = (cfg.wallet.scopes?.length ?? 0) > 0;
  if (multi) {
    if (cfg.wallet.signer_url) throw new Error('config: set EITHER wallet.scopes[] OR wallet.signer_url, not both');
    for (const s of cfg.wallet.scopes!) resolveKeySecrets(s.key);
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
  if (cfg.policy.auth === 'hmac' && !cfg.policy.hmac_secret) {
    throw new Error(
      'config: policy.auth is "hmac" but policy.hmac_secret is empty — set it, make sure the `env:` ref it '
      + 'points at is populated, or set policy.auth: "none" to state plainly that the channel is unauthenticated',
    );
  }
  // mTLS is not implemented (there is no client-certificate agent on the policy request). Accepting it
  // here would send plain, unauthenticated HTTP under a name that promises the opposite.
  if (cfg.policy.auth === 'mtls') {
    throw new Error(
      'config: policy.auth "mtls" is not implemented — the decision request would go out unauthenticated. '
      + 'Use "hmac", or terminate mTLS in a proxy in front of your engine and set "none".',
    );
  }
  if (cfg.trigger.webhook.hmac_secret) cfg.trigger.webhook.hmac_secret = resolveSecret(cfg.trigger.webhook.hmac_secret);
  if (cfg.admin.api_key) cfg.admin.api_key = resolveSecret(cfg.admin.api_key);
  if (cfg.admin.governance_admin_key) cfg.admin.governance_admin_key = resolveSecret(cfg.admin.governance_admin_key);
  return cfg;
}

export function parseBind(bind: string): { host: string; port: number } {
  const i = bind.lastIndexOf(':');
  return { host: bind.slice(0, i) || '0.0.0.0', port: Number(bind.slice(i + 1)) };
}
