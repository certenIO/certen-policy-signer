/** Config load + validation. Every field is documented in config.example.yaml; secrets use `env:NAME` refs. */
import { readFileSync } from 'node:fs';
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
}

export function loadConfig(path: string): Config {
  const raw = yaml.load(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const cfg = Schema.parse(raw);

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
  return cfg;
}

export function parseBind(bind: string): { host: string; port: number } {
  const i = bind.lastIndexOf(':');
  return { host: bind.slice(0, i) || '0.0.0.0', port: Number(bind.slice(i + 1)) };
}
