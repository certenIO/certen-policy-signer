/** Entry point: wire modules from config, run the startup self-check, start servers + poller. */
import { createHash } from 'node:crypto';
import { parseArgs, helpText, VERSION, BIN } from './cli.js';
import { loadConfig, parseBind, effectiveScopeRules, Config } from './config.js';
import { logger as baseLogger } from './logger.js';
import { MapKeyring, buildSignerFromSpec, bookOf, SigningScope } from './signer/keyring.js';
import { RawAccumulateClient } from './accumulate/raw-client.js';
import { HttpPolicyClient, loadPolicyAdapter } from './policy/policy.js';
import { MemoryStore, FileStore } from './store/store.js';
import { Resolver } from './resolver.js';
import { buildRegistry, loadDecoderModules } from './decode/registry.js';
import { makeValueCeilingGuard } from './guard.js';
import { applyKeyPageOp } from './ops/keypage.js';
import { GatewayClient, GatewayVoteBackend } from './vote/adapters/certen-gateway.js';
import { buildNotifier, MultiNotifier, NotifyConfig } from './notify.js';
import { Orchestrator, ScopeRules } from './orchestrator.js';
import { Poller } from './poller.js';
import { createServer, PauseController, HealthSource } from './server.js';
import { bytesToHex } from './accumulate/signing.js';

/** Host of an endpoint URL, for the startup log when `wallet.network` carries no label. */
function hostOf(endpoint: string): string {
  try { return new URL(endpoint).host; } catch { return endpoint; }
}

async function main() {
  // Argument handling before anything else: --help must answer even when there is no config, no key
  // and no network. It is printed raw rather than logged — a help screen wrapped in JSON is not help.
  const inv = parseArgs(process.argv.slice(2));
  if (inv.mode === 'help') { process.stdout.write(helpText()); return; }
  if (inv.mode === 'version') { process.stdout.write(`${BIN} ${VERSION}\n`); return; }
  if (inv.mode === 'error') {
    process.stderr.write(`${BIN}: ${inv.message}\nTry '${BIN} --help'.\n`);
    process.exit(2);
  }

  const cfg = loadConfig(inv.configPath);
  const logger = baseLogger.child({ org: cfg.wallet.org_id });

  // --- signing scopes + keyring (key custody) ---
  // Multi-scope: watch several key pages, each with its own key/provider. Single-scope (signer_url + the
  // top-level `signer`) folds into a one-element list so everything downstream is uniform.
  const scopes: SigningScope[] = (cfg.wallet.scopes?.length)
    ? cfg.wallet.scopes.map((s, i) => ({
        page: s.page,
        book: s.book ?? bookOf(s.page),
        signer: buildSignerFromSpec(s.key, logger, `scope[${i}] ${s.page}`),
      }))
    : [{
        page: cfg.wallet.signer_url!,
        book: bookOf(cfg.wallet.signer_url!),
        signer: buildSignerFromSpec(cfg.signer!, logger, cfg.wallet.signer_url!),
      }];
  const keyring = new MapKeyring(scopes);
  const endpoint = cfg.wallet.accumulate_endpoints[0];
  logger.info(
    { network: cfg.wallet.network ?? hostOf(endpoint), endpoint, scopes: scopes.map((s) => s.page) },
    scopes.length > 1 ? `starting policy signer (MULTI-SCOPE: ${scopes.length} pages)` : 'starting policy signer',
  );

  const accumulate = new RawAccumulateClient(cfg.wallet.accumulate_endpoints[0], logger);

  /**
   * Build the policy client for one effective policy block.
   *
   * Shared by the process default and every per-scope override so the two cannot diverge — an override
   * gets the same adapter loading, the same HMAC handling, and the same legacy-header warning. Adapter
   * modules are loaded here, at boot, so a broken or missing one stops the process rather than silently
   * leaving the default shape in place and talking the wrong protocol to a real engine.
   */
  const buildPolicyClient = async (p: Config['policy'], label: string) => {
    const adapter = await loadPolicyAdapter(p.adapter_module);
    if (adapter) {
      logger.info({
        scope: label,
        adapter: adapter.name,
        reshapes: [adapter.buildRequest ? 'request' : undefined, adapter.parseResponse ? 'response' : undefined].filter(Boolean),
      }, 'policy adapter loaded');
    }
    return new HttpPolicyClient({
      adapter,
      url: p.url,
      timeoutMs: p.timeout_ms,
      hmacSecret: p.auth === 'hmac' ? p.hmac_secret : undefined,
      signatureHeader: p.signature_header,
      timestampHeader: p.timestamp_header,
      onLegacyHeader: (h) =>
        logger.warn(
          { scope: label, header: h, configured: p.signature_header },
          'policy engine authenticated its response with the legacy header; set policy.signature_header to match your engine',
        ),
    });
  };

  const policy = await buildPolicyClient(cfg.policy, 'default');

  // Durable state: which txs we have already voted on (never vote twice) + the receipt audit trail.
  // In memory, a restart forgets both.
  const store = cfg.store.path ? new FileStore(cfg.store.path) : new MemoryStore();
  if (!cfg.store.path) logger.warn('no store.path configured — signing history and receipts are IN MEMORY and lost on restart');
  else logger.info({ path: cfg.store.path }, 'durable store');

  // Intent decoding: built-ins plus anything from resolver.decoder_modules. Built BEFORE the poller
  // starts — a decoder module that fails to load must stop the boot, not surface later as transactions
  // being described generically to the policy engine.
  const externalDecoders = await loadDecoderModules(cfg.resolver.decoder_modules);
  const decoders = buildRegistry(cfg.resolver.decoders, externalDecoders, logger);
  logger.info({ decoders: decoders.names() }, 'intent decoder chain (first claim wins)');

  const resolver = new Resolver(accumulate, decoders);
  const pause: PauseController = { paused: false };

  // SR4 local guard: refuse to sign above a value ceiling (see src/guard.ts — gates EVERY leg).
  const guard = cfg.behavior.value_ceiling
    ? makeValueCeilingGuard(BigInt(cfg.behavior.value_ceiling))
    : undefined;
  if (guard) logger.info({ ceiling: cfg.behavior.value_ceiling }, 'SR4 value ceiling active (every leg gated)');

  const delegators = cfg.wallet.attachment_model === 'delegate' && cfg.wallet.delegator_url
    ? [cfg.wallet.delegator_url]
    : undefined;

  // --- per-scope rules: a fleet rarely shares one rulebook ---
  //
  // Each scope may override `policy` and `behavior`; what it does not state, it inherits. Built here, at
  // boot, so a scope pointing at an unreachable adapter module or an unresolvable secret stops the process
  // — the alternative is discovering it the first time that one agent has work, which could be days later.
  //
  // Only scopes that actually differ get an entry; the map is consulted per transaction, and an absent
  // key means "use the defaults" without allocating a duplicate client per page.
  const scopeRules = new Map<string, ScopeRules>();
  for (const s of cfg.wallet.scopes ?? []) {
    const eff = effectiveScopeRules(cfg, s);
    if (!eff.overridden) continue;
    const rules: ScopeRules = {};
    if (s.policy && Object.keys(s.policy).length) {
      rules.policy = await buildPolicyClient(eff.policy, s.page);
    }
    if (s.behavior?.value_ceiling !== undefined) {
      rules.guard = makeValueCeilingGuard(BigInt(eff.behavior.value_ceiling!));
    }
    if (s.behavior?.submit_reject_vote !== undefined) {
      rules.submitRejectVote = eff.behavior.submit_reject_vote;
    }
    scopeRules.set(s.page.toLowerCase(), rules);
    logger.info({
      scope: s.page,
      policyUrl: eff.policy.url,
      valueCeiling: eff.behavior.value_ceiling ?? null,
      submitRejectVote: eff.behavior.submit_reject_vote,
    }, 'scope runs under its own rules');
  }

  // --- how votes reach the chain: DIRECT (we submit) or GATEWAY (the api-gateway relays) ---
  // Either way the org's key stays here and the policy gate is unchanged. Discovery and intent decoding
  // are always ours: the gateway's pending list has no transaction body to gate on.
  let gatewayClient: GatewayClient | undefined;
  let votes;
  if (cfg.gateway.enabled) {
    gatewayClient = new GatewayClient({
      url: cfg.gateway.url!, apiKey: cfg.gateway.api_key!, identity: cfg.gateway.identity!,
      signerUrl: cfg.gateway.signer_url ?? cfg.wallet.signer_url, timeoutMs: cfg.gateway.timeout_ms,
    }, logger);
    votes = new GatewayVoteBackend(gatewayClient, keyring, logger, cfg.behavior.max_bad_version_retries);
    logger.info({ gateway: cfg.gateway.url, identity: cfg.gateway.identity }, 'vote backend: GATEWAY (external signing seam)');
  } else {
    logger.info('vote backend: DIRECT (submitting to Accumulate ourselves)');
  }

  // --- outbound notifications (optional): SMS / email / Slack / webhook, all fire-and-forget ---
  const notifier = buildNotifier(cfg.notify as NotifyConfig, logger);
  if (notifier instanceof MultiNotifier) {
    // Log which channel gets which events. A filter typo shows up here at boot, not as a text message
    // that never arrives during the incident it was configured for.
    for (const { channel, events } of notifier.describe()) {
      logger.info({ channel, events }, 'notification channel enabled');
    }
    if (cfg.notify.webhook?.url && !cfg.notify.webhook.hmac_secret) {
      logger.warn('notify.webhook.url is set without hmac_secret — events go out unsigned, so the receiver cannot tell they came from this signer');
    }
  }

  const orchestrator = new Orchestrator({
    accumulate, keyring, policy, store, resolver, logger, votes,
    notifier, orgId: cfg.wallet.org_id, scopeRules,
    options: {
      submitRejectVote: cfg.behavior.submit_reject_vote,
      maxBadVersionRetries: cfg.behavior.max_bad_version_retries,
      policyTtlSeconds: cfg.policy.async_ttl_seconds,
      guard,
      isPaused: () => pause.paused,
      delegators,
    },
  });

  // --- SR6 startup self-check: EACH scope's public key MUST be verifiably on its on-chain page ---
  // Fail-closed, per scope. A wallet that cannot prove it holds a key on a page it claims to sign for is
  // misconfigured, and every vote it casts for that page would be rejected by the network — silently.
  // An unreachable page (or one whose key hashes we cannot read) stops boot; that is exactly the case
  // where you most want it to stop.
  for (const scope of scopes) {
    const pub = await scope.signer.publicKey();
    const keyHash = createHash('sha256').update(pub).digest('hex');
    logger.info({ page: scope.page, pubkey: bytesToHex(pub), keyHash }, 'signer public key');
    try {
      const info = await accumulate.getSignerInfo(scope.page);
      logger.info({ page: scope.page, version: info.version, credits: info.creditBalance }, 'signer page reachable');
      if (info.creditBalance === 0) logger.warn({ page: scope.page }, 'signer page has NO CREDITS — votes will fail to submit until it is funded');

      const rec: any = await (accumulate as RawAccumulateClient).query(scope.page);
      const keys = rec?.account?.keys ?? rec?.data?.keys ?? [];
      if (!keys.length) throw new Error(`SR6: signer page ${scope.page} exposes no key hashes — cannot verify our key is on it`);
      const match = keys.some((k: any) => (k?.publicKeyHash ?? '').toString().toLowerCase() === keyHash);
      if (!match) throw new Error(`SR6: our public key (${keyHash}) is not on ${scope.page} — refusing to start`);
      logger.info({ page: scope.page }, 'SR6 self-check OK: pubkey matches page');
    } catch (e) {
      const msg = (e as Error).message;
      if (!cfg.wallet.allow_unverified_signer) {
        throw new Error(`SR6 self-check failed: ${msg} (set wallet.allow_unverified_signer to override — you will be signing unverified)`);
      }
      logger.warn({ page: scope.page, err: msg }, 'SR6 self-check FAILED but allow_unverified_signer is set — proceeding UNVERIFIED');
    }
  }

  // --- pollers: ONE PER SCOPE, all feeding the shared orchestrator (built before the server so /healthz
  //     can report on them). Each watches its own page + book, on its own backoff. ---
  const pollers = cfg.trigger.poller.enabled
    ? scopes.map((scope) => new Poller(
        accumulate, orchestrator, scope.page, cfg.trigger.poller.interval_seconds * 1000,
        logger.child({ scope: scope.page }), Date.now,
        gatewayClient ? () => gatewayClient!.listPending() : undefined,   // supplement, never a replacement
        scope.book,
      ))
    : [];
  // Unhealthy if ANY scope's discovery loop is stalled; lastSuccess is the oldest success across them.
  // `scopes()` additionally names WHICH page stalled — on a fleet, the aggregate boolean is not actionable.
  const pollerHealth: HealthSource | undefined = pollers.length
    ? {
        healthy: () => pollers.every((p) => p.healthy()),
        lastSuccess: () => Math.min(...pollers.map((p) => p.lastSuccess())),
        scopes: () => pollers.map((p) => ({ page: p.page(), healthy: p.healthy(), lastSuccess: p.lastSuccess() || null })),
      }
    : undefined;

  // --- server (health/metrics/webhook/admin) ---
  const server = createServer({
    orchestrator, store, keyring, accumulate, pause, logger, poller: pollerHealth,
    webhookHmacSecret: cfg.trigger.webhook.enabled ? cfg.trigger.webhook.hmac_secret : undefined,
    webhookSignatureHeader: cfg.trigger.webhook.signature_header,
    adminApiKey: cfg.admin.api_key,
    governanceAdminKey: cfg.admin.governance_admin_key,
    metricsPublic: cfg.observability.metrics_public,
    notify: (event) => notifier.emit({ event, at: new Date().toISOString(), orgId: cfg.wallet.org_id }),
    // The set of governable pages is bound HERE, from our own config: `keyring.forPage` throws for any page
    // we do not hold a key for, so a caller can never point governance at an arbitrary page. Default: scope 0.
    keyPage: (op, page) => {
      const target = page ?? scopes[0].page;
      return applyKeyPageOp({ accumulate, signer: keyring.forPage(target), logger, page: target }, op);
    },
  });
  const { host, port } = parseBind(cfg.health.bind);
  server.listen(port, host, () => logger.info({ host, port }, 'http server listening (health/metrics/webhook/admin)'));

  // The admin routes (incl. SR8 pause) share this listener, so without an api_key they are disabled
  // rather than exposed. Say so at boot — an operator who thinks pause is available must not find out
  // during the incident that it is not.
  if (cfg.admin.api_key) logger.info('admin routes enabled (x-api-key required)');
  else logger.warn({ bind: cfg.health.bind }, 'admin routes DISABLED (403): no admin.api_key configured — SR8 pause is unavailable');

  if (cfg.trigger.webhook.enabled && !cfg.trigger.webhook.hmac_secret) {
    logger.warn('webhook trigger enabled but no hmac_secret set — POST /v1/pending will return 403 rather than accept unauthenticated triggers');
  }

  for (const p of pollers) p.start();
  if (pollers.length) logger.info({ intervalSeconds: cfg.trigger.poller.interval_seconds, pollers: pollers.length }, 'poller started');

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('shutting down');
    for (const p of pollers) p.stop();
    // In-flight signing finishes against the durable store, so a restart resumes rather than re-votes.
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e) => { baseLogger.error({ err: e.message }, 'fatal startup error'); process.exit(1); });
