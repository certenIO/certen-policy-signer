/**
 * Officer intake wiring, and the intake-only process. FICTIONAL Business Transaction Controls lab, Phase 7.
 *
 * Intake-only (contract §4): officer intake enabled and no signing configuration at all. No keyring, no key
 * provider, no poller, no policy engine, no votes — the process verifies personal signatures made on people's
 * own devices and submits them, and serves the decision-service relay. It is the post-retirement shape for a
 * party without a machine page.
 */
import http from 'node:http';
import { Config, parseBind } from './config.js';
import { Logger } from './logger.js';
import { RawAccumulateClient } from './accumulate/raw-client.js';
import { readPage } from './ops/rotate.js';
import { createOfficerIntake, OfficerIntake } from './officer/intake.js';
import { createRelayClientsHandler, RelayClientsHandler } from './relay-clients.js';
import { createServer } from './server.js';
import { MemoryStore, FileStore, Store } from './store/store.js';
import { buildRegistry, loadDecoderModules, DecoderRegistry } from './decode/registry.js';
import { createCertenIntentDecoder } from './decode/decoders/certen-intent.js';
import { buildSelectorTable } from './decode/abi.js';
import type { Keyring } from './signer/keyring.js';
import type { Orchestrator } from './orchestrator.js';
import type { TxBody } from './decode/types.js';

export async function buildDecoders(cfg: Config, logger: Logger): Promise<DecoderRegistry> {
  const externalDecoders = await loadDecoderModules(cfg.resolver.decoder_modules);
  const pins = cfg.decoders.evm_abi.map((e) => ({
    chainId: e.chain_id, address: e.address.toLowerCase(), name: e.name, table: buildSelectorTable(e.abi), ...(e.asset ? { asset: e.asset } : {}),
  }));
  return buildRegistry(cfg.resolver.decoders, externalDecoders, logger, {
    certenIntent: createCertenIntentDecoder({ pins, labels: cfg.decoders.labels }),
  });
}

export function buildOfficerIntake(cfg: Config, accumulate: RawAccumulateClient, store: Store, decoders: DecoderRegistry, logger: Logger): OfficerIntake {
  return createOfficerIntake({
    humanPages: cfg.officer_intake.human_pages,
    chain: accumulate,
    readPage: (page) => readPage(accumulate, page),
    getPolicyRequest: (h) => store.getPolicyRequest(h),
    saveAwaiting: (pr) => store.savePolicyRequest(pr),
    decode: (body, principal) => decoders.decode(body as TxBody, { principal }),
    labels: cfg.decoders.labels,
    landedTimeoutMs: cfg.officer_intake.landed_timeout_ms,
    logger,
  });
}

/** A keyring holding nothing: intake-only has no scope, so every signing lookup refuses. */
const EMPTY_KEYRING: Keyring = {
  forPage: (page: string) => { throw new Error(`intake-only signer holds no key (asked for ${page})`); },
  scopes: () => [],
  healthy: async () => true,
} as unknown as Keyring;

const NO_ORCHESTRATOR = {
  handle: async () => { throw new Error('intake-only signer does not sign'); },
} as unknown as Orchestrator;

export interface IntakeOnlyProcess { server: http.Server; intake: OfficerIntake; relayClients?: RelayClientsHandler }

/** Build (and, unless `listen: false`, start) the intake-only process. */
export async function startIntakeOnly(cfg: Config, logger: Logger, opts: { accumulate?: RawAccumulateClient; listen?: boolean } = {}): Promise<IntakeOnlyProcess> {
  const accumulate = opts.accumulate ?? new RawAccumulateClient(cfg.wallet.accumulate_endpoints[0], logger);
  const store: Store = cfg.store.path ? new FileStore(cfg.store.path) : new MemoryStore();
  const decoders = await buildDecoders(cfg, logger);
  const intake = buildOfficerIntake(cfg, accumulate, store, decoders, logger);

  let relayClients: RelayClientsHandler | undefined;
  if (cfg.admin.relay_clients?.length) {
    const gw = cfg.relay.gateway ? { url: cfg.relay.gateway.url, apiKey: cfg.relay.gateway.api_key } : undefined;
    relayClients = createRelayClientsHandler({
      clients: cfg.admin.relay_clients,
      reservedKeys: [cfg.admin.api_key, cfg.admin.governance_admin_key, cfg.relay.token],
      query: (scope, q) => accumulate.query(scope, q),
      gateway: gw,
      evm: cfg.relay.evm.map((c) => ({ chainId: c.chain_id, rpcUrl: c.rpc_url })),
      getPolicyRequest: (h) => store.getPolicyRequest(h),
      governanceKey: cfg.admin.governance_admin_key,
      pages: () => [],                 // no page is held: POST /relay/governance refuses every page
      propose: (page, ops, proposer) => intake.propose(page, ops, proposer),
      timeoutMs: cfg.relay.timeout_ms,
      logger,
    });
  }

  const server = createServer({
    relayClients, officerIntake: intake.handle, configVersion: cfg.configVersion,
    orchestrator: NO_ORCHESTRATOR, store, keyring: EMPTY_KEYRING, accumulate, pause: { paused: false }, logger,
    adminApiKey: cfg.admin.api_key,
    metricsPublic: cfg.observability.metrics_public,
  });
  if (opts.listen !== false) {
    const { host, port } = parseBind(cfg.health.bind);
    server.listen(port, host, () => logger.info({ host, port }, 'http server listening (health/relay/officer intake)'));
  }
  logger.info(
    { humanPages: cfg.officer_intake.human_pages, relayClients: (cfg.admin.relay_clients ?? []).map((c) => c.name) },
    'INTAKE-ONLY mode: officer intake + relay; no keys, no poller, no policy engine',
  );
  return { server, intake, relayClients };
}
