/**
 * Command-line surface. The signer takes one positional argument — the config path — but a first-time
 * user's first instinct is `--help`, and treating that as a filename produces an ENOENT that reads like
 * a broken install. Parsing lives here, apart from `index.ts`, so it can be tested without a boot.
 */
import pkg from '../package.json';

export const VERSION: string = pkg.version;
/** The short name. `certen-external-policy-signer` is still installed as an alias for existing deployments,
 *  but help output should teach the current one. */
export const BIN = 'certen-policy-signer';

export type Invocation =
  | { mode: 'run'; configPath: string }
  | { mode: 'help' }
  | { mode: 'version' }
  | { mode: 'error'; message: string };

export function helpText(): string {
  return `${BIN} ${VERSION}

  Headless off-chain policy signer for Accumulate. Watches one or more key pages for pending
  transactions, asks your policy engine to decide on each, and signs only what it approves.

USAGE
  ${BIN} [config-path]
  ${BIN} --help | --version

  The config path is resolved in this order — first one set wins:
    1. the positional argument
    2. $CONFIG_PATH
    3. ./config.yaml

  A missing or invalid config is a startup failure, never a default: the signer will not boot
  into a permissive state.

ENVIRONMENT
  CONFIG_PATH   Config file to load when no path is given on the command line.
  LOG_LEVEL     Pino level — trace, debug, info (default), warn, error, fatal.

  Config values written as env:NAME are read from the environment at boot, so keys and secrets
  need never appear in the file itself.

HTTP (one listener, address from health.bind)
  GET  /healthz              Liveness + per-scope poller freshness
  GET  /metrics              Prometheus text; public only if observability.metrics_public
  POST /v1/pending           Webhook trigger; requires an HMAC when trigger.webhook is enabled
  GET  /v1/requests          Decision + receipt audit trail          (admin)
                             ?limit=N&status=a,b — status=awaiting_policy is the work queue
  POST /v1/admin/pause       Withhold all signatures                 (admin)
  POST /v1/admin/resume      Resume signing                          (admin)
  GET  /v1/admin/pubkey      Public key per scope                    (admin)
  POST /v1/admin/key-page    Key-page governance                     (admin)

  Admin routes require the x-api-key header and are disabled — not merely unauthenticated —
  when no admin.api_key is configured.

GETTING STARTED
  cp config.minimal.yaml config.yaml    The five fields that have no default
  ${BIN} config.yaml

  config.example.yaml    Every option, documented inline, with the reasoning attached

  docs/QUICKSTART.md     A running signer against a test network
  docs/INTEGRATION.md    The policy-engine contract and custom intent decoders
  docs/OPERATIONS.md     Running it for real
`;
}

/** Parse `process.argv.slice(2)`. */
export function parseArgs(argv: string[]): Invocation {
  if (argv.includes('-h') || argv.includes('--help')) return { mode: 'help' };
  if (argv.includes('-v') || argv.includes('--version')) return { mode: 'version' };

  const positional = argv.filter((a) => !a.startsWith('-'));
  // An unrecognised flag must not be silently ignored — it usually means the operator believes they
  // have configured something (a bind address, a dry run) that is not in fact taking effect.
  const unknown = argv.find((a) => a.startsWith('-'));
  if (unknown) return { mode: 'error', message: `unknown option: ${unknown}` };
  if (positional.length > 1) {
    return { mode: 'error', message: `expected at most one config path, got ${positional.length}` };
  }

  return { mode: 'run', configPath: positional[0] ?? process.env.CONFIG_PATH ?? './config.yaml' };
}
