/** HTTP surface: health, metrics, webhook trigger, admin. Routes are documented in docs/OPERATIONS.md. */
import http from 'node:http';
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { bytesToHex } from './accumulate/signing.js';
import { KeyPageOp, KeyPageResult } from './ops/keypage.js';
import { Orchestrator } from './orchestrator.js';
import { Store } from './store/store.js';
import { Keyring } from './signer/keyring.js';
import { AccumulateClient } from './accumulate/client.js';
import { metrics } from './metrics.js';
import { Logger } from './logger.js';
import { DEFAULT_SIGNATURE_HEADER, LEGACY_SIGNATURE_HEADER } from './policy/policy.js';
import { REQUEST_STATUSES, RequestStatus } from './types.js';
import { NotifyEvent } from './notify.js';

export interface PauseController { paused: boolean; }

/** Anything whose staleness should make the wallet report unhealthy (the poller, in practice). */
export interface HealthSource {
  healthy(): boolean;
  lastSuccess(): number;
  /**
   * Per-scope breakdown, when this signer watches more than one page.
   *
   * The aggregate above answers "is discovery working"; on a fleet that is not actionable — twelve agent
   * pages report as one boolean, and an operator paged at 3am cannot tell which agent stopped. This names
   * them. Absent for a single-scope signer, where the aggregate already IS the answer.
   */
  scopes?(): Array<{ page: string; healthy: boolean; lastSuccess: number | null }>;
}

export interface ServerDeps {
  orchestrator: Orchestrator;
  store: Store;
  keyring: Keyring;
  accumulate: AccumulateClient;
  pause: PauseController;
  logger: Logger;
  webhookHmacSecret?: string;
  /** Header the caller signs the webhook body in. Defaults to DEFAULT_SIGNATURE_HEADER; the legacy name
   * is also accepted so an existing caller keeps working. */
  webhookSignatureHeader?: string;
  adminApiKey?: string;
  /** Separate, higher-privilege credential for key-page governance (changing a key changes who can act). */
  governanceAdminKey?: string;
  /** Executes a TYPED key-page operation against one of our pages (default: the first scope). Absent =>
   * governance is disabled. `page`, when given, must be a page this wallet holds a key for. */
  keyPage?: (op: KeyPageOp, page?: string) => Promise<KeyPageResult>;
  /** The poller, when enabled — a wallet whose discovery loop is dead is NOT healthy. */
  poller?: HealthSource;
  /** Serve /metrics without authentication (only when the port is already private). */
  metricsPublic?: boolean;
  /** Fire a lifecycle notification. Absent when no `notify.url` is configured. Best-effort by contract. */
  notify?: (event: NotifyEvent) => void;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size > 256 * 1024) { reject(new Error('body too large')); req.destroy(); } chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function json(res: http.ServerResponse, code: number, obj: unknown) {
  const s = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(s);
}
/** Constant-time credential comparison (a plain !== leaks the secret's prefix through timing). */
function safeEqual(given: string | string[] | undefined, expected: string): boolean {
  if (typeof given !== 'string') return false;
  const a = Buffer.from(given), b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
function verifyHmac(secret: string, header: string | undefined, body: string): boolean {
  const m = /t=(\d+),v1=([a-f0-9]+)/.exec(header ?? '');
  if (!m) return false;
  const expect = createHmac('sha256', secret).update(`${m[1]}.${body}`).digest('hex');
  try { return timingSafeEqual(Buffer.from(expect), Buffer.from(m[2])); } catch { return false; }
}

export function createServer(d: ServerDeps): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const method = req.method ?? 'GET';
    try {
      // --- health ---
      // A wallet is only healthy if it can still SIGN (key provider reachable) and still SEE work
      // (the discovery loop is polling successfully). A dead poller means pending transactions are
      // silently going unsigned, which must not report 200.
      if (method === 'GET' && (path === '/healthz' || path === '/health')) {
        const reasons: string[] = [];
        if (d.pause.paused) reasons.push('paused');   // deliberate (SR8) — degraded, not unhealthy
        const keyOk = await d.keyring.healthy();       // every scope's key provider reachable
        if (!keyOk) reasons.push('key_provider_unreachable');
        const pollerOk = d.poller ? d.poller.healthy() : true;
        if (!pollerOk) reasons.push('poller_stalled');
        const ok = keyOk && pollerOk;
        // Name the stalled scopes in `reasons`, not just the fact that something stalled. On a fleet,
        // "poller_stalled" alone sends an operator digging through logs to find which of twelve agents it
        // was; the page is the first thing they need and it is already known here.
        const scopeHealth = d.poller?.scopes?.();
        const stalled = scopeHealth?.filter((s) => !s.healthy).map((s) => s.page) ?? [];
        if (stalled.length) reasons.push(...stalled.map((p) => `poller_stalled:${p}`));
        return json(res, ok ? 200 : 503, {
          ok,
          paused: d.pause.paused,
          reasons,
          poller: d.poller ? { healthy: pollerOk, lastSuccess: d.poller.lastSuccess() || null } : undefined,
          // Only when there is more than one; a single-scope signer would just be repeating `poller`.
          scopes: scopeHealth && scopeHealth.length > 1 ? scopeHealth : undefined,
        });
      }
      // --- metrics ---
      // Decision counts are business intelligence about the org's approvals. Authenticated unless the
      // operator explicitly declares the port private (observability.metrics_public).
      if (method === 'GET' && path === '/metrics') {
        if (!d.metricsPublic) {
          if (!d.adminApiKey) return json(res, 403, { error: 'metrics disabled: set observability.metrics_public or admin.api_key' });
          if (!safeEqual(req.headers['x-api-key'], d.adminApiKey)) return json(res, 401, { error: 'unauthorized' });
        }
        res.writeHead(200, { 'content-type': 'text/plain' });
        return res.end(metrics.render());
      }
      // --- webhook trigger ---
      // The route exists ONLY when the webhook is enabled, and then only with an HMAC secret. Previously
      // it was registered unconditionally and the HMAC check was skipped when no secret was configured —
      // so anyone who could reach the port could drive orchestrator.handle() with arbitrary hashes. It
      // could not force a signature (policy still gates), but it was an unauthenticated trigger surface.
      if (method === 'POST' && path === '/v1/pending') {
        if (!d.webhookHmacSecret) return json(res, 403, { error: 'webhook disabled: enable trigger.webhook and set its hmac_secret' });
        const body = await readBody(req);
        const sigHeader = (d.webhookSignatureHeader ?? DEFAULT_SIGNATURE_HEADER).toLowerCase();
        const sig = (req.headers[sigHeader] ?? req.headers[LEGACY_SIGNATURE_HEADER]) as string | undefined;
        if (!verifyHmac(d.webhookHmacSecret, sig as string, body)) {
          return json(res, 401, { error: 'bad signature' });
        }
        const { tx_hash, signer_url } = JSON.parse(body || '{}');
        if (!tx_hash || !signer_url) return json(res, 400, { error: 'tx_hash and signer_url required' });
        metrics.inc('wallet_pending_seen_total');
        d.orchestrator.handle({ txHash: tx_hash, signerUrl: signer_url }).catch((e) => d.logger.error({ err: e.message }, 'handle failed'));
        return json(res, 202, { accepted: true, tx_hash });
      }
      // NOTE: there is no /v1/decisions callback. Async policy mode is not implemented (the config rejects
      // `policy.mode: async`), and an endpoint that accepts unauthenticated decision callbacks and merely
      // logs them is a liability, not a feature.
      // --- admin: ALWAYS authenticated ---
      // These routes pause signing (SR8), retry requests, and expose the signing key's identity. They are
      // served on the same listener as /healthz, which is bound publicly in most deploys — so an unset
      // api_key must DISABLE them, never open them. (Previously the check was skipped entirely when no key
      // was configured, leaving `POST /v1/admin/pause` open to anyone who could reach the port.)
      const isAdmin = path.startsWith('/v1/requests') || path.startsWith('/v1/admin') || path.startsWith('/v1/config');
      if (isAdmin) {
        if (!d.adminApiKey) return json(res, 403, { error: 'admin disabled: no admin.api_key configured' });
        if (!safeEqual(req.headers['x-api-key'], d.adminApiKey)) return json(res, 401, { error: 'unauthorized' });
      }
      // GET /v1/requests?limit=N[&status=a,b] — the audit view: recent requests, each with its receipt.
      //
      // `status` is what a work-queue UI is built on: `?status=awaiting_policy` is "everything the engine
      // has seen and not yet decided", i.e. the transactions a human still owes an answer on. Filtering
      // happens in the store, before the limit — see listRecent. An unknown status name is REJECTED rather
      // than ignored, because a silently-dropped filter returns a plausible-looking list of the wrong rows.
      if (method === 'GET' && path === '/v1/requests') {
        const raw = Number(url.searchParams.get('limit') ?? 50);
        // Clamp rather than reject: this backs an operator UI, and an out-of-range limit should show
        // something sensible instead of an error. The upper bound keeps a full history rewrite off the
        // response path of a store that holds thousands of rows.
        const limit = Number.isFinite(raw) ? Math.min(Math.max(Math.trunc(raw), 1), 500) : 50;
        const statusParam = url.searchParams.get('status');
        let statuses: RequestStatus[] | undefined;
        if (statusParam) {
          statuses = statusParam.split(',').map((s) => s.trim()).filter(Boolean) as RequestStatus[];
          const unknown = statuses.filter((s) => !REQUEST_STATUSES.includes(s));
          if (unknown.length) {
            return json(res, 400, { error: `unknown status: ${unknown.join(', ')}`, valid: REQUEST_STATUSES });
          }
        }
        return json(res, 200, { requests: await d.store.listRecent(limit, statuses) });
      }

      // GET /v1/requests/:tx
      let m = /^\/v1\/requests\/([a-f0-9]{64})$/.exec(path);
      if (method === 'GET' && m) {
        const reqRow = await d.store.get(m[1]);
        const receipt = await d.store.getReceipt(m[1]);
        if (!reqRow) return json(res, 404, { error: 'not found' });
        return json(res, 200, { request: reqRow, receipt });
      }
      // POST /v1/requests/:tx/retry
      m = /^\/v1\/requests\/([a-f0-9]{64})\/retry$/.exec(path);
      if (method === 'POST' && m) {
        const reqRow = await d.store.get(m[1]);
        if (!reqRow) return json(res, 404, { error: 'not found' });
        d.orchestrator.handle({ txHash: m[1], signerUrl: reqRow.signerUrl }).catch(() => {});
        return json(res, 202, { retrying: m[1] });
      }
      // POST /v1/admin/pause | resume
      if (method === 'POST' && path === '/v1/admin/pause') {
        d.pause.paused = true;
        d.logger.warn('SIGNING PAUSED');
        d.notify?.('signer.paused');
        return json(res, 200, { paused: true });
      }
      if (method === 'POST' && path === '/v1/admin/resume') {
        d.pause.paused = false;
        d.logger.warn('SIGNING RESUMED');
        d.notify?.('signer.resumed');
        return json(res, 200, { paused: false });
      }

      // GET /v1/admin/pubkey — the wallet's signing key(s) + Accumulate key hash(es), per page (for setup / SR6).
      // Multi-scope returns them all; the flat public_key/key_hash (first scope) stays for single-scope callers.
      if (method === 'GET' && path === '/v1/admin/pubkey') {
        const signers = await Promise.all(d.keyring.scopes().map(async (s) => {
          const pub = await s.signer.publicKey();
          return { page: s.page, public_key: bytesToHex(pub), key_hash: createHash('sha256').update(pub).digest('hex') };
        }));
        return json(res, 200, { signers, public_key: signers[0]?.public_key, key_hash: signers[0]?.key_hash });
      }

      // POST /v1/admin/key-page — governance on the org's OWN key page. TYPED, never blind.
      //
      // This replaces a `sign-governance` endpoint that signed an arbitrary caller-supplied 32-byte hash.
      // That was blind signing: the wallet could not know what it had authorised, and the "hash" could have
      // been ANY transaction — including one moving the org's tokens. Now the caller states an intent, the
      // wallet builds the transaction itself, forces the principal to its own page, signs what it built,
      // and confirms the result on-chain. There is no longer any way to make this key sign opaque bytes.
      //
      // PRIVILEGED: changing keys changes who can act for the org. Separate credential; fully audited.
      if (method === 'POST' && path === '/v1/admin/key-page') {
        if (!d.governanceAdminKey || !d.keyPage) return json(res, 403, { error: 'governance disabled (no admin.governance_admin_key configured)' });
        if (!safeEqual(req.headers['x-governance-key'], d.governanceAdminKey)) return json(res, 401, { error: 'unauthorized' });
        const body = await readBody(req);
        // Body carries the typed op; an optional `page` selects WHICH of our pages to govern (default: first).
        let op: KeyPageOp, page: string | undefined;
        try { const { page: p, ...rest } = JSON.parse(body || '{}'); op = rest as KeyPageOp; page = p; } catch { return json(res, 400, { error: 'body must be JSON' }); }

        // Resolve the key on the targeted page — this also validates it is a page we actually hold.
        const targetPage = page ?? d.keyring.scopes()[0]?.page;
        let pub: Uint8Array;
        try { pub = await d.keyring.forPage(targetPage).publicKey(); }
        catch (e) { return json(res, 400, { error: (e as Error).message }); }

        d.logger.warn(
          { audit: 'governance_operation', op, page: targetPage, key_hash: createHash('sha256').update(pub).digest('hex') },
          'GOVERNANCE OPERATION REQUESTED',
        );
        const result = await d.keyPage(op, targetPage);
        d.logger.warn({ audit: 'governance_operation_result', ok: result.ok, page: targetPage, submitted: result.submitted, keys: result.after?.keyHashes }, 'GOVERNANCE OPERATION COMPLETE');
        return json(res, result.ok ? 200 : 400, result);
      }

      return json(res, 404, { error: 'not found' });
    } catch (e) {
      d.logger.error({ err: (e as Error).message, path }, 'server error');
      return json(res, 500, { error: 'internal error' });
    }
  });
}
