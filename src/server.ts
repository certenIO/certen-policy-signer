/** HTTP surface: health, metrics, webhook trigger, admin. Routes are documented in docs/OPERATIONS.md. */
import http from 'node:http';
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { bytesToHex } from './accumulate/signing.js';
import { KeyPageOp, KeyPageResult } from './ops/keypage.js';
import { PageState } from './ops/rotate.js';
import { KeyPageGuardError } from './ops/keypage-guard.js';
import { Orchestrator } from './orchestrator.js';
import { bookOf } from './delegation/path.js';
import { WrapperRegistry } from './registry/wrappers.js';
import { Store, keyOf } from './store/store.js';
import { Keyring } from './signer/keyring.js';
import { AccumulateClient } from './accumulate/client.js';
import { metrics } from './metrics.js';
import { Logger } from './logger.js';
import { DEFAULT_SIGNATURE_HEADER, LEGACY_SIGNATURE_HEADER } from './policy/policy.js';
import { REQUEST_STATUSES, RequestStatus } from './types.js';
import { NotifyEvent } from './notify.js';
import { RelayHandler, RELAY_PREFIX } from './relay.js';
import { RelayClientsHandler, RELAY_CLIENT_PREFIX } from './relay-clients.js';
import { OfficerIntakeHandler, OFFICER_PATHS } from './officer/intake.js';
import type { PauseControl, PauseOutcome } from './binding/pause-store.js';
import type { PinControl } from './binding/pin-store.js';

export type { PauseControl } from './binding/pause-store.js';

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
  /** Wrapper mode: the enrolment registry behind `/v1/admin/wrappers`. Absent => that route is 404. */
  wrapperRegistry?: WrapperRegistry;
  /** Wrapper mode: our own book, which every subscriber's book must sort after. */
  wrapperOurBook?: string;
  orchestrator: Orchestrator;
  store: Store;
  keyring: Keyring;
  accumulate: AccumulateClient;
  /** The PERSISTED pause (seat and subject scopes, DECISION.md section 6): `/healthz` reads it, `/v1/admin/pause` and `/resume` change it. */
  pause: PauseControl;
  /** The persisted policy pin of every bound seat (DE-93, DE-94): `GET` and `POST /v1/admin/pin`. Absent: the routes answer 404. */
  pins?: PinControl;
  /** Voids decision nonces (`POST /v1/admin/decisions/void`). Absent => that route is 404. */
  nonces?: { voidNonces(nonces: string[], reason: string): Promise<{ voided: string[] }> };
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
  /**
   * Read one of our key pages off the chain. Absent => GET /v1/admin/page is disabled.
   *
   * Injected as a function rather than reached through `accumulate` above, for the same reason
   * `keyPage` is: this file has no business holding a chain client, and a test wants to answer the
   * route without one. index.ts wires it to `readPage`.
   */
  pageState?: (page: string) => Promise<PageState>;
  /** The poller, when enabled — a wallet whose discovery loop is dead is NOT healthy. */
  poller?: HealthSource;
  /** Serve /metrics without authentication (only when the port is already private). */
  metricsPublic?: boolean;
  /** Fire a lifecycle notification. Absent when no `notify.url` is configured. Best-effort by contract. */
  notify?: (event: NotifyEvent) => void;
  /** Read-only relay (src/relay.ts), when `relay.enabled` and no separate `relay.bind`. Absent => /v1/relay/* is 404. */
  relay?: RelayHandler;
  /** Decision-service relay (src/relay-clients.ts, Phase 6.4), when `admin.relay_clients` is set. Absent => /relay/* is 404. */
  relayClients?: RelayClientsHandler;
  /** Officer intake (src/officer/intake.ts, Phase 7), when `officer_intake.enabled`. Its own authentication; absent => 404. */
  officerIntake?: OfficerIntakeHandler;
  /** Shown on /v1/config/version for the admin views (Phase 6.3). */
  configVersion?: string;
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
/**
 * The rows a `/v1/requests/:key` route addresses. A work key (`<hash>:<path>`, one wrapper path) names ONE row; a bare tx hash names
 * every page-keyed row of the transaction: the keyed seat's and each human-only seat's (review #1), never a wrapper path's.
 */
async function requestRows(store: Store, key: string) {
  if (key.includes(':')) {
    const row = await store.get(key);
    return row ? [row] : [];
  }
  return store.listForTx(key);
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
      // --- read-only relay (P2) --- its own bearer token; never falls through to the admin routes.
      if (path === RELAY_PREFIX || path.startsWith(`${RELAY_PREFIX}/`)) {
        if (!d.relay) return json(res, 404, { error: 'not found' });
        return await d.relay(req, res, url);
      }
      // --- officer intake (Phase 7) --- authenticated by the officer's own key, never by a relay client key.
      if (OFFICER_PATHS(path)) {
        if (!d.officerIntake) return json(res, 404, { error: 'not found' });
        return await d.officerIntake(req, res, url);
      }
      // --- decision-service relay (6.4) --- per-client key + scopes; never falls through to the admin routes.
      if (path === RELAY_CLIENT_PREFIX || path.startsWith(`${RELAY_CLIENT_PREFIX}/`)) {
        if (!d.relayClients) return json(res, 404, { error: 'not found' });
        return await d.relayClients(req, res, url);
      }
      // --- health ---
      // A wallet is only healthy if it can still SIGN (key provider reachable) and still SEE work
      // (the discovery loop is polling successfully). A dead poller means pending transactions are
      // silently going unsigned, which must not report 200.
      if (method === 'GET' && (path === '/healthz' || path === '/health')) {
        const reasons: string[] = [];
        const paused = d.pause.anyPaused();
        if (paused) reasons.push('paused');   // deliberate (SR8) — degraded, not unhealthy
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
          paused,
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
        const { tx_hash, signer_url, principal, wrapper_book } = JSON.parse(body || '{}');
        if (!tx_hash || !signer_url) return json(res, 400, { error: 'tx_hash and signer_url required' });
        metrics.inc('wallet_pending_seen_total');
        // `principal` and `wrapper_book` are ROUTING HINTS (wrapper runbook, change 1): where to read the
        // transaction and the votes. Nothing is taken on their word — the path is derived from the votes
        // recorded at that wrapper book, and a wrong hint finds none. A hint that is not an acc:// URL is
        // dropped rather than passed on.
        const hint = (v: unknown) => (typeof v === 'string' && /^acc:\/\/[^\s]+$/i.test(v) ? v : undefined);
        const p = hint(principal);
        const wb = hint(wrapper_book);
        d.orchestrator.handleAll({ txHash: tx_hash, signerUrl: signer_url, ...(p ? { principal: p } : {}), ...(wb ? { wrapperBook: wb } : {}) })
          .catch((e) => d.logger.error({ err: e.message }, 'handle failed'));
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

      // GET /v1/requests/:key — the tx hash, or `<hash>:<16 hex>` for one wrapper path's vote.
      let m = /^\/v1\/requests\/([a-f0-9]{64}(?::[a-f0-9]{16})?)$/.exec(path);
      if (method === 'GET' && m) {
        // Every page's record for this transaction (review #1: a keyed seat and a human-only seat each keep
        // their own). `request` is the keyed seat's when there is one, else the first; `seats` lists them all.
        const rows = await requestRows(d.store, m[1]);
        const reqRow = rows.find((r) => !r.recordId) ?? rows[0];
        if (!reqRow) return json(res, 404, { error: 'not found' });
        const receipt = await d.store.getReceipt(keyOf(reqRow));
        const seats = await Promise.all(rows.map(async (r) => ({ page: r.signerUrl, request: r, receipt: await d.store.getReceipt(keyOf(r)) })));
        // G-64: WHY the seat is holding (`pending`, only while it is) and the last hold once it ended
        // (`pendingFinal`). Also on `request`; repeated here so a reader need not know the row's shape.
        return json(res, 200, { request: reqRow, receipt, pending: reqRow.pending ?? null, pendingFinal: reqRow.pendingFinal ?? null, seats });
      }
      // POST /v1/requests/:key/retry
      m = /^\/v1\/requests\/([a-f0-9]{64}(?::[a-f0-9]{16})?)\/retry$/.exec(path);
      if (method === 'POST' && m) {
        // One row for a work key (`hash:path`), else every page-keyed row of the transaction (a keyed seat's and each human-only seat's).
        const rows = await requestRows(d.store, m[1]);
        if (!rows.length) return json(res, 404, { error: 'not found' });
        for (const reqRow of rows) {
          // The transaction, not the stored path: in wrapper mode the paths are re-derived from chain state,
          // so a retry can never replay a path the chain no longer supports.
          d.orchestrator.handleAll({
            txHash: reqRow.txHash, signerUrl: reqRow.signerUrl, ...(reqRow.principal ? { principal: reqRow.principal } : {}),
            // Where to read, not what to sign: the path is re-derived from the votes recorded there.
            ...(reqRow.delegators?.length ? { wrapperBook: bookOf(reqRow.delegators[0]!) } : {}),
          }).catch(() => {});
        }
        return json(res, 202, { retrying: m[1] });
      }
      // GET|POST /v1/admin/wrappers — the enrolment registry (wrapper mode). POST registers a wrapper as
      // ENROLLING, before its creation transaction is submitted, so discovery watches it and the creation
      // vote is recognised. It never makes a wrapper active: that happens only when the creation executes
      // on chain and the result passes the wrapper check (wrapper runbook, change 6).
      if (path === '/v1/admin/wrappers' && (method === 'GET' || method === 'POST')) {
        if (!d.wrapperRegistry) return json(res, 404, { error: 'not in wrapper mode' });
        if (method === 'GET') return json(res, 200, { wrappers: await d.wrapperRegistry.list() });
        let b: any;
        try { b = JSON.parse((await readBody(req)) || '{}'); } catch { return json(res, 400, { error: 'body must be JSON' }); }
        const book = typeof b.wrapper_book === 'string' ? b.wrapper_book.replace(/\/+$/, '') : '';
        if (!/^acc:\/\/[^\s/]+(\/[^\s/]+)+$/i.test(book) || /\/\d+$/.test(book)) return json(res, 400, { error: 'wrapper_book must be an acc:// key book URL' });
        if (typeof b.subject_id !== 'string' || !b.subject_id || b.subject_id.length > 256) return json(res, 400, { error: 'subject_id required (at most 256 characters)' });
        // The subscriber's own book, the wrapper's other delegate. The creation vote requires exactly this
        // book, so the wrapper we join is the one the subject enrolled.
        const subscriberBook = typeof b.subscriber_book === 'string' ? b.subscriber_book.replace(/\/+$/, '') : '';
        if (!/^acc:\/\/[^\s/]+(\/[^\s/]+)+$/i.test(subscriberBook) || /\/\d+$/.test(subscriberBook)) return json(res, 400, { error: 'subscriber_book must be an acc:// key book URL (the subscriber\'s own book, not a page)' });
        if (!d.wrapperOurBook) return json(res, 500, { error: 'wrapper mode without our own book configured' });
        if (subscriberBook.toLowerCase() === d.wrapperOurBook.replace(/\/+$/, '').toLowerCase()) return json(res, 400, { error: 'subscriber_book cannot be our own book' });
        const existing = await d.wrapperRegistry.get(book);
        if (existing && existing.status !== 'enrolling') return json(res, 409, { error: 'already an active wrapper', wrapper: existing });
        // The subject is what every later vote through this wrapper stands for. Re-registering under a
        // different subject is refused rather than silently re-pointed, even before activation.
        if (existing && (existing.subjectId !== b.subject_id || (existing.subscriberBook && existing.subscriberBook.toLowerCase() !== subscriberBook.toLowerCase()))) {
          return json(res, 409, { error: 'already enrolling for a different subject or subscriber book', wrapper: existing });
        }
        const entry = { wrapperBook: book, wrapperPage: `${book}/1`, subjectId: b.subject_id, subscriberBook, enrolledAt: 0, seats: [], status: 'enrolling' as const };
        await d.wrapperRegistry.upsert(entry);
        d.logger.info({ audit: 'wrapper_enrolling', wrapper: book, subject: b.subject_id, subscriberBook }, 'wrapper registered as enrolling');
        return json(res, 201, { wrapper: entry });
      }
      // GET /v1/config/version — the signer-config version stamped on every PolicyRequest and Receipt (6.3).
      if (method === 'GET' && path === '/v1/config/version') {
        return json(res, 200, { configVersion: d.configVersion ?? null });
      }
      // GET|POST /v1/admin/pause, POST /v1/admin/resume — the PERSISTED pause (DAX-4S, DECISION.md section 6).
      //
      // Body `{scope?, id?, by, reason}`: `scope` is `seat` or `subject` and `id` the seat id or the subject ADI; without a scope the
      // call acts on EVERY configured seat (the old "stop everything"; a pause on a subject is never lifted by it). `by` is a named
      // seat (`seat:<name>`) and `reason` at least ten characters: a pause without a seat, a resume without a reason and a resume
      // of what is not paused are refused by name (DE-26); pausing what is already paused answers 200 `status: already_paused` (idempotent, DE-78). `by` is the caller's declaration, authenticated only as far as the admin
      // key is. The pause is durable before the answer is sent, survives a restart, and is read again before every signature.
      if (method === 'GET' && path === '/v1/admin/pause') {
        const st = d.pause.snapshot();
        return json(res, 200, { paused: st.pauses.length > 0, pauses: st.pauses, seats: d.pause.seats() });
      }
      if (method === 'POST' && (path === '/v1/admin/pause' || path === '/v1/admin/resume')) {
        const pausing = path === '/v1/admin/pause';
        let b: any;
        try { b = JSON.parse((await readBody(req)) || '{}'); } catch { return json(res, 400, { error: 'body must be JSON' }); }
        if (b === null || typeof b !== 'object' || Array.isArray(b)) return json(res, 400, { error: 'body must be a JSON object' });
        const by = typeof b.by === 'string' ? b.by : '';
        const reason = typeof b.reason === 'string' ? b.reason : '';
        let out: PauseOutcome;
        if (b.scope === undefined && b.id === undefined) {
          out = pausing ? await d.pause.setAllSeats(by, reason) : await d.pause.resumeAllSeats(by, reason);
        } else {
          const op = { scope: b.scope, id: b.id, by, reason };
          out = pausing ? await d.pause.set(op) : await d.pause.resume(op);
        }
        if (!out.ok) {
          const status = out.reason === 'not_paused' ? 409 : out.reason.startsWith('journal_') ? 500 : 400;
          d.logger.warn({ audit: pausing ? 'pause_refused' : 'resume_refused', reason: out.reason, detail: out.detail }, 'pause change refused');
          return json(res, status, { error: out.reason, ...(out.detail !== undefined ? { detail: out.detail } : {}) });
        }
        d.logger.warn({ audit: pausing ? 'signing_paused' : 'signing_resumed', scope: b.scope ?? 'all seats', id: b.id, by, reason }, pausing ? 'SIGNING PAUSED' : 'SIGNING RESUMED');
        d.notify?.(pausing ? 'signer.paused' : 'signer.resumed');
        return json(res, 200, { paused: out.state.pauses.length > 0, pauses: out.state.pauses, ...(out.status ? { status: out.status } : {}) });
      }
      // GET|POST /v1/admin/pin — the policy pin step (DE-93, DE-94). Body `{seat, hash, by, reason}`: `hash` must be the rule-set hash the seat LOADED at boot
      // (`GET` shows it beside the pin and the phase), `by` a named seat identity (`seat:<name>`) and `reason` at least ten characters. The step is durable (a
      // `policy.pinned` entry of the journal) before the answer, survives a restart, and repeating it for the pinned hash is idempotent (200, no second entry).
      // A seat that is not pinned decides nothing; a seat whose loaded hash differs from its pin is `pin_stale` until the step is repeated.
      if (path === '/v1/admin/pin' && (method === 'GET' || method === 'POST')) {
        if (!d.pins) return json(res, 404, { error: 'not found' });
        if (method === 'GET') return json(res, 200, { seats: d.pins.snapshot() });
        let b: any;
        try { b = JSON.parse((await readBody(req)) || '{}'); } catch { return json(res, 400, { error: 'body must be JSON' }); }
        if (b === null || typeof b !== 'object' || Array.isArray(b)) return json(res, 400, { error: 'body must be a JSON object' });
        const out = await d.pins.pin({ seat: b.seat, hash: b.hash, by: typeof b.by === 'string' ? b.by : '', reason: b.reason });
        if (!out.ok) {
          d.logger.warn({ audit: 'policy_pin_refused', reason: out.reason, detail: out.detail }, 'policy pin step refused');
          return json(res, out.reason.startsWith('journal_') ? 500 : 400, { error: out.reason, ...(out.detail !== undefined ? { detail: out.detail } : {}) });
        }
        d.logger.warn({ audit: 'policy_pinned', seat: b.seat, hash: b.hash, by: b.by, reason: b.reason, idempotent: out.idempotent === true }, 'POLICY PINNED');
        return json(res, 200, { phase: out.phase, ...(out.idempotent === true ? { idempotent: true } : { previous: out.previous ?? null }) });
      }
      // POST /v1/admin/decisions/void {nonces, reason} — marks decision nonces spent without a decision being accepted: the old
      // nonce of a decision a recheck voided (re-issued, denied, expired), so the old decision cannot be used even by a seat that
      // pins no policy. Idempotent and durable.
      if (method === 'POST' && path === '/v1/admin/decisions/void') {
        if (!d.nonces) return json(res, 404, { error: 'not found' });
        let b: any;
        try { b = JSON.parse((await readBody(req)) || '{}'); } catch { return json(res, 400, { error: 'body must be JSON' }); }
        if (!Array.isArray(b?.nonces) || typeof b?.reason !== 'string' || b.reason.length === 0) return json(res, 400, { error: 'nonces (array) and reason required' });
        try {
          const r = await d.nonces.voidNonces(b.nonces, b.reason);
          d.logger.warn({ audit: 'nonces_voided', count: r.voided.length, reason: b.reason }, 'decision nonces voided');
          return json(res, 200, r);
        } catch (e) {
          return json(res, e instanceof Error && (e as { reason?: string }).reason === 'nonce_malformed' ? 400 : 500, { error: (e as { reason?: string }).reason ?? 'void failed' });
        }
      }

      // GET /v1/admin/pubkey — the wallet's signing key(s) + Accumulate key hash(es), per page (for setup / SR6).
      // Multi-scope returns them all; the flat public_key/key_hash (first scope) stays for single-scope callers.
      // `signature_type` is here because a caller must not infer it. Since a scope's key may be a
      // certificate, `public_key` is no longer necessarily 32 bytes (91 for P-256 PKIX DER) -- and a
      // screen reading an algorithm off a field's LENGTH would assert something this signer never said.
      // `key_hash` is sha256(public_key) for every type alike, and is the page entry.
      if (method === 'GET' && path === '/v1/admin/pubkey') {
        const signers = await Promise.all(d.keyring.scopes().map(async (s) => {
          const pub = await s.signer.publicKey();
          return {
            page: s.page,
            signature_type: s.signer.signatureType,
            public_key: bytesToHex(pub),
            key_hash: createHash('sha256').update(pub).digest('hex'),
          };
        }));
        return json(res, 200, { signers, public_key: signers[0]?.public_key, key_hash: signers[0]?.key_hash });
      }

      // GET /v1/admin/page - the authority the NETWORK will enforce, per scope, read live off the chain.
      //
      // /v1/admin/pubkey above answers "which key do we sign with". This answers "and what does the page
      // that key sits on actually require" -- threshold, seats, delegates, version. The approval console
      // renders it (Runbook F Phase F1): the console holds no chain code and must never acquire any, so
      // everything it can say about on-chain authority has to arrive through a route like this one.
      //
      // A page that cannot be read yields a REASON AND NO NUMBERS. The tempting alternative -- zeroes,
      // or a 500 for the whole route -- is worse in both directions: a threshold of 0 is a plausible
      // number meaning "this page requires nobody", and one unreadable page is not an outage of the
      // others. Per scope, so an operator sees which one is unreachable.
      if (method === 'GET' && path === '/v1/admin/page') {
        if (!d.pageState) return json(res, 403, { error: 'page state unavailable: no page reader configured' });
        const pages = await Promise.all(d.keyring.scopes().map(async (s) => {
          const head = { page: s.page, book: s.book, signature_type: s.signer.signatureType };
          try {
            const st = await d.pageState!(s.page);
            return {
              ...head,
              state: {
                version: st.version,
                threshold: st.threshold,
                entry_count: st.entries.length,
                entries: st.entries.map((e) => ({ key_hash: e.keyHash, delegate: e.delegate })),
              },
            };
          } catch (e) {
            return { ...head, error: (e as Error).message };
          }
        }));
        return json(res, 200, { pages });
      }

      /**
       * GET /v1/admin/tx-signatures?txid=acc://<hash>@<principal> — WHO SIGNED, as the chain has it.
       *
       * The approval console cannot ask this itself. Invariant F-1 keeps chain work in the signer, and
       * its `check-no-chain-code` lint specifically refuses a computed `sha256` in the authority
       * module — because hashing a key to compare it against a page entry is a two-line change nobody
       * would think of as adopting chain code, and it is one.
       *
       * So the console could report *the organisation signed in her name* — our own signer made that
       * signature and knew which key it used — and could not report *she signed*, because her
       * certificate signs on chain and nobody read it back. One direction had an alarm and the other
       * had silence, and silence gets read as absence. T32.
       *
       * FACTS ONLY: status, algorithm, key hash, delegators. WHOSE key it is stays a question this
       * route does not answer — a key page entry is `sha256(publicKey)` for every key type alike, so
       * nothing here distinguishes a person's certificate from a piece of software. The caller matches
       * these against a roster its own people agreed, and the record must keep saying which half is a
       * reading and which half is a declaration.
       */
      if (method === 'GET' && path === '/v1/admin/tx-signatures') {
        const read = d.accumulate.getTxSignatures?.bind(d.accumulate);
        if (!read) return json(res, 501, { error: 'this signer cannot read transaction signatures' });

        const txid = (url.searchParams.get('txid') ?? '').trim();
        const m = /^(?:acc:\/\/)?([0-9a-fA-F]{64})@(.+)$/.exec(txid);
        if (!m) {
          return json(res, 400, {
            // The hash alone is not enough: the network is asked for a transaction ON an account, so
            // the principal is part of the address rather than decoration.
            error: 'txid must be acc://<64-hex-hash>@<principal>',
            example: 'acc://5770d714…532588@twoa1788601803711.acme/data',
          });
        }

        const out = await read(m[1]!, m[2]!);
        // 503 when we could not ASK. A 200 with an empty list would say "nobody signed", which is a
        // different fact and the one nobody may invent.
        return json(res, out.unavailable ? 503 : 200, {
          txid,
          status: out.status,
          delivered: out.delivered,
          signature_count: out.signatures.length,
          signatures: out.signatures.map((s) => ({
            type: s.type,
            public_key_hash: s.publicKeyHash,
            delegators: s.delegators,
            ...(s.signer ? { signer: s.signer } : {}),
          })),
          ...(out.unavailable ? { unavailable: out.unavailable } : {}),
        });
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
        let result: KeyPageResult;
        try {
          result = await d.keyPage(op, targetPage);
        } catch (e) {
          // G-65: the page could not be read at decision time. Nothing was signed; say why, distinctly.
          if (!(e instanceof KeyPageGuardError)) throw e;
          d.logger.warn({ audit: 'governance_operation_refused', page: targetPage, refusal: e.refusal }, 'GOVERNANCE OPERATION REFUSED');
          return json(res, e.refusal.reason === 'page_unreadable' ? 503 : 400, { ok: false, op: (op as { op?: unknown })?.op ?? null, submitted: [], error: e.refusal.reason, refusal: e.refusal });
        }
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
