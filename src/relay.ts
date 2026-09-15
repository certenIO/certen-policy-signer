/**
 * Read-only relay. Business Transaction Controls runbook Phase 5.3 (FICTIONAL lab), decision P2.
 *
 * P2: in every cell the headless signer is the ONLY component that talks to the CERTEN gateway or to
 * chains. A component that must READ Accumulate, the gateway's proof API or an EVM chain (the payment
 * hub's release gate) therefore reads through this relay rather than acquiring a chain client of its own.
 *
 * READ-ONLY BY CONSTRUCTION, not by convention:
 *   - Accumulate: only `query` is ever called; there is no route that reaches `submit`.
 *   - Gateway: an exact allowlist of GET proof/transaction paths; path params are validated; no query
 *     string, body or caller header is forwarded; redirects are not followed (the api key stays put).
 *   - EVM: an allowlist of read JSON-RPC methods; a batch containing any other method is refused WHOLE
 *     and nothing is forwarded.
 *   - No route touches the keyring (P3): nothing here can sign, and no response carries key material,
 *     the relay token, the gateway api key or an RPC URL (which often embeds a provider key).
 *
 * Bodies are passed through as the upstream returned them. They are READINGS for the caller to verify,
 * not evidence the relay vouches for — e.g. a proof's `requiredLevel` is relayer-set and never evidence (F5).
 */
import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { normalizeTxRecord, isDefinitiveNotFound } from './accumulate/raw-client.js';
import { Logger } from './logger.js';

export const RELAY_PREFIX = '/v1/relay';

export const EVM_READ_METHODS: ReadonlySet<string> = new Set([
  'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getTransactionReceipt',
  'eth_getTransactionByHash', 'eth_getLogs', 'eth_call', 'eth_getCode',
]);

const MAX_RPC_BODY = 1024 * 1024;
const MAX_BATCH = 100;
const HEX64 = /^(?:0x)?[0-9a-fA-F]{64}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
/** Accumulate URL: authority + optional path; no userinfo, query, fragment, spaces or `@`. */
const ACC_URL = /^acc:\/\/[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9._-]+)*\/?$/;
/** `.` / `..` path segments are refused outright rather than normalized. */
const DOT_SEGMENT = /(^|\/)\.{1,2}(\/|$)/;
const TX_ID = /^acc:\/\/([0-9a-fA-F]{64})@([A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9._-]+)*)$/;

export interface RelayDeps {
  /** Bearer token callers must present. Resolved secret; never logged or echoed. */
  token: string;
  /** Accumulate v3 `query` (RawAccumulateClient.query). The only Accumulate call the relay can make. */
  query: (scope: string, query?: unknown) => Promise<any>;
  gateway?: { url: string; apiKey: string };
  evm: Array<{ chainId: number; rpcUrl: string }>;
  timeoutMs?: number;
  logger: Logger;
  /** Test seam; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
}

export type RelayHandler = (req: http.IncomingMessage, res: http.ServerResponse, url: URL) => Promise<void>;

function send(res: http.ServerResponse, code: number, obj: unknown) {
  // JSON only, never cached, and deliberately no Access-Control-* headers: a browser page on another
  // origin gets nothing from this surface.
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(obj));
}

/**
 * Constant-time bearer check. Both sides are hashed first so the comparison runs over equal-length
 * buffers whatever the caller sent — a length mismatch must not return early and leak the token length.
 */
export function bearerMatches(header: string | string[] | undefined, token: string): boolean {
  if (!token || typeof header !== 'string') return false;
  const m = /^Bearer ([^\s]+)$/.exec(header);
  const given = createHash('sha256').update(m ? m[1] : '').digest();
  const expected = createHash('sha256').update(token).digest();
  return timingSafeEqual(given, expected) && m !== null;
}

function readCapped(req: http.IncomingMessage, cap: number): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0, over = false;
    req.on('data', (c: Buffer) => {
      if (over) return;
      size += c.length;
      if (size > cap) { over = true; resolve(null); return; }
      chunks.push(c);
    });
    req.on('end', () => { if (!over) resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}

type GatewayRoute = { re: RegExp; param: 'hash' | 'uuid'; to: (p: string) => string };
/**
 * The gateway paths the relay will fetch — exactly these (api-gateway src/routes/proof.routes.ts and
 * transaction.routes.ts), with nothing derived from caller input but the validated param.
 */
export const GATEWAY_ROUTES: readonly GatewayRoute[] = [
  { re: /^\/v1\/relay\/gateway\/proof\/tx\/([^/]+)\/receipt$/, param: 'hash', to: (p) => `/v1/proof/tx/${p}/receipt` },
  { re: /^\/v1\/relay\/gateway\/proof\/tx\/([^/]+)$/, param: 'hash', to: (p) => `/v1/proof/tx/${p}` },
  { re: /^\/v1\/relay\/gateway\/proof\/([^/]+)\/bundle$/, param: 'uuid', to: (p) => `/v1/proof/${p}/bundle` },
  { re: /^\/v1\/relay\/gateway\/proof\/([^/]+)$/, param: 'uuid', to: (p) => `/v1/proof/${p}` },
  { re: /^\/v1\/relay\/gateway\/transaction\/([^/]+)$/, param: 'uuid', to: (p) => `/v1/transaction/${p}` },
];

export function createRelayHandler(d: RelayDeps): RelayHandler {
  if (!d.token) throw new Error('relay: refusing to start without a token');
  const doFetch = d.fetchImpl ?? fetch;
  const timeoutMs = d.timeoutMs ?? 15_000;
  const chains = new Map(d.evm.map((c) => [c.chainId, c.rpcUrl]));

  async function upstream(url: string, init: RequestInit): Promise<{ status: number; body: unknown } | { error: string }> {
    let r: Response;
    try {
      r = await doFetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      // The error text can carry the URL (and so an embedded provider key): log the kind, return nothing.
      d.logger.warn({ err: (e as Error).name }, 'relay: upstream unreachable');
      return { error: 'upstream unreachable' };
    }
    if (r.status >= 300 && r.status < 400) return { error: 'upstream redirected; not followed' };
    const text = await r.text();
    if (d.gateway?.apiKey && text.includes(d.gateway.apiKey)) return { error: 'upstream response withheld' };
    if (text === '') return { status: r.status, body: null };
    try { return { status: r.status, body: JSON.parse(text) }; }
    catch { return { error: 'upstream returned non-JSON' }; }
  }

  return async (req, res, url) => {
    const path = url.pathname;
    const method = req.method ?? 'GET';
    if (!bearerMatches(req.headers['authorization'], d.token)) return send(res, 401, { error: 'unauthorized' });

    // --- Accumulate ---
    if (path === `${RELAY_PREFIX}/accumulate/tx`) {
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      const id = url.searchParams.get('id') ?? '';
      const m = TX_ID.exec(id);
      if (!m || DOT_SEGMENT.test(m[2])) return send(res, 400, { error: 'id must be acc://<64-hex-hash>@<principal>' });
      let rec: any;
      try { rec = await d.query(id); }
      catch (e) { return accError(res, e); }
      const out = normalizeTxRecord(rec);
      if (!out.txid) out.txid = id;
      if (!out.hash) out.hash = m[1].toLowerCase();
      return send(res, 200, out);
    }
    if (path === `${RELAY_PREFIX}/accumulate/account`) {
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      const acct = url.searchParams.get('url') ?? '';
      if (!ACC_URL.test(acct) || DOT_SEGMENT.test(acct.slice(6))) return send(res, 400, { error: 'url must be an acc:// account URL' });
      let rec: any;
      try { rec = await d.query(acct); }
      catch (e) { return accError(res, e); }
      return send(res, 200, rec?.account ?? rec);
    }

    // --- Gateway ---
    if (path.startsWith(`${RELAY_PREFIX}/gateway/`)) {
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      let target: string | undefined;
      let bad: string | undefined;
      for (const r of GATEWAY_ROUTES) {
        const m = r.re.exec(path);
        if (!m) continue;
        // Validated on the raw segment: no percent-decoding, so nothing encoded can smuggle a `/` or `..`.
        const param = m[1];
        if (r.param === 'hash') {
          if (HEX64.test(param)) target = r.to(param.replace(/^0x/, '').toLowerCase());
          else bad = 'hash must be 64 hex characters';
        } else if (UUID.test(param)) target = r.to(param.toLowerCase());
        else bad = 'id must be a UUID';
        break;
      }
      if (bad) return send(res, 400, { error: bad });
      if (!target) return send(res, 404, { error: 'not found' });
      if (!d.gateway) return send(res, 503, { error: 'relay gateway not configured' });
      const out = await upstream(d.gateway.url.replace(/\/+$/, '') + target, {
        method: 'GET', headers: { accept: 'application/json', 'x-api-key': d.gateway.apiKey },
      });
      if ('error' in out) return send(res, 502, { error: out.error });
      return send(res, out.status, out.body);
    }

    // --- EVM ---
    const em = new RegExp(`^${RELAY_PREFIX}/evm/([^/]+)$`).exec(path);
    if (em) {
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      if (!/^[1-9][0-9]{0,15}$/.test(em[1])) return send(res, 400, { error: 'chainId must be a positive integer' });
      const rpcUrl = chains.get(Number(em[1]));
      if (!rpcUrl) return send(res, 404, { error: 'unknown chain' });
      if (Number(req.headers['content-length'] ?? 0) > MAX_RPC_BODY) return send(res, 413, { error: 'body too large' });
      const raw = await readCapped(req, MAX_RPC_BODY);
      if (raw === null) return send(res, 413, { error: 'body too large' });
      let parsed: unknown;
      try { parsed = JSON.parse(raw); }
      catch { return send(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
      const checked = checkRpc(parsed);
      if ('reject' in checked) return send(res, 200, checked.reject);
      const out = await upstream(rpcUrl, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(checked.forward),
      });
      if ('error' in out) return send(res, 502, { error: out.error });
      return send(res, out.status, out.body);
    }

    return send(res, 404, { error: 'not found' });
  };
}

function accError(res: http.ServerResponse, e: unknown) {
  const msg = (e as Error)?.message ?? '';
  // "No such record" is an answer (404); anything else is a failure to ask (502), never an empty record.
  if (isDefinitiveNotFound(msg)) return send(res, 404, { error: 'not found' });
  return send(res, 502, { error: 'accumulate query failed' });
}

type RpcReq = { jsonrpc: '2.0'; id?: unknown; method: string; params?: unknown };
const rpcErr = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });

/**
 * Validate a JSON-RPC request or batch against the read allowlist. Only re-serialized, validated fields
 * are forwarded. A batch with ANY invalid or forbidden entry is refused whole — partially forwarding a
 * batch would make "nothing forbidden reached the node" depend on per-entry bookkeeping.
 */
export function checkRpc(parsed: unknown): { forward: RpcReq | RpcReq[] } | { reject: unknown } {
  const one = (e: unknown): { ok: RpcReq } | { err: unknown } => {
    if (!e || typeof e !== 'object' || Array.isArray(e)) return { err: rpcErr(null, -32600, 'invalid request') };
    const o = e as Record<string, unknown>;
    const id = typeof o.id === 'string' || typeof o.id === 'number' || o.id === null ? o.id : null;
    if (o.jsonrpc !== '2.0' || typeof o.method !== 'string') return { err: rpcErr(id, -32600, 'invalid request') };
    if (!EVM_READ_METHODS.has(o.method)) return { err: rpcErr(id, -32601, `method not allowed by relay: ${o.method.slice(0, 64)}`) };
    if (o.params !== undefined && (typeof o.params !== 'object' || o.params === null)) return { err: rpcErr(id, -32602, 'invalid params') };
    return { ok: { jsonrpc: '2.0', ...(o.id !== undefined ? { id } : {}), method: o.method, ...(o.params !== undefined ? { params: o.params } : {}) } };
  };
  if (!Array.isArray(parsed)) {
    const r = one(parsed);
    return 'ok' in r ? { forward: r.ok } : { reject: r.err };
  }
  if (parsed.length === 0 || parsed.length > MAX_BATCH) return { reject: rpcErr(null, -32600, `batch must hold 1..${MAX_BATCH} requests`) };
  const results = parsed.map(one);
  if (results.every((r) => 'ok' in r)) return { forward: results.map((r) => (r as { ok: RpcReq }).ok) };
  return {
    reject: results.map((r, i) => ('err' in r ? r.err
      : rpcErr((parsed[i] as Record<string, unknown>).id, -32600, 'batch refused: it contains a request the relay does not allow'))),
  };
}

/** A dedicated listener for the relay when `relay.bind` is set; otherwise the relay shares the health server. */
export function createRelayServer(handler: RelayHandler, logger: Logger): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (url.pathname === RELAY_PREFIX || url.pathname.startsWith(`${RELAY_PREFIX}/`)) return await handler(req, res, url);
      send(res, 404, { error: 'not found' });
    } catch (e) {
      logger.error({ err: (e as Error).name }, 'relay error');
      if (!res.headersSent) send(res, 500, { error: 'internal error' });
    }
  });
}
