/**
 * Decision-service relay on the admin API. FICTIONAL Business Transaction Controls lab, Phase 6.4.
 * Contract: transaction-controls docs/interfaces/phase6-seat-contract.md §2.
 *
 * P2: a seat's Console decision service has no chain code, no keys and no gateway client, so everything it
 * must read (proofs, who signed, receipts, an FDBUSD `holderStatus`) and the one thing it may ask for
 * (governance on a page this signer holds) goes through here. A6: every decision service has ITS OWN
 * credential, separate from `admin.api_key` and from the Phase 5 hub relay token, and a scope list.
 *
 * READ-ONLY except `POST /relay/governance`, which is the existing typed key-page path (never blind
 * signing), restricted to pages in this signer's keyring and gated by the `x-governance-key` as well.
 * The upstream fetch, parameter patterns and the Accumulate record normalisation are the Phase 5 relay's.
 */
import type { PauseOp, PauseOutcome } from './binding/pause-store.js';
import type { PauseState } from './core/pause.js';
import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { normalizeTxRecord, relaySignatureView } from './accumulate/raw-client.js';
import { extractAcceptance } from './decode/facts.js';
import { ACC_URL, DOT_SEGMENT, HEX64, UUID, accError, makeUpstream, readCapped, send } from './relay.js';
import type { KeyPageOp, KeyPageResult } from './ops/keypage.js';
import type { PageState } from './ops/rotate.js';
import { checkKeyPageChange, KeyPageGuardError, KeyPageRefusal, operationsFromKeyPageOps } from './ops/keypage-guard.js';
import type { PolicyRequest } from './types.js';
import { Logger } from './logger.js';
import type { CountedReader } from './binding/read-cache.js';
import { relayAccountRoute } from './binding/relay-routes.js';
import { ExecutionInputError, findExecution, rpcOver } from './binding/evm-execution.js';

export const RELAY_CLIENT_PREFIX = '/relay';
export type RelayScope = 'proof' | 'tx' | 'pending' | 'governance' | 'chain' | 'pause';

export interface RelayClientsDeps {
  clients: Array<{ name: string; key: string; scopes: RelayScope[] }>;
  /** Credentials a client key must never equal. Checked again here, not only in config. */
  reservedKeys: Array<string | undefined>;
  query: (scope: string, query?: unknown) => Promise<any>;
  gateway?: { url: string; apiKey: string };
  evm: Array<{ chainId: number; rpcUrl: string }>;
  getPolicyRequest: (txHash: string) => Promise<PolicyRequest | undefined>;
  /** `admin.governance_admin_key`. Absent => the governance route is 403. */
  governanceKey?: string;
  /** Pages this signer holds a key for (the keyring). Governance is refused for any other page. */
  pages: () => string[];
  applyKeyPageOp?: (op: KeyPageOp, page: string) => Promise<KeyPageResult>;
  /**
   * G-65: read a key page off the chain at decision time. `POST /relay/governance` validates the WHOLE
   * operation list against what this returns before anything is signed, and refuses when it is absent or
   * the page cannot be read (`page_unreadable`) -- it never assumes a page state.
   */
  readPage?: (page: string) => Promise<PageState>;
  /** Phase 7: record a governance tx this signer submitted that still awaits another signature (officer intake). */
  recordAwaiting?: (r: { txHash: string; page: string; op: KeyPageOp }) => Promise<void>;
  /** Phase 7: `POST /relay/governance/proposal` (officer intake). Absent => 404. */
  propose?: (page: string, operations: KeyPageOp[], proposer: string) => Promise<{ status: number; body: unknown }>;
  /** DAX-F188: `POST /relay/governance/proposal/withdraw` (officer intake). Absent => 403, as `propose`. */
  withdrawProposal?: (proposalId: string, by: string, note: string) => Promise<{ status: number; body: unknown }>;
  /**
   * The Accumulate facts the Console's reader needs (scope `chain`): one evaluation view of the SAME read cache the signer's own
   * decision binding uses, so the Console's reads and the signer's share the cache, the TTL, the concurrency bound and the
   * counters. Absent => the chain routes are 503.
   */
  chainReader?: () => CountedReader;
  /**
   * AGT-3: the PERSISTED pause this signer reads before every signature (src/binding/pause-store.ts), for the Console's person-held
   * agent pause (scope `pause`): `GET /relay/pause` reads it, `POST /relay/pause` and `/relay/resume` set and lift a SUBJECT pause
   * with a named seat and a reason (the core's own rules, DE-24 to DE-27). A seat-wide pause stays with the admin route. Absent => 503.
   */
  pause?: { snapshot(): PauseState; set(op: PauseOp): Promise<PauseOutcome>; resume(op: PauseOp): Promise<PauseOutcome> };
  timeoutMs?: number;
  logger: Logger;
  fetchImpl?: typeof fetch;
}

export type RelayClientsHandler = (req: http.IncomingMessage, res: http.ServerResponse, url: URL) => Promise<void>;

const digest = (s: string) => createHash('sha256').update(s).digest();
/** Constant-time: both sides hashed to equal length first, as `bearerMatches` does. */
function keyMatches(given: unknown, expected: string): boolean {
  const ok = timingSafeEqual(digest(typeof given === 'string' ? given : ''), digest(expected));
  return ok && typeof given === 'string' && expected.length > 0;
}

/** A key-page guard refusal as an HTTP answer: 503 when the page could not be read (retryable), else 400. */
function sendRefusal(res: http.ServerResponse, refusal: KeyPageRefusal, txids: string[] = []) {
  return send(res, refusal.reason === 'page_unreadable' ? 503 : 400, {
    txid: txids[txids.length - 1] ?? null, status: 'refused', error: refusal.reason, refusal, txids,
  });
}

/** the chain routes: the account is ONE percent-encoded path segment (no raw slash) */
const CHAIN_ROUTE = new RegExp('^/relay/(data|authorities|history|keybook|chainlen)/([^/]+)$');
const GOV_TYPES = new Set(['add-key', 'remove-key', 'set-threshold', 'set-reject-threshold', 'add-delegate', 'remove-delegate']);
const MAX_GOV_OPS = 10;
const sameUrl = (a: string, b: string) => a.toLowerCase().replace(/\/+$/, '') === b.toLowerCase().replace(/\/+$/, '');
const accUrlOk = (u: unknown): u is string => typeof u === 'string' && ACC_URL.test(u) && !DOT_SEGMENT.test(u.slice(6));

/** Validate one governance operation into a typed KeyPageOp, or return the reason it is refused. */
export function toKeyPageOp(o: unknown): KeyPageOp | string {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return 'operation must be an object';
  const r = o as Record<string, unknown>;
  const type = r.type;
  if (typeof type !== 'string' || !GOV_TYPES.has(type)) return `operation type must be one of ${[...GOV_TYPES].join(', ')}`;
  switch (type) {
    case 'add-key':
    case 'remove-key':
      if (typeof r.keyHash !== 'string' || !HEX64.test(r.keyHash)) return `${type}: keyHash must be 64 hex characters`;
      return { op: type, keyHash: r.keyHash.replace(/^0x/, '').toLowerCase() };
    case 'set-threshold':
      if (typeof r.threshold !== 'number' || !Number.isInteger(r.threshold) || r.threshold < 1 || r.threshold > 1000) return 'set-threshold: threshold must be a positive integer';
      return { op: type, threshold: r.threshold };
    case 'set-reject-threshold':
      // DAX-F178: the page's reject threshold; the guard refuses one above the entries the page will hold
      if (typeof r.threshold !== 'number' || !Number.isInteger(r.threshold) || r.threshold < 1 || r.threshold > 1000) return 'set-reject-threshold: threshold must be a positive integer';
      return { op: type, threshold: r.threshold };
    default:
      if (!accUrlOk(r.delegate)) return `${type}: delegate must be an acc:// key book URL`;
      return { op: type as 'add-delegate' | 'remove-delegate', delegate: r.delegate };
  }
}

export function createRelayClientsHandler(d: RelayClientsDeps): RelayClientsHandler {
  const reserved = d.reservedKeys.filter((k): k is string => !!k);
  for (const c of d.clients) {
    if (!c.key || c.key.length < 16) throw new Error(`relay client ${c.name}: key must be at least 16 characters`);
    if (reserved.includes(c.key)) throw new Error(`relay client ${c.name}: key must not equal an admin or relay credential`);
  }
  const byName = new Map(d.clients.map((c) => [c.name, c]));
  const chains = new Map(d.evm.map((c) => [c.chainId, c.rpcUrl]));
  const upstream = makeUpstream({ fetchImpl: d.fetchImpl, timeoutMs: d.timeoutMs, logger: d.logger, gatewayApiKey: d.gateway?.apiKey });
  const DUMMY = 'x'.repeat(32);

  async function gatewayGet(res: http.ServerResponse, path: string) {
    if (!d.gateway) return send(res, 503, { error: 'relay gateway not configured' });
    const out = await upstream(d.gateway.url.replace(/\/+$/, '') + path, {
      method: 'GET', headers: { accept: 'application/json', 'x-api-key': d.gateway.apiKey },
    });
    if ('error' in out) return send(res, 502, { error: out.error });
    return send(res, out.status, out.body);
  }

  return async (req, res, url) => {
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // --- auth: named client + its own key (constant-time; an unknown name still pays for a compare) ---
    const nameHdr = req.headers['x-relay-client'];
    const client = typeof nameHdr === 'string' ? byName.get(nameHdr) : undefined;
    const keyOk = keyMatches(req.headers['x-api-key'], client?.key ?? DUMMY);
    if (!client || !keyOk) return send(res, 401, { error: 'unauthorized' });
    const need = (scope: RelayScope) => client.scopes.includes(scope);

    let m: RegExpExecArray | null;

    // GET /relay/data|authorities|history|keybook|chainlen/:account  (scope chain; read-only, v3 only, strictly validated: src/binding/relay-routes.ts)
    if ((m = CHAIN_ROUTE.exec(path))) {
      if (!need('chain')) return send(res, 403, { error: 'forbidden: scope chain required' });
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      if (url.search !== '') return send(res, 400, { error: 'no query parameters are accepted' });
      if (!d.chainReader) return send(res, 503, { error: 'chain reader not configured' });
      const out = await relayAccountRoute(d.chainReader(), m[1] as 'data' | 'authorities' | 'history' | 'keybook' | 'chainlen', m[2]);
      for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
      return send(res, out.status, out.body);
    }

    // AGT-3: the agent pause (scope pause). The signer is the enforcement point: what is set here is journalled and read again before
    // EVERY signature, a reject vote included (orchestrator pausedFor -> PauseStore.check -> core checkSigningFromText).
    if (path === '/relay/pause' || path === '/relay/resume') {
      if (!need('pause')) return send(res, 403, { error: 'forbidden: scope pause required' });
      if (!d.pause) return send(res, 503, { error: 'pause store not configured' });
      if (method === 'GET' && path === '/relay/pause') {
        const st = d.pause.snapshot();
        return send(res, 200, { pauses: st.pauses.filter((p) => p.scope === 'subject') });
      }
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      let b: Record<string, unknown>;
      try { b = JSON.parse((await readJsonBody(req)) || '{}'); } catch { return send(res, 400, { error: 'body must be JSON' }); }
      if (b === null || typeof b !== 'object' || Array.isArray(b)) return send(res, 400, { error: 'body must be a JSON object' });
      const keys = Object.keys(b).sort().join(',');
      if (keys !== 'by,id,reason,scope') return send(res, 400, { error: 'body must be exactly {scope, id, by, reason}' });
      if (b.scope !== 'subject') return send(res, 400, { error: 'scope must be subject: a seat-wide pause is the admin route' });
      const op = { scope: 'subject' as const, id: String(b.id), by: String(b.by), reason: String(b.reason) };
      const out = path === '/relay/pause' ? await d.pause.set(op) : await d.pause.resume(op);
      if (!out.ok) return send(res, out.reason === 'not_paused' ? 409 : out.reason.startsWith('journal_') ? 500 : 400, { error: out.reason, ...(out.detail !== undefined ? { detail: out.detail } : {}) });
      d.logger.warn({ audit: path === '/relay/pause' ? 'subject_paused' : 'subject_resumed', client: client.name, id: op.id, by: op.by }, 'subject pause changed');
      return send(res, 200, { pauses: out.state.pauses.filter((p) => p.scope === 'subject'), ...(out.status ? { status: out.status } : {}) });
    }

    // GET /relay/proof/tx/:hash
    if ((m = /^\/relay\/proof\/tx\/([^/]+)$/.exec(path))) {
      if (!need('proof')) return send(res, 403, { error: 'forbidden: scope proof required' });
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      if (!HEX64.test(m[1])) return send(res, 400, { error: 'hash must be 64 hex characters' });
      return gatewayGet(res, `/v1/proof/tx/${m[1].replace(/^0x/, '').toLowerCase()}`);
    }
    // GET /relay/proof/:id/bundle
    if ((m = /^\/relay\/proof\/([^/]+)\/bundle$/.exec(path))) {
      if (!need('proof')) return send(res, 403, { error: 'forbidden: scope proof required' });
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      if (!UUID.test(m[1])) return send(res, 400, { error: 'id must be a UUID' });
      return gatewayGet(res, `/v1/proof/${m[1].toLowerCase()}/bundle`);
    }
    // GET /relay/tx/:hash/signatures?principal=<acc url>
    if ((m = /^\/relay\/tx\/([^/]+)\/signatures$/.exec(path))) {
      if (!need('tx')) return send(res, 403, { error: 'forbidden: scope tx required' });
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      if (!HEX64.test(m[1])) return send(res, 400, { error: 'hash must be 64 hex characters' });
      const principal = url.searchParams.get('principal') ?? '';
      if (!accUrlOk(principal)) return send(res, 400, { error: 'principal must be an acc:// account URL' });
      const hash = m[1].replace(/^0x/, '').toLowerCase();
      const id = `acc://${hash}@${principal.slice(6).replace(/\/+$/, '')}`;
      let rec: any;
      try { rec = await d.query(id); }
      catch (e) { return accError(res, e); }
      const n = normalizeTxRecord(rec);
      const body = n.body as { type?: unknown } | null;
      // The acceptance fact is decoded from the chain record itself, so a decision service can verify an acceptance
      // this signer never had to sign (e.g. bank compliance checking a customer's firm acceptance, decision 0028).
      const acceptance = extractAcceptance(n.body as Parameters<typeof extractAcceptance>[0], n.principal || principal);
      return send(res, 200, {
        txid: n.txid || id,
        status: n.status,
        header: n.header,
        bodyType: typeof body?.type === 'string' ? body.type : '',
        ...(acceptance ? { acceptance } : {}),
        // DAX-F177 (b): each signature also carries its signer version and, for the initiating one, initiator: true (raw-client.ts relaySignatureView)
        signatures: n.signatures.map(relaySignatureView),
      });
    }
    // GET /relay/tx/:hash/receipt
    if ((m = /^\/relay\/tx\/([^/]+)\/receipt$/.exec(path))) {
      if (!need('tx')) return send(res, 403, { error: 'forbidden: scope tx required' });
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      if (!HEX64.test(m[1])) return send(res, 400, { error: 'hash must be 64 hex characters' });
      return gatewayGet(res, `/v1/proof/tx/${m[1].replace(/^0x/, '').toLowerCase()}/receipt`);
    }
    // GET /relay/pending/:hash
    if ((m = /^\/relay\/pending\/([^/]+)$/.exec(path))) {
      if (!need('pending')) return send(res, 403, { error: 'forbidden: scope pending required' });
      if (method !== 'GET') return send(res, 405, { error: 'method not allowed' });
      if (!HEX64.test(m[1])) return send(res, 400, { error: 'hash must be 64 hex characters' });
      const pr = await d.getPolicyRequest(m[1].replace(/^0x/, '').toLowerCase());
      if (!pr) return send(res, 404, { error: 'not found' });
      return send(res, 200, pr);
    }
    // POST /relay/evm/:chainId/call  { to, data }
    if ((m = /^\/relay\/evm\/([^/]+)\/call$/.exec(path))) {
      if (!need('tx')) return send(res, 403, { error: 'forbidden: scope tx required' });
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      if (!/^[1-9][0-9]{0,15}$/.test(m[1])) return send(res, 400, { error: 'chainId must be a positive integer' });
      const rpcUrl = chains.get(Number(m[1]));
      if (!rpcUrl) return send(res, 404, { error: 'unknown chain' });
      const raw = await readCapped(req, 64 * 1024);
      if (raw === null) return send(res, 413, { error: 'body too large' });
      let b: { to?: unknown; data?: unknown };
      try { b = JSON.parse(raw); } catch { return send(res, 400, { error: 'body must be JSON' }); }
      if (typeof b?.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(b.to)) return send(res, 400, { error: 'to must be a 0x 20-byte address' });
      if (typeof b.data !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(b.data)) return send(res, 400, { error: 'data must be 0x hex bytes' });
      const out = await upstream(rpcUrl, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: b.to, data: b.data }, 'latest'] }),
      });
      if ('error' in out) return send(res, 502, { error: out.error });
      const rpc = out.body as { result?: unknown; error?: { code?: unknown; message?: unknown } } | null;
      if (rpc?.error) return send(res, 502, { error: 'eth_call failed', code: rpc.error.code ?? null });
      if (typeof rpc?.result !== 'string') return send(res, 502, { error: 'eth_call returned no result' });
      return send(res, 200, { result: rpc.result });
    }
    // POST /relay/evm/:chainId/execution  { account, operationId, fromBlock | fromTime } - read only (AGT scene-verify-9, EVIDENCE-AGT section 1): the ONE
    // transaction in which the account emitted LeafConsumed for this operation id, and whose receipt succeeded (src/binding/evm-execution.ts)
    if ((m = /^\/relay\/evm\/([^/]+)\/execution$/.exec(path))) {
      if (!need('tx')) return send(res, 403, { error: 'forbidden: scope tx required' });
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      if (!/^[1-9][0-9]{0,15}$/.test(m[1])) return send(res, 400, { error: 'chainId must be a positive integer' });
      const rpcUrl = chains.get(Number(m[1]));
      if (!rpcUrl) return send(res, 404, { error: 'unknown chain' });
      const raw = await readCapped(req, 16 * 1024);
      if (raw === null) return send(res, 413, { error: 'body too large' });
      let b: { account?: unknown; operationId?: unknown; fromBlock?: unknown; fromTime?: unknown };
      try { b = JSON.parse(raw); } catch { return send(res, 400, { error: 'body must be JSON' }); }
      if (b === null || typeof b !== 'object' || Array.isArray(b)) return send(res, 400, { error: 'body must be a JSON object' });
      const rpc = rpcOver((body) => upstream(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body }));
      try {
        const answer = await findExecution(rpc, { account: b.account as string, operationId: b.operationId as string, ...(b.fromBlock !== undefined ? { fromBlock: b.fromBlock as number } : {}), ...(b.fromTime !== undefined ? { fromTime: b.fromTime as number } : {}) });
        return send(res, 200, answer);
      } catch (e) {
        if (e instanceof ExecutionInputError) return send(res, 400, { error: e.message });
        return send(res, 502, { error: `execution lookup failed: ${(e as Error).message}` });
      }
    }
    // POST /relay/governance/proposal/withdraw  { proposalId, by, note } — DAX-F188; a proposal no signature was sent for becomes
    // `withdrawn` (never prepared again); one with a signature sent is refused by name. Nothing is signed or submitted.
    if (path === '/relay/governance/proposal/withdraw') {
      if (!need('governance')) return send(res, 403, { error: 'forbidden: scope governance required' });
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      if (!d.governanceKey || !d.withdrawProposal) return send(res, 403, { error: 'proposals disabled (needs admin.governance_admin_key and officer_intake)' });
      if (!keyMatches(req.headers['x-governance-key'], d.governanceKey)) return send(res, 401, { error: 'unauthorized' });
      const raw = await readCapped(req, 16 * 1024);
      if (raw === null) return send(res, 413, { error: 'body too large' });
      let b: { proposalId?: unknown; by?: unknown; note?: unknown };
      try { b = JSON.parse(raw); } catch { return send(res, 400, { error: 'body must be JSON' }); }
      if (b === null || typeof b !== 'object' || Array.isArray(b)) return send(res, 400, { error: 'body must be a JSON object' });
      if (typeof b.proposalId !== 'string' || !/^(?:proposal:)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(b.proposalId)) {
        return send(res, 400, { error: 'proposalId must be proposal:<uuid>' });
      }
      if (typeof b.by !== 'string' || !/^[^\u0000-\u001f\u007f]{1,128}$/.test(b.by) || b.by.trim() === '') return send(res, 400, { error: 'by must be 1..128 printable characters' });
      if (typeof b.note !== 'string' || !/^[^\u0000-\u001f\u007f]{12,2000}$/.test(b.note.trim())) return send(res, 400, { error: 'note must say why, in 12..2000 printable characters' });
      d.logger.warn({ audit: 'relay_governance_proposal_withdraw', client: client.name, proposalId: b.proposalId, by: b.by }, 'GOVERNANCE PROPOSAL WITHDRAWAL REQUESTED (relay client)');
      const out = await d.withdrawProposal(b.proposalId, b.by.trim(), b.note.trim());
      return send(res, out.status, out.body);
    }
    // POST /relay/governance/proposal  { page, operations: [...], proposer } — Phase 7; nothing is signed or submitted.
    if (path === '/relay/governance/proposal') {
      if (!need('governance')) return send(res, 403, { error: 'forbidden: scope governance required' });
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      if (!d.governanceKey || !d.propose) return send(res, 403, { error: 'proposals disabled (needs admin.governance_admin_key and officer_intake)' });
      if (!keyMatches(req.headers['x-governance-key'], d.governanceKey)) return send(res, 401, { error: 'unauthorized' });
      const raw = await readCapped(req, 64 * 1024);
      if (raw === null) return send(res, 413, { error: 'body too large' });
      let b: { page?: unknown; operations?: unknown; proposer?: unknown };
      try { b = JSON.parse(raw); } catch { return send(res, 400, { error: 'body must be JSON' }); }
      if (!accUrlOk(b?.page)) return send(res, 400, { error: 'page must be an acc:// key page URL' });
      if (typeof b.proposer !== 'string' || !/^[^\u0000-\u001f\u007f]{1,128}$/.test(b.proposer)) return send(res, 400, { error: 'proposer must be 1..128 printable characters' });
      if (!Array.isArray(b.operations) || b.operations.length === 0 || b.operations.length > MAX_GOV_OPS) {
        return send(res, 400, { error: `operations must be an array of 1..${MAX_GOV_OPS}` });
      }
      const ops: KeyPageOp[] = [];
      for (const o of b.operations) {
        const v = toKeyPageOp(o);
        if (typeof v === 'string') return send(res, 400, { error: v });
        ops.push(v);
      }
      d.logger.warn({ audit: 'relay_governance_proposal', client: client.name, page: b.page, ops, proposer: b.proposer }, 'GOVERNANCE PROPOSAL REQUESTED (relay client)');
      const out = await d.propose((b.page as string).replace(/\/+$/, ''), ops, b.proposer);
      return send(res, out.status, out.body);
    }
    // POST /relay/governance  { page, operations: [...] }
    if (path === '/relay/governance') {
      if (!need('governance')) return send(res, 403, { error: 'forbidden: scope governance required' });
      if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
      if (!d.governanceKey || !d.applyKeyPageOp) return send(res, 403, { error: 'governance disabled (no admin.governance_admin_key configured)' });
      if (!keyMatches(req.headers['x-governance-key'], d.governanceKey)) return send(res, 401, { error: 'unauthorized' });
      const raw = await readCapped(req, 64 * 1024);
      if (raw === null) return send(res, 413, { error: 'body too large' });
      let b: { page?: unknown; operations?: unknown };
      try { b = JSON.parse(raw); } catch { return send(res, 400, { error: 'body must be JSON' }); }
      if (!accUrlOk(b?.page)) return send(res, 400, { error: 'page must be an acc:// key page URL' });
      const page = d.pages().find((p) => sameUrl(p, b.page as string));
      // Only a page this signer holds a key for (P3: never another party's page, never an arbitrary URL).
      if (!page) return send(res, 403, { error: 'forbidden: page is not held by this signer' });
      if (!Array.isArray(b.operations) || b.operations.length === 0 || b.operations.length > MAX_GOV_OPS) {
        return send(res, 400, { error: `operations must be an array of 1..${MAX_GOV_OPS}` });
      }
      const ops: KeyPageOp[] = [];
      for (const o of b.operations) {
        const v = toKeyPageOp(o);
        if (typeof v === 'string') return send(res, 400, { error: v });
        ops.push(v);
      }
      d.logger.warn({ audit: 'relay_governance_operation', client: client.name, page, ops }, 'GOVERNANCE OPERATION REQUESTED (relay client)');
      // G-65: the whole list, against the page as it reads now, before the first operation is signed --
      // each operation is its own transaction, so refusing the third after submitting the first two would
      // leave the page half-changed. Each operation is checked again, against a fresh read, inside
      // applyKeyPageOp.
      const check = await checkKeyPageChange(d.readPage, page, operationsFromKeyPageOps(ops));
      if (!check.ok) {
        d.logger.warn({ audit: 'relay_governance_refused', client: client.name, page, refusal: check.refusal }, 'GOVERNANCE OPERATION REFUSED: the change would brick the page or the page is unreadable');
        return sendRefusal(res, check.refusal);
      }
      const txids: string[] = [];
      let awaiting = false;
      for (const op of ops) {
        let r: KeyPageResult;
        try {
          r = await d.applyKeyPageOp(op, page);
        } catch (e) {
          if (!(e instanceof KeyPageGuardError)) throw e;
          d.logger.warn({ audit: 'relay_governance_refused', client: client.name, page, refusal: e.refusal }, 'GOVERNANCE OPERATION REFUSED');
          return sendRefusal(res, e.refusal, txids);
        }
        txids.push(...r.submitted);
        // Phase 7: a submitted transaction still waiting for another signature (a delegate's consent, a
        // threshold above one) is recorded so a human on that page can sign it through officer intake.
        if (r.submitted.length && (r.awaitingConsent || !r.ok) && d.recordAwaiting) {
          for (const t of r.submitted) {
            const hash = /([0-9a-fA-F]{64})/.exec(t)?.[1]?.toLowerCase();
            if (hash) await d.recordAwaiting({ txHash: hash, page, op }).catch((e) => d.logger.error({ err: (e as Error).message, tx: hash }, 'could not record awaiting governance transaction'));
          }
        }
        if (!r.ok && r.refusal) {
          d.logger.warn({ audit: 'relay_governance_refused', client: client.name, page, refusal: r.refusal }, 'GOVERNANCE OPERATION REFUSED');
          return sendRefusal(res, r.refusal, txids);
        }
        if (!r.ok) {
          d.logger.warn({ audit: 'relay_governance_result', client: client.name, page, ok: false }, 'GOVERNANCE OPERATION FAILED');
          return send(res, 400, { txid: txids[txids.length - 1] ?? null, status: 'failed', error: r.error ?? 'governance operation failed', txids });
        }
        if (r.awaitingConsent) awaiting = true;
      }
      d.logger.warn({ audit: 'relay_governance_result', client: client.name, page, ok: true, txids }, 'GOVERNANCE OPERATION COMPLETE');
      return send(res, 200, { txid: txids[txids.length - 1] ?? null, status: awaiting ? 'awaiting_consent' : 'confirmed', txids });
    }

    return send(res, 404, { error: 'not found' });
  };
}

/** a request body, at most 4 KiB (a pause body is a few short strings) */
function readJsonBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 4096) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => resolve(b));
    req.on('error', reject);
  });
}
