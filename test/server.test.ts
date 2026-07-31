import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { AddressInfo } from 'node:net';
import pino from 'pino';
import { createServer, PauseController } from '../src/server.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const SIGNER = 'acc://demo-org.acme/book/1';
const GOV_KEY = 'gov-secret-123';
const ADMIN_KEY = 'admin-secret-123';
const HOOK_KEY = 'webhook-secret-123';
/** Admin routes are authenticated — see hardening.test.ts for the unauthenticated-caller cases. */
const ADMIN = { 'x-api-key': ADMIN_KEY };

/** The webhook trigger requires an HMAC over the raw body — it is not an open door. */
function hookSig(body: unknown): Record<string, string> {
  const raw = JSON.stringify(body);
  const t = String(Date.now());
  const mac = createHmac('sha256', HOOK_KEY).update(`${t}.${raw}`).digest('hex');
  return { 'x-certen-signature': `t=${t},v1=${mac}` };
}

function build(opts: { webhook?: boolean } = {}) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] }, principal: 'acc://alice.acme/tokens' });
  const signer = new LocalSigner(new Uint8Array(32).fill(9));
  const keyring = singleKeyring(signer);
  const store = new MemoryStore();
  const pause: PauseController = { paused: false };
  const orchestrator = new Orchestrator({ accumulate: acc, keyring, policy: new MockPolicyClient({ decision: 'approve' }), store, resolver: new Resolver(acc), logger: silent, options: { isPaused: () => pause.paused } });
  const keyPageOps: unknown[] = [];   // records what the typed governance route was asked to do
  const server = createServer({
    orchestrator, store, keyring, accumulate: acc, pause, logger: silent,
    adminApiKey: ADMIN_KEY, governanceAdminKey: GOV_KEY,
    webhookHmacSecret: opts.webhook === false ? undefined : HOOK_KEY,
    keyPage: async (op) => {
      keyPageOps.push(op);
      return { ok: true, op: op.op, submitted: ['deadbeef'], before: { version: 1, keyHashes: [] }, after: { version: 2, keyHashes: [] } };
    },
  });
  return { server, acc, store, pause, signer, keyPageOps };
}

function reqH(port: number, method: string, path: string, headers: Record<string, string>, body?: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const h = { ...headers, ...(data ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(data)) } : {}) };
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: h }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      // safeJson: /metrics answers text/plain, so a bare JSON.parse here would throw inside the response
      // handler and leave the promise forever unsettled (the failure looks like a server timeout).
      res.on('end', () => { const t = Buffer.concat(chunks).toString('utf8'); resolve({ status: res.statusCode!, json: t ? safeJson(t) : undefined }); });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

function req(port: number, method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {} }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const t = Buffer.concat(chunks).toString('utf8'); resolve({ status: res.statusCode!, json: t ? safeJson(t) : undefined }); });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}
function safeJson(s: string) { try { return JSON.parse(s); } catch { return s; } }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('http server', () => {
  let ctx: ReturnType<typeof build>;
  let port: number;
  beforeEach(async () => {
    ctx = build();
    await new Promise<void>((res) => ctx.server.listen(0, '127.0.0.1', res));
    port = (ctx.server.address() as AddressInfo).port;
  });
  afterEach(() => ctx.server.close());

  it('GET /healthz → 200 ok', async () => {
    const r = await req(port, 'GET', '/healthz');
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
  });

  /**
   * Per-scope discovery health.
   *
   * On a fleet the aggregate boolean is not actionable: twelve agent pages report as one value, so an
   * operator paged at 3am learns that discovery stopped but not which agent stopped. `/healthz` names them,
   * and `reasons` carries the stalled pages so an alert built on the reason string is specific too.
   */
  describe('/healthz per-scope detail', () => {
    /** A health source standing in for N pollers, with chosen pages healthy. */
    function withScopes(pages: Array<{ page: string; healthy: boolean; lastSuccess: number | null }>) {
      const acc = new MockAccumulateClient();
      const keyring = singleKeyring(new LocalSigner(new Uint8Array(32).fill(9)));
      const store = new MemoryStore();
      const pause: PauseController = { paused: false };
      return createServer({
        orchestrator: new Orchestrator({
          accumulate: acc, keyring, policy: new MockPolicyClient({ decision: 'approve' }),
          store, resolver: new Resolver(acc), logger: silent,
        }),
        store, keyring, accumulate: acc, pause, logger: silent, adminApiKey: ADMIN_KEY,
        poller: {
          healthy: () => pages.every((p) => p.healthy),
          lastSuccess: () => Math.min(...pages.map((p) => p.lastSuccess ?? 0)),
          scopes: () => pages,
        },
      });
    }

    async function get(server: http.Server, path: string) {
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
      const p = (server.address() as AddressInfo).port;
      try { return await req(p, 'GET', path); } finally { server.close(); }
    }

    it('lists every page when there is more than one', async () => {
      const r = await get(withScopes([
        { page: 'acc://a.acme/book/1', healthy: true, lastSuccess: 1000 },
        { page: 'acc://b.acme/book/1', healthy: true, lastSuccess: 2000 },
      ]), '/healthz');
      expect(r.status).toBe(200);
      expect(r.json.scopes.map((s: any) => s.page)).toEqual(['acc://a.acme/book/1', 'acc://b.acme/book/1']);
    });

    it('names the stalled page in reasons, not just that something stalled', async () => {
      const r = await get(withScopes([
        { page: 'acc://healthy.acme/book/1', healthy: true, lastSuccess: 1000 },
        { page: 'acc://stuck.acme/book/1', healthy: false, lastSuccess: null },
      ]), '/healthz');
      expect(r.status).toBe(503);
      expect(r.json.ok).toBe(false);
      expect(r.json.reasons).toContain('poller_stalled:acc://stuck.acme/book/1');
      // The healthy one must not be implicated — that would send an operator after the wrong agent.
      expect(r.json.reasons.join(' ')).not.toContain('healthy.acme');
    });

    /** One page is the single-scope case; repeating it as a `scopes` array is noise the console would
     *  then render as a pointless one-row table and a one-option filter. */
    it('omits scopes for a single-page signer', async () => {
      const r = await get(withScopes([{ page: 'acc://solo.acme/book/1', healthy: true, lastSuccess: 1000 }]), '/healthz');
      expect(r.json.scopes).toBeUndefined();
      expect(r.json.poller.healthy).toBe(true);
    });
  });

  /**
   * GET /v1/requests — the operator audit view, backing the console's activity table.
   *
   * Returns each request WITH its receipt: the request says what happened, the receipt says why. An
   * operator asking "why did we sign that?" should not need a second round trip per row to find out.
   */
  describe('GET /v1/requests (audit view)', () => {
    /** Put one decided transaction in the store, the way the orchestrator would. */
    async function seed(n: number) {
      for (let i = 0; i < n; i++) {
        const tx = i.toString(16).padStart(2, '0').repeat(32);
        await ctx.store.create({
          txHash: tx, signerUrl: SIGNER, status: 'signed', decision: 'approve',
          actionSummary: `transfer #${i}`, attempts: 0, createdAt: Date.now(), updatedAt: Date.now() + i,
        });
        await ctx.store.saveReceipt({ txHash: tx, decision: 'approve', vote: 'approve', reason: `rule ${i}` });
      }
    }

    it('is admin-authenticated — decision history is not public', async () => {
      expect((await req(port, 'GET', '/v1/requests')).status).toBe(401);
    });

    it('returns requests paired with their receipts', async () => {
      await seed(1);
      const r = await reqH(port, 'GET', '/v1/requests', ADMIN);
      expect(r.status).toBe(200);
      expect(r.json.requests).toHaveLength(1);
      expect(r.json.requests[0].request.status).toBe('signed');
      expect(r.json.requests[0].receipt.reason).toBe('rule 0');   // the WHY, in the same row
    });

    it('returns the most recently updated first', async () => {
      await seed(3);
      const r = await reqH(port, 'GET', '/v1/requests', ADMIN);
      expect(r.json.requests.map((x: any) => x.request.actionSummary))
        .toEqual(['transfer #2', 'transfer #1', 'transfer #0']);
    });

    it('honors ?limit', async () => {
      await seed(5);
      const r = await reqH(port, 'GET', '/v1/requests?limit=2', ADMIN);
      expect(r.json.requests).toHaveLength(2);
    });

    // Clamped rather than rejected: this backs a UI, where an out-of-range value should still render
    // something sensible instead of an error page.
    it('clamps a nonsensical limit instead of failing', async () => {
      await seed(3);
      for (const q of ['?limit=0', '?limit=-5', '?limit=abc', '?limit=99999']) {
        const r = await reqH(port, 'GET', `/v1/requests${q}`, ADMIN);
        expect(r.status).toBe(200);
        expect(r.json.requests.length).toBeGreaterThan(0);
      }
    });

    it('is empty, not an error, before anything has happened', async () => {
      const r = await reqH(port, 'GET', '/v1/requests', ADMIN);
      expect(r.status).toBe(200);
      expect(r.json.requests).toEqual([]);
    });

    /**
     * ?status= — the work queue. `awaiting_policy` is "the engine has seen it and not yet decided", i.e.
     * exactly the transactions a human still owes an answer on.
     */
    describe('?status=', () => {
      /** A store holding a mix: two waiting, three settled. */
      async function seedMixed() {
        const rows: Array<[string, 'awaiting_policy' | 'signed' | 'rejected']> = [
          ['a1', 'awaiting_policy'], ['a2', 'awaiting_policy'],
          ['b1', 'signed'], ['b2', 'signed'], ['c1', 'rejected'],
        ];
        for (const [tag, status] of rows) {
          await ctx.store.create({
            txHash: tag.charCodeAt(1).toString(16).padStart(2, '0').repeat(31) + (tag === 'a1' ? '11' : tag === 'a2' ? '22' : tag === 'b1' ? '33' : tag === 'b2' ? '44' : '55'),
            signerUrl: SIGNER, status, actionSummary: tag, attempts: 0, createdAt: Date.now(), updatedAt: Date.now(),
          });
        }
      }

      it('returns only the requested status', async () => {
        await seedMixed();
        const r = await reqH(port, 'GET', '/v1/requests?status=awaiting_policy', ADMIN);
        expect(r.status).toBe(200);
        expect(r.json.requests).toHaveLength(2);
        expect(r.json.requests.every((x: any) => x.request.status === 'awaiting_policy')).toBe(true);
      });

      it('accepts several statuses, comma-separated', async () => {
        await seedMixed();
        const r = await reqH(port, 'GET', '/v1/requests?status=signed,rejected', ADMIN);
        expect(r.json.requests).toHaveLength(3);
      });

      /**
       * The filter runs BEFORE the limit. Otherwise a queue UI on a busy signer shows an empty work list:
       * the recent window fills with settled transactions and the waiting ones fall off the end.
       */
      it('filters before applying the limit, not after', async () => {
        await seedMixed();
        const r = await reqH(port, 'GET', '/v1/requests?status=awaiting_policy&limit=2', ADMIN);
        expect(r.json.requests).toHaveLength(2);
        expect(r.json.requests.every((x: any) => x.request.status === 'awaiting_policy')).toBe(true);
      });

      /**
       * A typo'd status is REJECTED, not ignored. A silently-dropped filter returns a plausible-looking
       * list of the wrong rows — an operator would read "nothing is waiting" off a full queue.
       */
      it('rejects an unknown status instead of ignoring the filter', async () => {
        await seedMixed();
        const r = await reqH(port, 'GET', '/v1/requests?status=awaiting_polcy', ADMIN);
        expect(r.status).toBe(400);
        expect(r.json.error).toMatch(/unknown status/);
        expect(r.json.valid).toContain('awaiting_policy');
      });

      it('an empty status param is treated as no filter', async () => {
        await seedMixed();
        const r = await reqH(port, 'GET', '/v1/requests?status=', ADMIN);
        expect(r.status).toBe(200);
        expect(r.json.requests).toHaveLength(5);
      });
    });
  });

  it('GET /metrics → 200 text (authenticated: it exposes the org\'s decision counts)', async () => {
    const body = { tx_hash: TX, signer_url: SIGNER };
    await reqH(port, 'POST', '/v1/pending', hookSig(body), body);
    const r = await reqH(port, 'GET', '/metrics', ADMIN);
    expect(r.status).toBe(200);
    expect(String(r.json)).toContain('wallet_pending_seen_total');
  });

  it('POST /v1/pending (HMAC-signed) → 202, then request becomes signed', async () => {
    const r = await reqH(port, 'POST', '/v1/pending', hookSig({ tx_hash: TX, signer_url: SIGNER }), { tx_hash: TX, signer_url: SIGNER });
    expect(r.status).toBe(202);
    // async handle; poll the request endpoint
    let signed = false;
    for (let i = 0; i < 20 && !signed; i++) {
      const g = await reqH(port, 'GET', `/v1/requests/${TX}`, ADMIN);
      if (g.json?.request?.status === 'signed') signed = true; else await sleep(25);
    }
    expect(signed).toBe(true);
    expect(ctx.acc.submissions.length).toBe(1);
  });

  it('POST /v1/pending missing fields → 400', async () => {
    const body = { tx_hash: TX };
    const r = await reqH(port, 'POST', '/v1/pending', hookSig(body), body);
    expect(r.status).toBe(400);
  });

  it('POST /v1/pending unsigned → 401 (the trigger is not an open door)', async () => {
    const r = await req(port, 'POST', '/v1/pending', { tx_hash: TX, signer_url: SIGNER });
    expect(r.status).toBe(401);
    expect(ctx.acc.submissions.length).toBe(0);
  });

  it('POST /v1/pending → 403 when the webhook is not enabled at all', async () => {
    const noHook = build({ webhook: false });
    await new Promise<void>((res) => noHook.server.listen(0, '127.0.0.1', res));
    const p = (noHook.server.address() as AddressInfo).port;
    const r = await req(p, 'POST', '/v1/pending', { tx_hash: TX, signer_url: SIGNER });
    expect(r.status).toBe(403);
    noHook.server.close();
  });

  it('pause → healthz shows paused, and signing is withheld', async () => {
    const p = await reqH(port, 'POST', '/v1/admin/pause', ADMIN);
    expect(p.json.paused).toBe(true);
    const h = await req(port, 'GET', '/healthz');
    expect(h.json.paused).toBe(true);
    const body = { tx_hash: TX, signer_url: SIGNER };
    await reqH(port, 'POST', '/v1/pending', hookSig(body), body);   // properly triggered, so the
    await sleep(200);                                               // 0 submissions below is the PAUSE,
    expect(ctx.acc.submissions.length).toBe(0);                     // not a rejected trigger
  });

  it('GET unknown request → 404', async () => {
    const r = await reqH(port, 'GET', `/v1/requests/${'cd'.repeat(32)}`, ADMIN);
    expect(r.status).toBe(404);
  });

  it('GET /v1/admin/pubkey → wallet pubkey + key hash', async () => {
    const r = await reqH(port, 'GET', '/v1/admin/pubkey', ADMIN);
    expect(r.status).toBe(200);
    expect(r.json.public_key).toHaveLength(64);
    expect(r.json.key_hash).toHaveLength(64);
  });

  // --- governance: typed, never blind ---

  it('the blind-signing endpoint is GONE: it will not sign an arbitrary hash any more', async () => {
    const r = await reqH(port, 'POST', '/v1/admin/sign-governance', { ...ADMIN, 'x-governance-key': GOV_KEY }, { hash: 'cd'.repeat(32) });
    expect(r.status).toBe(404);   // no route — the wallet cannot be made to sign opaque bytes
  });

  it('POST /v1/admin/key-page executes a TYPED operation the wallet builds itself', async () => {
    const r = await reqH(port, 'POST', '/v1/admin/key-page', { ...ADMIN, 'x-governance-key': GOV_KEY }, { op: 'add-key', keyHash: 'ab'.repeat(32) });
    expect(r.status).toBe(200);
    expect(ctx.keyPageOps).toEqual([{ op: 'add-key', keyHash: 'ab'.repeat(32) }]);
  });

  it('POST /v1/admin/key-page without the governance key → 401', async () => {
    const r = await reqH(port, 'POST', '/v1/admin/key-page', { ...ADMIN, 'x-governance-key': 'wrong' }, { op: 'add-key', keyHash: 'ab'.repeat(32) });
    expect(r.status).toBe(401);
    expect(ctx.keyPageOps).toEqual([]);
  });

  it('key-page governance needs the admin key too — the governance key alone is not enough', async () => {
    const r = await reqH(port, 'POST', '/v1/admin/key-page', { 'x-governance-key': GOV_KEY }, { op: 'add-key', keyHash: 'ab'.repeat(32) });
    expect(r.status).toBe(401);   // rejected at the admin gate, before the governance check
    expect(ctx.keyPageOps).toEqual([]);
  });
});
