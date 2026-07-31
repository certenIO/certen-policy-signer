/**
 * Operator console — backend-for-frontend.
 *
 * WHY THIS EXISTS RATHER THAN A PURE STATIC PAGE. The signer's admin routes are protected by
 * `admin.api_key`, and a browser page cannot hold that key: anything the page can read, the page can
 * leak. So this small server holds the credentials, exposes only the operations below, and serves the UI.
 *
 * It has no dependencies and is meant to be read and modified. Add a route, add a panel — the UI is one
 * HTML file beside this one.
 *
 *   ADMIN_API_KEY=<key> SIGNER_URL=http://127.0.0.1:8080 node console/server.mjs
 *   open http://127.0.0.1:8099
 *
 * Optional:
 *   GOVERNANCE_KEY=<key>   enables the key-page panel (changing keys changes who can act for you, so it
 *                          is deliberately a SEPARATE credential from the pause)
 *   PORT=8099
 *
 * ── SECURITY ──────────────────────────────────────────────────────────────────────────────────────────
 * This is an OPERATOR TOOL. It holds credentials that can pause your signing and reorganize your key
 * page. Run it inside your trust domain — a workstation or a private network — and never expose it
 * publicly. It binds to loopback by default for that reason; changing BIND is a deliberate act.
 *
 * There is intentionally no authentication in front of it: adding a password field would imply a
 * security boundary this does not have. Reachability IS the boundary. Treat it like `kubectl`.
 */
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac } from 'node:crypto';
import { randomUUID } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 8099);
const BIND = process.env.BIND ?? '127.0.0.1';
const SIGNER_URL = (process.env.SIGNER_URL ?? 'http://127.0.0.1:8080').replace(/\/$/, '');
const ADMIN_API_KEY = process.env.ADMIN_API_KEY ?? '';
const GOVERNANCE_KEY = process.env.GOVERNANCE_KEY ?? '';

// ---- the escalation panel ---------------------------------------------------
//
// Optional. Set these and the console grows a queue of what the automated seats
// could not settle, plus a button to sign one with the operator's own seat.
//
// The seat's key never lives here: KEYSTORE_PATH points at an encrypted file and
// the passphrase is typed per signature, used once, and discarded. There is no
// unlocked key and no cached passphrase, so nothing can sign while the operator
// is away — which is the entire reason the escalation seat is separate from the
// automated ones.
const POLICY_URL = (process.env.POLICY_URL ?? '').replace(/\/$/, '');
const POLICY_TOKEN = process.env.POLICY_TOKEN ?? '';
const KEYSTORE_PATH = process.env.CERTEN_KEYSTORE ?? '';
const GATEWAY_URL = (process.env.CERTEN_GATEWAY ?? 'https://gateway.kompendium.co').replace(/\/$/, '');
const GATEWAY_KEY = process.env.CERTEN_API_KEY ?? '';
const PANEL_IDENTITY = process.env.CERTEN_IDENTITY ?? '';
const PANEL_PAGE = process.env.CERTEN_PAGE ?? '';
const ACC_RPC = process.env.ACC_RPC ?? 'https://kermit.accumulatenetwork.io/v3';

/**
 * Exactly which signer routes the browser may reach, and with which method.
 *
 * An allowlist rather than a pass-through proxy: a generic proxy in front of an admin API means the
 * browser can call anything the credential can, and this page is the least trustworthy component in the
 * picture. Adding a capability should be a deliberate line here.
 */
const ALLOW = [
  { method: 'GET', path: '/healthz' },
  { method: 'GET', path: '/v1/requests' },
  { method: 'GET', path: '/v1/admin/pubkey' },
  { method: 'POST', path: '/v1/admin/pause' },
  { method: 'POST', path: '/v1/admin/resume' },
  { method: 'POST', path: '/v1/admin/key-page', governance: true },
  { method: 'POST', path: /^\/v1\/requests\/[a-f0-9]{64}\/retry$/ },
];

function allowed(method, path) {
  return ALLOW.find((a) =>
    a.method === method && (typeof a.path === 'string' ? a.path === path : a.path.test(path)));
}

const send = (res, status, body, type = 'application/json') => {
  const raw = type === 'application/json' ? JSON.stringify(body) : body;
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(raw);
};

const readBody = (req) => new Promise((resolve) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
});

/**
 * Send a synthetic decision request to a candidate policy engine and report exactly what came back.
 *
 * This is the panel integrators use most. Wiring a policy engine fails in a handful of predictable ways —
 * wrong path, non-JSON body, a `decision` value that is not one of the three, a MAC computed over
 * re-serialized JSON instead of the bytes on the wire — and each one shows up in production as "the
 * signer never signs anything", which is a miserable thing to debug from the signer's side.
 *
 * So: test it here, see the raw reply, and get told which rule it broke.
 */
async function testPolicyEngine({ url, hmacSecret, values }) {
  const request = {
    requestId: randomUUID(),
    txHash: 'ab'.repeat(32),
    operationId: 'console-test',
    account: 'acc://example.acme/data',
    chain: 'ethereum',
    actionSummary: 'Console connectivity test — not a real transaction',
    target: '0x0000000000000000000000000000000000000000',
    value: (values && values[0]) || '4000',
    values: values && values.length ? values : ['4000'],
    expiresAt: new Date(Date.now() + 900_000).toISOString(),
  };
  const body = JSON.stringify(request);
  const headers = { 'content-type': 'application/json' };
  if (hmacSecret) {
    const ts = String(Date.now());
    headers['x-signer-timestamp'] = ts;
    headers['x-signer-signature'] = `t=${ts},v1=${createHmac('sha256', hmacSecret).update(`${ts}.${body}`).digest('hex')}`;
  }

  const started = Date.now();
  let res, raw;
  try {
    res = await fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(10_000) });
    raw = await res.text();
  } catch (e) {
    return {
      ok: false,
      stage: 'transport',
      problem: `could not reach the endpoint: ${e.message}`,
      note: 'The signer treats this exactly the same way: it signs nothing and retries.',
      request,
    };
  }
  const ms = Date.now() - started;
  const out = { status: res.status, ms, raw, request, headersSent: Object.keys(headers) };

  if (!res.ok) {
    return { ...out, ok: false, stage: 'status',
      problem: `the endpoint returned HTTP ${res.status}; the signer requires 2xx`,
      note: 'Non-2xx is fail-closed: nothing is signed, and it retries.' };
  }

  let parsed;
  try { parsed = JSON.parse(raw); } catch {
    return { ...out, ok: false, stage: 'json', problem: 'the response body is not JSON' };
  }

  const valid = ['approve', 'deny', 'pending'];
  if (!valid.includes(parsed?.decision)) {
    return { ...out, ok: false, stage: 'decision', parsed,
      problem: `"decision" was ${JSON.stringify(parsed?.decision)}; expected one of ${valid.join(', ')}` };
  }

  // If a secret was supplied, the signer would REQUIRE a valid signature on the response — so check it
  // here, over the raw bytes, exactly as the signer does.
  if (hmacSecret) {
    const sig = res.headers.get('x-signer-signature') || res.headers.get('x-certen-signature') || '';
    const m = /t=(\d+),v1=([a-f0-9]+)/.exec(sig);
    if (!m) {
      return { ...out, ok: false, stage: 'response-auth', parsed,
        problem: 'no signature header on the response, but a shared secret is configured',
        note: 'With policy.auth: hmac the signer REQUIRES a signed response. Unsigned means never signs.' };
    }
    const expect = createHmac('sha256', hmacSecret).update(`${m[1]}.${raw}`).digest('hex');
    if (expect !== m[2]) {
      return { ...out, ok: false, stage: 'response-auth', parsed,
        problem: 'the response signature did not verify over the raw response bytes',
        note: 'Most often this means the MAC was computed over a re-serialized copy of the body rather ' +
              'than the exact bytes sent. Sign the string you write to the socket.' };
    }
    if (Math.abs(Date.now() - Number(m[1])) > 300_000) {
      return { ...out, ok: false, stage: 'response-auth', parsed,
        problem: 'the response timestamp is outside the 5-minute replay window (check clock skew)' };
    }
  }

  return { ...out, ok: true, parsed, decision: parsed.decision,
    note: `Contract satisfied. The signer would ${
      parsed.decision === 'approve' ? 'SIGN this transaction'
      : parsed.decision === 'deny' ? 'cast a REJECT vote'
      : 'sign nothing and ask again next poll'}.` };
}

/**
 * Is this transaction still awaiting signatures on chain?
 *
 * null when unknown — unknown items are still shown, because hiding real work
 * because the network hiccuped is the worse failure of the two.
 */
async function stillPending(txHash) {
  if (!PANEL_IDENTITY) return null;
  try {
    const r = await fetch(ACC_RPC, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'query',
        params: { scope: `acc://${txHash}@${PANEL_IDENTITY.replace('acc://', '')}/data` },
      }),
      signal: AbortSignal.timeout(8000),
    });
    const j = await r.json();
    if (j.error) return null;
    return j.result?.status === 'pending';
  } catch {
    return null;
  }
}

/**
 * Add the operator's signature to a pending transaction, on their own key page.
 *
 * Their page is higher priority and satisfies the book on its own, so this one
 * signature completes work the routine page could never finish.
 */
async function signEscalation(txHash, passphrase) {
  if (!GATEWAY_KEY) throw new Error('CERTEN_API_KEY is not configured');
  if (!PANEL_IDENTITY || !PANEL_PAGE) throw new Error('CERTEN_IDENTITY and CERTEN_PAGE must be set');

  const { loadKeystore, signWithKeystore } = await import('../../certen-carp-starter/examples/keystore.mjs');
  const store = await loadKeystore(KEYSTORE_PATH);

  const gw = async (path, body) => {
    const r = await fetch(`${GATEWAY_URL}${path}`, {
      method: 'POST',
      headers: { 'X-API-Key': GATEWAY_KEY, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await r.text();
    let json; try { json = JSON.parse(text); } catch { json = text; }
    if (!r.ok) throw new Error(`gateway ${path} -> ${r.status}: ${JSON.stringify(json).slice(0, 200)}`);
    return json;
  };

  const prep = await gw('/v1/sign', {
    type: 'pending_tx',
    target_id: txHash,
    identity: PANEL_IDENTITY,
    signer_url: PANEL_PAGE,        // OUR page — the one this signature satisfies
    public_key: store.publicKey,
  });
  const sd = prep.signing_data ?? {};
  const toSign = sd.data_for_signature ?? sd.hash_to_sign;
  if (!toSign) throw new Error('gateway returned no hash to sign');

  // Opens the keystore, signs, and wipes the seed — see keystore.mjs.
  const signature = await signWithKeystore(store, passphrase, toSign);

  const submitted = await gw(prep.submit_url, { signature, public_key: store.publicKey });
  return { signed: txHash, page: PANEL_PAGE, result: submitted };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');
  const path = url.pathname;

  if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
    return send(res, 200, readFileSync(join(HERE, 'index.html'), 'utf8'), 'text/html; charset=utf-8');
  }

  // What the UI needs to know before it renders: which panels are usable.
  if (req.method === 'GET' && path === '/api/config') {
    return send(res, 200, {
      signerUrl: SIGNER_URL,
      hasAdminKey: !!ADMIN_API_KEY,
      hasGovernanceKey: !!GOVERNANCE_KEY,
      // The escalation panel needs all four to be useful; the UI hides it
      // otherwise rather than offering a button that cannot work.
      hasApprovals: !!(POLICY_URL && KEYSTORE_PATH && GATEWAY_KEY && PANEL_PAGE),
      panelPage: PANEL_PAGE,
    });
  }

  if (req.method === 'POST' && path === '/api/test-policy') {
    let input;
    try { input = JSON.parse(await readBody(req) || '{}'); } catch { return send(res, 400, { error: 'bad JSON' }); }
    if (!input.url) return send(res, 400, { error: 'url required' });
    return send(res, 200, await testPolicyEngine(input));
  }

  // ---- escalation queue ----------------------------------------------------
  //
  // What the automated seats could not settle. It comes from the operator's own
  // policy engine; the signer has no opinion about it and is not consulted.
  if (req.method === 'GET' && path === '/api/approvals') {
    if (!POLICY_URL) return send(res, 200, { configured: false, pending: [] });
    try {
      const r = await fetch(`${POLICY_URL}/pending`, {
        headers: POLICY_TOKEN ? { authorization: `Bearer ${POLICY_TOKEN}` } : {},
        signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) return send(res, 502, { error: `policy engine returned ${r.status}` });
      const { pending = [] } = await r.json();
      // Reconcile against the chain: the engine records what IT withheld on and
      // never learns a transaction settled some other way. Listing finished work
      // invites signing something already done.
      const live = await Promise.all(pending.map(async (p) => ({ p, open: await stillPending(p.txHash) })));
      return send(res, 200, {
        configured: true,
        settled: live.filter((x) => x.open === false).length,
        pending: live.filter((x) => x.open !== false).map((x) => x.p),
      });
    } catch (err) {
      return send(res, 502, { error: `policy engine unreachable: ${err.message}` });
    }
  }

  /**
   * Sign one escalation with the operator's own seat.
   *
   * The passphrase arrives per request, is used once, and is never stored,
   * cached or logged. The console holds no key: the keystore stays encrypted on
   * disk and is opened only for the moment of signing. Nothing here can sign
   * while the operator is away, which is the property that makes an escalation
   * seat worth having.
   */
  if (req.method === 'POST' && path === '/api/approve') {
    let input;
    try { input = JSON.parse(await readBody(req) || '{}'); } catch { return send(res, 400, { error: 'bad JSON' }); }
    try {
      if (!KEYSTORE_PATH) return send(res, 400, { error: 'CERTEN_KEYSTORE is not configured' });
      if (!/^[a-fA-F0-9]{64}$/.test(String(input.txHash ?? ''))) {
        return send(res, 400, { error: 'txHash must be 64-character hex' });
      }
      if (!input.passphrase) return send(res, 400, { error: 'passphrase required' });
      const out = await signEscalation(String(input.txHash), String(input.passphrase));
      return send(res, 200, out);
    } catch (err) {
      // The message may say "wrong passphrase"; it must never echo the value.
      return send(res, 400, { error: err.message });
    } finally {
      if (input) input.passphrase = '';
    }
  }

  // Everything else is a proxied signer call.
  if (path.startsWith('/api/signer/')) {
    const target = path.slice('/api/signer'.length) + url.search;
    const targetPath = target.split('?')[0];
    const rule = allowed(req.method, targetPath);
    if (!rule) return send(res, 403, { error: `not an allowed operation: ${req.method} ${targetPath}` });
    if (rule.governance && !GOVERNANCE_KEY) {
      return send(res, 403, { error: 'GOVERNANCE_KEY is not set on this console — key-page operations are disabled' });
    }

    const headers = { 'content-type': 'application/json' };
    if (ADMIN_API_KEY) headers['x-api-key'] = ADMIN_API_KEY;
    if (rule.governance) headers['x-governance-key'] = GOVERNANCE_KEY;
    const body = req.method === 'POST' ? await readBody(req) : undefined;

    try {
      const r = await fetch(SIGNER_URL + target, {
        method: req.method, headers, body: body || undefined, signal: AbortSignal.timeout(30_000),
      });
      const text = await r.text();
      res.writeHead(r.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      return res.end(text || '{}');
    } catch (e) {
      return send(res, 502, { error: `could not reach the signer at ${SIGNER_URL}: ${e.message}` });
    }
  }

  send(res, 404, { error: 'not found' });
});

server.listen(PORT, BIND, () => {
  console.log(`operator console  http://${BIND}:${PORT}`);
  console.log(`  signer:      ${SIGNER_URL}`);
  console.log(`  admin key:   ${ADMIN_API_KEY ? 'set' : 'NOT SET — status is read-only and pause is unavailable'}`);
  console.log(`  governance:  ${GOVERNANCE_KEY ? 'set' : 'not set — key-page panel disabled'}`);
  if (BIND !== '127.0.0.1' && BIND !== 'localhost') {
    console.warn('  WARNING: bound to a non-loopback address. This console holds admin credentials and has');
    console.warn('           no authentication of its own. Do not expose it beyond your trust domain.');
  }
});
