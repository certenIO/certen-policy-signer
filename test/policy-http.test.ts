import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { HttpPolicyClient } from '../src/policy/policy.js';
import { PolicyRequest } from '../src/types.js';

/** A configurable fake policy engine — each test sets `handler`. */
let server: http.Server;
let port = 0;
let handler: (body: string, res: http.ServerResponse) => void;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => handler(Buffer.concat(chunks).toString('utf8'), res));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as any).port;
});
afterAll(() => server.close());

const url = () => `http://127.0.0.1:${port}/decision`;
const REQ: PolicyRequest = {
  requestId: 'r1', txHash: 'ab'.repeat(32), account: 'acc://a.acme/data',
  actionSummary: 'Transfer 4000 wei', value: '4000', expiresAt: new Date(0).toISOString(),
};
const jsonOk = (res: http.ServerResponse, body: unknown, extraHeaders: Record<string, string> = {}) => {
  res.writeHead(200, { 'content-type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(body));
};

/** Sign a raw body exactly as a partner's engine would: HMAC-SHA256(secret, "<ts>.<raw bytes>"). */
function signRaw(secret: string, raw: string, ts = String(Date.now())) {
  const mac = createHmac('sha256', secret).update(`${ts}.${raw}`).digest('hex');
  return { 'x-certen-timestamp': ts, 'x-certen-signature': `t=${ts},v1=${mac}` };
}

describe('HMAC response auth is verified over the RAW bytes on the wire', () => {
  const SECRET = 's3cret';
  const client = () => new HttpPolicyClient({ url: url(), hmacSecret: SECRET });

  // Regression: the MAC used to be checked against JSON.stringify(parse(body)). Any engine whose
  // serialization differs from Node's — Python's json.dumps spacing, or pretty-printed JSON — would fail
  // the MAC forever, and since a bad MAC is a policy failure, the wallet would silently never sign again.
  it('accepts an engine that emits Python-style spacing: {"decision": "approve"}', async () => {
    const raw = '{"decision": "approve", "reason": "biometric match"}';
    handler = (_b, res) => { res.writeHead(200, { 'content-type': 'application/json', ...signRaw(SECRET, raw) }); res.end(raw); };
    await expect(client().decide(REQ)).resolves.toMatchObject({ decision: 'approve' });
  });

  it('accepts a pretty-printed response body', async () => {
    const raw = JSON.stringify({ decision: 'deny', reason: 'no match' }, null, 2);
    handler = (_b, res) => { res.writeHead(200, { 'content-type': 'application/json', ...signRaw(SECRET, raw) }); res.end(raw); };
    await expect(client().decide(REQ)).resolves.toMatchObject({ decision: 'deny' });
  });

  it('rejects a tampered body whose MAC no longer matches', async () => {
    const signed = '{"decision":"deny"}';
    const tampered = '{"decision":"approve"}';   // an attacker flips the verdict in flight
    handler = (_b, res) => { res.writeHead(200, { 'content-type': 'application/json', ...signRaw(SECRET, signed) }); res.end(tampered); };
    await expect(client().decide(REQ)).rejects.toThrow(/bad response auth/);
  });

  it('rejects a stale decision (replay bound)', async () => {
    const raw = '{"decision":"approve"}';
    const old = String(Date.now() - 3600_000);   // an hour-old approval, correctly signed
    handler = (_b, res) => { res.writeHead(200, { 'content-type': 'application/json', ...signRaw(SECRET, raw, old) }); res.end(raw); };
    await expect(client().decide(REQ)).rejects.toThrow(/outside the .*window|replay/);
  });

  it('signs the REQUEST over its raw body too, so the engine can authenticate us', async () => {
    let seen: { body: string; sig: string } | undefined;
    const raw = '{"decision":"approve"}';
    handler = (b, res) => {
      seen = { body: b, sig: '' };
      res.writeHead(200, { 'content-type': 'application/json', ...signRaw(SECRET, raw) });
      res.end(raw);
    };
    await client().decide(REQ);
    expect(JSON.parse(seen!.body).txHash).toBe(REQ.txHash);
  });
});

describe('HttpPolicyClient wire behavior', () => {
  it('accepts a well-formed approve', async () => {
    handler = (_b, res) => jsonOk(res, { decision: 'approve', reason: 'ok' });
    const d = await new HttpPolicyClient({ url: url() }).decide(REQ);
    expect(d.decision).toBe('approve');
  });

  it('accepts a well-formed deny', async () => {
    handler = (_b, res) => jsonOk(res, { decision: 'deny', reason: 'risk' });
    expect((await new HttpPolicyClient({ url: url() }).decide(REQ)).decision).toBe('deny');
  });

  it('rejects a malformed decision (fail-closed)', async () => {
    handler = (_b, res) => jsonOk(res, { decision: 'maybe' });
    await expect(new HttpPolicyClient({ url: url() }).decide(REQ)).rejects.toThrow(/malformed/i);
  });

  it('throws on non-2xx (retryable, no decision)', async () => {
    handler = (_b, res) => { res.writeHead(500).end('boom'); };
    await expect(new HttpPolicyClient({ url: url() }).decide(REQ)).rejects.toThrow(/HTTP 500/);
  });

  describe('HMAC response authentication', () => {
    const secret = 's3cret';
    // A fresh timestamp: decisions carry a replay bound, so a fixed 2023 timestamp would be rejected as
    // stale before the MAC is ever checked — and the bad-MAC test below would then pass for the wrong reason.
    const sign = (body: string) => {
      const ts = String(Date.now());
      const mac = createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
      return { 'x-certen-signature': `t=${ts},v1=${mac}` };
    };

    it('accepts a correctly-signed response', async () => {
      handler = (_b, res) => { const body = JSON.stringify({ decision: 'approve' }); res.writeHead(200, { 'content-type': 'application/json', ...sign(body) }); res.end(body); };
      const d = await new HttpPolicyClient({ url: url(), hmacSecret: secret }).decide(REQ);
      expect(d.decision).toBe('approve');
    });

    it('rejects a response with a bad MAC', async () => {
      handler = (_b, res) => jsonOk(res, { decision: 'approve' }, { 'x-certen-signature': `t=${Date.now()},v1=deadbeef` });
      await expect(new HttpPolicyClient({ url: url(), hmacSecret: secret }).decide(REQ)).rejects.toThrow(/bad response auth/i);
    });

    it('rejects a response missing the signature header', async () => {
      handler = (_b, res) => jsonOk(res, { decision: 'approve' });
      await expect(new HttpPolicyClient({ url: url(), hmacSecret: secret }).decide(REQ)).rejects.toThrow(/missing response auth/i);
    });
  });
});
