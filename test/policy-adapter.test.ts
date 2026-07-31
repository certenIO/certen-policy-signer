/**
 * The policy adapter seam — pointing the signer at an approvals API that already exists.
 *
 * An adapter runs between the network and the signing decision, so the tests that matter are the ones
 * proving it CANNOT loosen anything: it cannot invent an approval, cannot skip response authentication,
 * and cannot turn its own bugs into signatures.
 */
import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { createHmac } from 'node:crypto';
import { HttpPolicyClient, PolicyAdapter, loadPolicyAdapter } from '../src/policy/policy.js';
import { PolicyRequest } from '../src/types.js';

const REQ: PolicyRequest = {
  requestId: 'r-1', txHash: 'ab'.repeat(32), operationId: 'PO-1043',
  account: 'acc://acme.acme/orders', chain: 'ethereum', actionSummary: 'Transfer 4000 wei',
  target: '0xBe00', value: '4000', values: ['4000'], expiresAt: '2026-07-29T12:00:00Z',
};

/** A server that records the request and replies however the test says. */
async function engine(reply: { status?: number; body?: string; sign?: string }) {
  const seen: Array<{ body: string; headers: Record<string, string>; url: string }> = [];
  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    seen.push({ body: raw, headers: req.headers as Record<string, string>, url: req.url ?? '' });
    const body = reply.body ?? '{"decision":"approve"}';
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (reply.sign) {
      const t = String(Date.now());
      headers['x-signer-signature'] = `t=${t},v1=${createHmac('sha256', reply.sign).update(`${t}.${body}`).digest('hex')}`;
    }
    res.writeHead(reply.status ?? 200, headers).end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return { seen, url: `http://127.0.0.1:${port}/decide`, close: () => server.close() };
}

describe('policy adapter — reshaping the request', () => {
  it('sends the adapter\'s body and headers instead of the default shape', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = {
        name: 'acme',
        buildRequest: (r) => ({ body: { ref: r.operationId, amounts: r.values }, headers: { 'x-api-key': 'k1' } }),
      };
      const out = await new HttpPolicyClient({ url: e.url, adapter }).decide(REQ);
      expect(out.decision).toBe('approve');
      expect(JSON.parse(e.seen[0].body)).toEqual({ ref: 'PO-1043', amounts: ['4000'] });
      expect(e.seen[0].headers['x-api-key']).toBe('k1');
    } finally { e.close(); }
  });

  it('sends a string body verbatim, so a non-JSON encoding is possible', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = {
        name: 'form', buildRequest: (r) => ({ body: `ref=${r.operationId}`, headers: { 'content-type': 'application/x-www-form-urlencoded' } }),
      };
      await new HttpPolicyClient({ url: e.url, adapter }).decide(REQ);
      expect(e.seen[0].body).toBe('ref=PO-1043');
    } finally { e.close(); }
  });

  it('honors a per-request url override', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = { name: 'perpath', buildRequest: () => ({ body: {}, url: `${e.url}/sub/path` }) };
      await new HttpPolicyClient({ url: e.url, adapter }).decide(REQ);
      expect(e.seen[0].url).toBe('/decide/sub/path');
    } finally { e.close(); }
  });

  /** The MAC must cover the bytes actually sent, so authentication does not depend on the adapter. */
  it('signs the adapter\'s bytes when hmac is on', async () => {
    const secret = 's3cret';
    const e = await engine({ sign: secret });
    try {
      const adapter: PolicyAdapter = { name: 'acme', buildRequest: () => ({ body: { hello: 'world' } }) };
      await new HttpPolicyClient({ url: e.url, adapter, hmacSecret: secret }).decide(REQ);
      const { body, headers } = e.seen[0];
      const m = /t=(\d+),v1=([a-f0-9]+)/.exec(headers['x-signer-signature']);
      expect(createHmac('sha256', secret).update(`${m![1]}.${body}`).digest('hex')).toBe(m![2]);
    } finally { e.close(); }
  });

  it('withholds when buildRequest throws — it never falls back to the default shape', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = { name: 'broken', buildRequest: () => { throw new Error('kaboom'); } };
      await expect(new HttpPolicyClient({ url: e.url, adapter }).decide(REQ)).rejects.toThrow(/buildRequest threw/);
      expect(e.seen).toHaveLength(0);   // nothing was sent at all
    } finally { e.close(); }
  });
});

describe('policy adapter — reshaping the response', () => {
  it('maps a foreign vocabulary onto a decision', async () => {
    const e = await engine({ body: '{"outcome":"ALLOW","rule_name":"under-limit","rule_id":12}' });
    try {
      const adapter: PolicyAdapter = {
        name: 'acme',
        parseResponse: ({ body }) => {
          const r = JSON.parse(body);
          return r.outcome === 'ALLOW'
            ? { decision: 'approve', reason: r.rule_name, evidence: { ruleId: r.rule_id } }
            : { decision: 'deny' };
        },
      };
      const out = await new HttpPolicyClient({ url: e.url, adapter }).decide(REQ);
      expect(out).toMatchObject({ decision: 'approve', reason: 'under-limit', evidence: { ruleId: 12 } });
    } finally { e.close(); }
  });

  /**
   * Some APIs say "denied" with a 403. The default path treats any non-2xx as a failure (withhold), which
   * would leave the transaction pending instead of killing it — so an adapter is handed the status and
   * decides what it means.
   */
  it('can treat a non-2xx status as a real deny rather than an outage', async () => {
    const e = await engine({ status: 403, body: '{"blocked":true}' });
    try {
      const adapter: PolicyAdapter = {
        name: 'acme',
        parseResponse: ({ status }) => (status === 403 ? { decision: 'deny', reason: 'blocked' } : { decision: 'approve' }),
      };
      expect((await new HttpPolicyClient({ url: e.url, adapter }).decide(REQ)).decision).toBe('deny');
    } finally { e.close(); }
  });

  // ── the security properties ─────────────────────────────────────────────────────────────────────────

  it('CANNOT invent a decision value the signer does not recognize', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = { name: 'sneaky', parseResponse: () => ({ decision: 'ALLOW' as never }) };
      await expect(new HttpPolicyClient({ url: e.url, adapter }).decide(REQ)).rejects.toThrow(/decision malformed/);
    } finally { e.close(); }
  });

  it('CANNOT approve by returning nothing', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = { name: 'empty', parseResponse: () => undefined as never };
      await expect(new HttpPolicyClient({ url: e.url, adapter }).decide(REQ)).rejects.toThrow(/decision malformed/);
    } finally { e.close(); }
  });

  it('withholds when parseResponse throws', async () => {
    const e = await engine({});
    try {
      const adapter: PolicyAdapter = { name: 'broken', parseResponse: () => { throw new Error('bad schema'); } };
      await expect(new HttpPolicyClient({ url: e.url, adapter }).decide(REQ)).rejects.toThrow(/parseResponse threw/);
    } finally { e.close(); }
  });

  /**
   * The one an adapter must never be able to skip. Response auth runs BEFORE parseResponse, so an
   * unauthenticated reply cannot reach adapter code at all — otherwise adding an adapter would silently
   * remove the protection that stops anything on the network path from returning an approval.
   */
  it('verifies the response MAC BEFORE the adapter sees the body', async () => {
    const e = await engine({ body: '{"outcome":"ALLOW"}' });   // NOT signed
    try {
      let called = false;
      const adapter: PolicyAdapter = {
        name: 'acme',
        parseResponse: () => { called = true; return { decision: 'approve' }; },
      };
      await expect(new HttpPolicyClient({ url: e.url, adapter, hmacSecret: 's3cret' }).decide(REQ))
        .rejects.toThrow(/missing response auth/);
      expect(called).toBe(false);
    } finally { e.close(); }
  });
});

describe('loadPolicyAdapter', () => {
  it('returns undefined when nothing is configured', async () => {
    expect(await loadPolicyAdapter(undefined)).toBeUndefined();
  });

  it('loads the shipped example', async () => {
    const a = await loadPolicyAdapter('./examples/policy-adapter.mjs');
    expect(a?.name).toBe('acme-approvals-v2');
    expect(typeof a?.buildRequest).toBe('function');
    expect(typeof a?.parseResponse).toBe('function');
  });

  /** Boot must stop rather than silently keep the default shape and talk the wrong protocol. */
  it('throws on a module that cannot be loaded', async () => {
    await expect(loadPolicyAdapter('./examples/does-not-exist.mjs')).rejects.toThrow(/failed to load/);
  });

  it('throws on a module that does nothing, rather than loading a no-op', async () => {
    await expect(loadPolicyAdapter('./test/fixtures/adapter-noop.mjs')).rejects.toThrow(/neither buildRequest nor parseResponse/);
  });
});
