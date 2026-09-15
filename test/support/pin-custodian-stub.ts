/**
 * A test stand-in for the PIN custodian (contract §2), implementing its release rules closely enough to
 * exercise the signer's client: HMAC over `t + "." + body`, a 60 s clock window, single-use nonces, the
 * configured page and key label, and an "approved" set of transaction hashes standing in for the party's
 * decision service. FICTIONAL; the PIN it releases is whatever the test hands it.
 */
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { createHmac, timingSafeEqual } from 'node:crypto';

export interface CustodianStubOptions {
  hmacSecret: string;
  pin: () => string;
  page: string;
  keyLabel: string;
  approved: Set<string>;
}

export interface CustodianRequest {
  body: { txHash: string; principal: string; page: string; keyLabel: string; ts: number; nonce: string };
  result: 'released' | 'refused';
  reason?: string;
}

export async function startCustodianStub(opts: CustodianStubOptions) {
  const seen: CustodianRequest[] = [];
  const nonces = new Set<string>();
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const refuse = (reason: string, body?: CustodianRequest['body']) => {
        if (body) seen.push({ body, result: 'refused', reason });
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ reason }));
      };
      const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(String(req.headers['x-pin-auth'] ?? ''));
      if (req.method !== 'POST' || req.url !== '/v1/pin' || !m) return refuse('bad request');
      const expected = createHmac('sha256', opts.hmacSecret).update(`${m[1]}.${raw}`).digest();
      if (!timingSafeEqual(expected, Buffer.from(m[2]!, 'hex'))) return refuse('bad hmac');
      let body: CustodianRequest['body'];
      try { body = JSON.parse(raw); } catch { return refuse('bad body'); }
      if (Math.abs(Date.now() - Number(m[1])) > 60_000) return refuse('stale', body);
      if (nonces.has(body.nonce)) return refuse('replayed nonce', body);
      nonces.add(body.nonce);
      if (body.page !== opts.page || body.keyLabel !== opts.keyLabel) return refuse('page or key label mismatch', body);
      if (!opts.approved.has(body.txHash)) return refuse('no approve decision for this transaction', body);
      seen.push({ body, result: 'released' });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ pin: opts.pin() }));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/pin`;
  return { url, seen, close: () => new Promise<void>((r) => server.close(() => r())) };
}
