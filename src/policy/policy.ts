/** Policy engine client: interface, an HTTP impl, and a mock for tests. */
import axios from 'axios';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Decision, PolicyRequest } from '../types.js';

export interface PolicyClient {
  decide(req: PolicyRequest): Promise<Decision>;
}

/**
 * Header names for the signed channel.
 *
 * Vendor-neutral by default so an integrator is not asked to emit another company's header names. The
 * legacy names are still ACCEPTED on responses (never sent) so an engine written against the previous
 * release keeps working; point `signatureHeader` at whatever your engine already emits.
 */
export const DEFAULT_SIGNATURE_HEADER = 'x-signer-signature';
export const DEFAULT_TIMESTAMP_HEADER = 'x-signer-timestamp';
export const LEGACY_SIGNATURE_HEADER = 'x-certen-signature';

export interface HttpPolicyOptions {
  url: string;
  timeoutMs?: number;
  hmacSecret?: string;       // if set, sign the request and verify the response
  maxSkewSeconds?: number;   // reject decisions whose timestamp is outside this window (replay bound)
  signatureHeader?: string;  // default DEFAULT_SIGNATURE_HEADER
  timestampHeader?: string;  // default DEFAULT_TIMESTAMP_HEADER
  /** Called once if a response is authenticated via the legacy header, so the deprecation is visible. */
  onLegacyHeader?: (header: string) => void;
  // mTLS would be configured at the axios/agent level (omitted in POC)
}

/** Constant-time hex compare (a plain !== leaks the expected MAC's prefix through timing). */
function macEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8'), y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Synchronous HTTP policy client. Async/callback mode is handled by the server layer. */
export class HttpPolicyClient implements PolicyClient {
  private legacyWarned = false;

  constructor(private readonly opts: HttpPolicyOptions) {}

  private get sigHeader(): string { return this.opts.signatureHeader ?? DEFAULT_SIGNATURE_HEADER; }
  private get tsHeader(): string { return this.opts.timestampHeader ?? DEFAULT_TIMESTAMP_HEADER; }

  async decide(req: PolicyRequest): Promise<Decision> {
    const body = JSON.stringify(req);
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.opts.hmacSecret) {
      const ts = String(Date.now());
      const mac = createHmac('sha256', this.opts.hmacSecret).update(`${ts}.${body}`).digest('hex');
      headers[this.tsHeader] = ts;
      headers[this.sigHeader] = `t=${ts},v1=${mac}`;
    }
    const res = await axios.post(this.opts.url, body, {
      headers,
      timeout: this.opts.timeoutMs ?? 10_000,
      validateStatus: () => true,
      maxRedirects: 0,
      // Keep the response body as the RAW BYTES the engine sent. axios would otherwise parse it, and
      // verifying the MAC over JSON.stringify(parse(body)) is NOT verifying what was signed: an engine
      // that emits `{"decision": "approve"}` (Python's json.dumps spacing) or pretty-printed JSON would
      // fail the MAC forever, and — because a bad MAC is a policy failure — the wallet would silently
      // never sign again. Verify the wire bytes, then parse.
      transformResponse: [(d) => d],
      responseType: 'text',
    });
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`policy engine HTTP ${res.status}`);
    }
    const raw: string = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

    // Response authentication: if an HMAC secret is configured, require + verify it.
    if (this.opts.hmacSecret) {
      // Prefer the configured header; fall back to the legacy name so an engine written against the
      // previous release still authenticates rather than silently failing closed forever.
      const configured = String(res.headers[this.sigHeader.toLowerCase()] ?? '');
      let sig = configured;
      if (!sig && this.sigHeader.toLowerCase() !== LEGACY_SIGNATURE_HEADER) {
        sig = String(res.headers[LEGACY_SIGNATURE_HEADER] ?? '');
        if (sig && !this.legacyWarned) {
          this.legacyWarned = true;
          this.opts.onLegacyHeader?.(LEGACY_SIGNATURE_HEADER);
        }
      }
      const m = /t=(\d+),v1=([a-f0-9]+)/.exec(sig);
      if (!m) throw new Error('policy decision rejected: missing response auth');

      // Replay bound: a decision signed long ago must not be replayable as a fresh approval.
      const skewSeconds = Math.abs(Date.now() - Number(m[1])) / 1000;
      const maxSkew = this.opts.maxSkewSeconds ?? 300;
      if (!Number.isFinite(skewSeconds) || skewSeconds > maxSkew) {
        throw new Error(`policy decision rejected: timestamp outside the ${maxSkew}s window (clock skew or replay)`);
      }
      const expect = createHmac('sha256', this.opts.hmacSecret).update(`${m[1]}.${raw}`).digest('hex');
      if (!macEqual(expect, m[2])) throw new Error('policy decision rejected: bad response auth');
    }

    let data: unknown;
    try { data = JSON.parse(raw); } catch { throw new Error('policy decision malformed: response is not JSON'); }
    const d = data as Decision;
    // `pending` is a valid answer meaning "not decided yet" — see Decision in types.ts. Anything else is
    // malformed, which the caller treats as a failure to decide: fail-closed, sign nothing, retry.
    if (d?.decision !== 'approve' && d?.decision !== 'deny' && d?.decision !== 'pending') {
      throw new Error(
        `policy decision malformed: expected decision to be "approve", "deny" or "pending", got ${JSON.stringify(d?.decision)}`,
      );
    }
    return d;
  }
}

/** Mock policy client — returns a canned decision (or a per-tx function). */
export class MockPolicyClient implements PolicyClient {
  calls: PolicyRequest[] = [];
  constructor(private readonly responder: Decision | ((r: PolicyRequest) => Promise<Decision> | Decision)) {}
  async decide(req: PolicyRequest): Promise<Decision> {
    this.calls.push(req);
    return typeof this.responder === 'function' ? this.responder(req) : this.responder;
  }
}
