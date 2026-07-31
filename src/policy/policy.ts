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

/**
 * Reshapes the decision call to fit an API you already have.
 *
 * Without one, the signer sends its own JSON and expects `{"decision":"approve"}` back. That is a clean
 * contract but it assumes you are writing a new endpoint for it. Plenty of integrators are not — they have
 * an approvals service, a rules engine, a fraud API, already deployed, already speaking some other shape.
 * An adapter lets the signer talk to that directly instead of making you deploy a translating shim.
 *
 * Both methods are optional; supply only the direction you need.
 *
 * THE FAIL-CLOSED RULE STILL HOLDS, and it is enforced here rather than trusted. `parseResponse` may only
 * return one of the three decisions; anything else — a different string, undefined, a thrown error — is a
 * failure to decide, and a failure to decide withholds the signature. An adapter cannot widen what counts
 * as an approval, only describe where to find one.
 */
export interface PolicyAdapter {
  name: string;
  /**
   * Turn the signer's decision request into the bytes to send. Return `body` as a string to control the
   * encoding exactly (form-encoded, XML, a different JSON shape); return an object and it is JSON-encoded.
   * `headers` are merged over the defaults, so this is also where an API key or a tenant header goes.
   * `url` overrides `policy.url` per request — for an engine with a per-account path.
   */
  buildRequest?(req: PolicyRequest): { body: unknown; headers?: Record<string, string>; url?: string };
  /**
   * Read your engine's reply. `body` is the RAW response text, exactly as it arrived — parse it yourself,
   * including deciding what a non-2xx status means. Return a Decision, or throw to withhold.
   */
  parseResponse?(res: { status: number; body: string; headers: Record<string, string> }): Decision;
}

export interface HttpPolicyOptions {
  url: string;
  timeoutMs?: number;
  hmacSecret?: string;       // if set, sign the request and verify the response
  maxSkewSeconds?: number;   // reject decisions whose timestamp is outside this window (replay bound)
  signatureHeader?: string;  // default DEFAULT_SIGNATURE_HEADER
  timestampHeader?: string;  // default DEFAULT_TIMESTAMP_HEADER
  /** Called once if a response is authenticated via the legacy header, so the deprecation is visible. */
  onLegacyHeader?: (header: string) => void;
  /** Reshapes the request and/or the response. See PolicyAdapter. */
  adapter?: PolicyAdapter;
  // mTLS would be configured at the axios/agent level (omitted in POC)
}

/**
 * The gate every decision passes through, adapter or not.
 *
 * Exported because this is the security property worth testing directly: whatever produced the value, only
 * these three strings are decisions, and everything else raises — which the orchestrator treats as
 * "withhold and retry".
 */
export function assertDecision(d: unknown, source: string): Decision {
  const v = (d as Decision)?.decision;
  if (v !== 'approve' && v !== 'deny' && v !== 'pending') {
    throw new Error(
      `policy decision malformed: ${source} produced decision=${JSON.stringify(v)}, expected "approve", "deny" or "pending"`,
    );
  }
  return d as Decision;
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
    const adapter = this.opts.adapter;

    // Shape the outbound call. An adapter that throws here is a failure to decide, like any other — it
    // must not fall back to the default shape, because sending a request the engine will misread is worse
    // than sending none: it can produce an approval for something other than what was asked.
    let body: string;
    let url = this.opts.url;
    let extraHeaders: Record<string, string> = {};
    if (adapter?.buildRequest) {
      let built;
      try {
        built = adapter.buildRequest(req);
      } catch (e) {
        throw new Error(`policy adapter "${adapter.name}" buildRequest threw: ${(e as Error).message}`);
      }
      body = typeof built.body === 'string' ? built.body : JSON.stringify(built.body);
      extraHeaders = built.headers ?? {};
      if (built.url) url = built.url;
    } else {
      body = JSON.stringify(req);
    }

    const headers: Record<string, string> = { 'content-type': 'application/json', ...extraHeaders };
    // The MAC covers the bytes actually sent, adapter output included — so authentication does not depend
    // on the adapter cooperating, and an adapter cannot produce an unsigned request by accident.
    if (this.opts.hmacSecret) {
      const ts = String(Date.now());
      const mac = createHmac('sha256', this.opts.hmacSecret).update(`${ts}.${body}`).digest('hex');
      headers[this.tsHeader] = ts;
      headers[this.sigHeader] = `t=${ts},v1=${mac}`;
    }
    const res = await axios.post(url, body, {
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
    const raw: string = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

    // An adapter with a parseResponse owns the whole reply, INCLUDING what a status code means — some APIs
    // answer 403 for "denied", and forcing that through the default not-2xx check would turn a real deny
    // into a withhold. It is handed the status and decides. The MAC below is still verified first, so an
    // adapter never sees a reply the signer could not authenticate.
    if (adapter?.parseResponse) {
      this.verifyResponseAuth(res, raw);
      let out: Decision;
      try {
        out = adapter.parseResponse({ status: res.status, body: raw, headers: res.headers as Record<string, string> });
      } catch (e) {
        throw new Error(`policy adapter "${adapter.name}" parseResponse threw: ${(e as Error).message}`);
      }
      return assertDecision(out, `adapter "${adapter.name}"`);
    }

    if (res.status < 200 || res.status >= 300) {
      throw new Error(`policy engine HTTP ${res.status}`);
    }

    this.verifyResponseAuth(res, raw);

    let data: unknown;
    try { data = JSON.parse(raw); } catch { throw new Error('policy decision malformed: response is not JSON'); }
    // `pending` is a valid answer meaning "not decided yet" — see Decision in types.ts. Anything else is
    // malformed, which the caller treats as a failure to decide: fail-closed, sign nothing, retry.
    return assertDecision(data, 'the policy engine');
  }

  /**
   * Response authentication: if an HMAC secret is configured, require + verify it over the RAW bytes.
   *
   * Shared by the default and adapter paths so that adding an adapter cannot skip it. An adapter reshapes
   * what a reply *means*; it has no say in whether the reply is authentic.
   */
  private verifyResponseAuth(res: { headers: Record<string, unknown> }, raw: string): void {
    if (!this.opts.hmacSecret) return;
    // Prefer the configured header; fall back to the legacy name so an engine written against the
    // previous release still authenticates rather than silently failing closed forever.
    let sig = String(res.headers[this.sigHeader.toLowerCase()] ?? '');
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
}

/**
 * Load a policy adapter module. Same seam and same rules as `resolver.decoder_modules`: a path or a
 * package name, default-exporting the adapter. An unloadable or malformed module stops the boot rather
 * than falling back to the default shape — a signer talking the wrong protocol to a real engine either
 * gets nothing signed or, worse, gets the wrong thing signed.
 */
export async function loadPolicyAdapter(spec: string | undefined): Promise<PolicyAdapter | undefined> {
  if (!spec) return undefined;
  const { pathToFileURL } = await import('node:url');
  const { resolve } = await import('node:path');
  const target = /^[./]|^[A-Za-z]:[\\/]/.test(spec) ? pathToFileURL(resolve(spec)).href : spec;

  let mod: { default?: unknown };
  try {
    mod = (await import(target)) as { default?: unknown };
  } catch (err) {
    throw new Error(`policy.adapter_module: failed to load "${spec}" — ${err instanceof Error ? err.message : String(err)}`);
  }
  const a = mod.default as PolicyAdapter | undefined;
  if (!a || typeof a !== 'object' || typeof a.name !== 'string') {
    throw new Error(`policy.adapter_module: "${spec}" must default-export an object with a string \`name\``);
  }
  if (typeof a.buildRequest !== 'function' && typeof a.parseResponse !== 'function') {
    throw new Error(
      `policy.adapter_module: "${spec}" defines neither buildRequest nor parseResponse, so it would do nothing`,
    );
  }
  return a;
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
