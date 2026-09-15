/**
 * The PIN custodian client — a per-signature PKCS#11 user PIN, released by the key holder's own cell.
 * Phase 8, custody Mode 3 (contract §1.1 and §2).
 *
 * In Mode 3 the signer runs in the bank's cell but the HSM token's user PIN never lives there. For every
 * signature this client asks the custodian in the key holder's cell, naming the transaction; the custodian
 * releases the PIN only if its own party's decision service approved that transaction for its seat. The
 * custodian therefore gates each PIN RELEASE on the party's approval, and an honest signer asks every time.
 *
 * WHAT THIS DOES NOT STOP. The token has one static user PIN. A compromised signer host — which the bank
 * controls in Mode 3 — can keep the PIN after a single release, and holding the token files it can then sign
 * without the custodian, or attack the token offline. Protection per USE needs a per-signature credential or
 * an HSM that enforces party-authorised use: for example a PIN rotated by the custodian after every release,
 * or an HSM key-use-authorisation mechanism. docs/KEY-SOURCES.md records this.
 *
 *   POST {url}   body    {"txHash","principal","page","keyLabel","ts","nonce"}
 *                header  x-pin-auth: t=<unix ms>,v1=<hex hmac-sha256(secret, t + "." + body)>
 *   200 {"pin"}  released          403 {"reason"}  refused — no PIN
 *
 * FAIL CLOSED. Anything other than a well-formed 200 — a refusal, a timeout, a redirect, a 5xx, a body that
 * is not JSON or carries no PIN — throws, and the caller signs nothing. The error carries the custodian's
 * `reason` (sanitised, truncated) and never the response body itself.
 *
 * NOT LOGGED, NOT CACHED. The PIN is returned to the one caller that logs in with it. The raw response bytes
 * are overwritten before this returns. The PIN also exists as a JavaScript string, because that is what
 * `C_Login` takes (pkcs11js), and a JS string cannot be overwritten: it becomes unreachable when the caller
 * drops it and is reclaimed by the garbage collector. docs/KEY-SOURCES.md records that limit.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { SignContext } from './signer.js';

export interface PinSourceOptions {
  url: string;
  hmacSecret: string;
  timeoutMs?: number;
  /** Test seams. */
  fetch?: typeof fetch;
  now?: () => number;
}

/** A refusal or failure from the custodian. Its message never contains a PIN. */
export class PinSourceError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'PinSourceError';
  }
}

const printable = (s: string): string => s.replace(/[^\x20-\x7e]/g, '?').slice(0, 200);

/** The exact header the custodian verifies. Exported so tests (and the custodian's own tests) share it. */
export function pinAuthHeader(secret: string, t: number, body: string): string {
  const mac = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  return `t=${t},v1=${mac}`;
}

export async function requestPin(opts: PinSourceOptions, ctx: SignContext, keyLabel: string): Promise<string> {
  if (!opts.hmacSecret) throw new PinSourceError('pin_source: no HMAC secret configured');
  const doFetch = opts.fetch ?? fetch;
  const ts = (opts.now ?? Date.now)();
  const nonce = randomBytes(16).toString('hex');
  const body = JSON.stringify({ txHash: ctx.txHash, principal: ctx.principal, page: ctx.page, keyLabel, ts, nonce });

  let res: Response;
  try {
    res = await doFetch(opts.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-pin-auth': pinAuthHeader(opts.hmacSecret, ts, body) },
      body,
      redirect: 'error',
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
    });
  } catch (e) {
    const name = (e as Error).name === 'TimeoutError' ? 'timed out' : printable((e as Error).message);
    throw new PinSourceError(`pin custodian unreachable: ${name}`);
  }

  let raw: Buffer | undefined;
  try {
    raw = Buffer.from(await res.arrayBuffer());
    let parsed: unknown;
    try { parsed = JSON.parse(raw.toString('utf8')); } catch { parsed = undefined; }
    if (res.status !== 200) {
      const reason = parsed && typeof (parsed as { reason?: unknown }).reason === 'string'
        ? printable((parsed as { reason: string }).reason)
        : 'no reason given';
      throw new PinSourceError(`pin custodian refused (HTTP ${res.status}): ${reason}`, res.status);
    }
    const pin = parsed && typeof parsed === 'object' ? (parsed as { pin?: unknown }).pin : undefined;
    if (typeof pin !== 'string' || pin.length === 0) {
      throw new PinSourceError('pin custodian answered 200 without a PIN');
    }
    return pin;
  } catch (e) {
    if (e instanceof PinSourceError) throw e;
    throw new PinSourceError(`pin custodian response unreadable: ${printable((e as Error).name)}`);
  } finally {
    raw?.fill(0);
  }
}
