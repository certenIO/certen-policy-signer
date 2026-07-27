/**
 * Governance operations on the org's OWN key page — typed, never blind.
 *
 * This exists to kill a capability we used to expose: an endpoint that signed an arbitrary caller-supplied
 * 32-byte hash with the org's key. That is blind signing. However well it is credentialed, the wallet has no
 * idea what it just authorised — the "hash" could be any transaction at all, including a token transfer out
 * of the org's accounts. A signer must never sign bytes it did not construct.
 *
 * So the caller states its INTENT (rotate this key; add that key; set the threshold) and the wallet:
 *   1. builds the transaction itself, from that intent,
 *   2. forces the principal to be its OWN key page (never a caller-supplied URL),
 *   3. signs what it built, and
 *   4. confirms the result by reading the key page back.
 *
 * The worst a compromised governance credential can now do is reorganise the org's own key page — which is
 * bad, and is why the credential is separate and audited — but it can no longer make the org's key sign
 * anything else in the universe.
 */
import { RawAccumulateClient } from '../accumulate/raw-client.js';
import { EdSigner } from '../signer/signer.js';
import { Logger } from '../logger.js';
import { hexToBytes } from '../accumulate/signing.js';
import { confirmPage, readPage, rotateKey, signAndSubmit, PageState, RotateMode } from './rotate.js';

export type KeyPageOp =
  | { op: 'rotate-key'; newKeyHash: string; mode?: RotateMode }
  | { op: 'add-key'; keyHash: string }
  | { op: 'remove-key'; keyHash: string }
  | { op: 'set-threshold'; threshold: number };

export interface KeyPageDeps {
  accumulate: RawAccumulateClient;
  signer: EdSigner;
  logger: Logger;
  /** OUR key page. The principal is always this — it is not accepted from the caller. */
  page: string;
}

export interface KeyPageResult {
  ok: boolean;
  op: string;
  submitted: string[];
  before: PageState;
  after: PageState;
  error?: string;
}

const HEX32 = /^[0-9a-f]{64}$/;

/** Validate + execute one governance operation against our own key page. */
export async function applyKeyPageOp(d: KeyPageDeps, req: KeyPageOp, timeoutMs = 90_000): Promise<KeyPageResult> {
  const { accumulate, signer, logger, page } = d;
  const before = await readPage(accumulate, page);

  const hash = (h: string, what: string) => {
    const v = String(h ?? '').toLowerCase().replace(/^0x/, '');
    if (!HEX32.test(v)) throw new Error(`${what} must be 64 hex chars (sha256 of an ed25519 public key)`);
    return v;
  };

  try {
    switch (req.op) {
      case 'rotate-key': {
        // Delegates to the rotation path, which confirms on-chain and refuses unsafe states.
        const r = await rotateKey({ accumulate, signer, logger }, {
          page, newKeyHash: hash(req.newKeyHash, 'newKeyHash'), mode: req.mode ?? 'updateKey', confirmTimeoutMs: timeoutMs,
        });
        return { ok: r.ok, op: req.op, submitted: r.submitted, before: r.before, after: r.after, error: r.error };
      }

      case 'add-key': {
        const kh = hash(req.keyHash, 'keyHash');
        if (before.keyHashes.includes(kh)) throw new Error(`key ${kh} is already on ${page}`);
        const tx = await signAndSubmit({ accumulate, signer, logger }, page, {
          type: 'updateKeyPage', operation: [{ type: 'add', entry: { keyHash: hexToBytes(kh) } }],
        }, 'updateKeyPage/add');
        const after = await confirmPage(accumulate, page, { present: [kh], minVersion: before.version + 1 }, logger, timeoutMs);
        return { ok: true, op: req.op, submitted: [tx], before, after };
      }

      case 'remove-key': {
        const kh = hash(req.keyHash, 'keyHash');
        if (!before.keyHashes.includes(kh)) throw new Error(`key ${kh} is not on ${page}`);
        // Refuse to strip the page of its last key: that would make the org permanently unable to sign.
        if (before.keyHashes.length <= 1) throw new Error('refusing to remove the only key on the page — the org would lose its authority irrecoverably');
        const tx = await signAndSubmit({ accumulate, signer, logger }, page, {
          type: 'updateKeyPage', operation: [{ type: 'remove', entry: { keyHash: hexToBytes(kh) } }],
        }, 'updateKeyPage/remove');
        const after = await confirmPage(accumulate, page, { absent: [kh], minVersion: before.version + 1 }, logger, timeoutMs);
        return { ok: true, op: req.op, submitted: [tx], before, after };
      }

      case 'set-threshold': {
        const t = Number(req.threshold);
        if (!Number.isInteger(t) || t < 1) throw new Error('threshold must be a positive integer');
        if (t > before.keyHashes.length) throw new Error(`threshold ${t} exceeds the ${before.keyHashes.length} key(s) on the page — it could never be met`);
        const tx = await signAndSubmit({ accumulate, signer, logger }, page, {
          type: 'updateKeyPage', operation: [{ type: 'setThreshold', threshold: t }],
        }, 'updateKeyPage/setThreshold');
        const after = await confirmPage(accumulate, page, { minVersion: before.version + 1 }, logger, timeoutMs);
        return { ok: true, op: req.op, submitted: [tx], before, after };
      }

      default:
        throw new Error(`unknown governance operation: ${JSON.stringify((req as { op?: unknown }).op)}`);
    }
  } catch (e) {
    const error = (e as Error).message;
    logger.error({ op: (req as { op?: string }).op, err: error, page }, 'governance operation FAILED');
    return { ok: false, op: String((req as { op?: string }).op), submitted: [], before, after: await readPage(accumulate, page).catch(() => before), error };
  }
}
