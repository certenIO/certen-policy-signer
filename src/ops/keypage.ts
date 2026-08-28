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
  | { op: 'set-threshold'; threshold: number }
  // A SEAT on this page, held by somebody else's key book. Runbook F Phase F3: a roster names an
  // employee's own book as a delegate, so revoking authority removes one entry and retires no
  // identity, and the two things that change at different rates -- who holds a role, and what the
  // role may do -- stop sharing an object.
  | { op: 'add-delegate'; delegate: string }
  | { op: 'remove-delegate'; delegate: string };

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
  /**
   * Submitted, and the network is holding it until somebody else signs.
   *
   * Only `add-delegate` produces this, and it is the normal outcome rather than a degraded one:
   * `update_key_page.go` `TransactionIsReady` requires that all new delegates sign the transaction
   * that adds them, so the seat does not exist until the employee's own key has agreed to hold it.
   * That is invariant F-5, enforced by the protocol.
   *
   * `ok: true` with `awaitingConsent: true` means the proposal was made. It does NOT mean anybody
   * holds a seat, and a caller that renders the two the same way has quietly reported an enrolment
   * that has not happened.
   */
  awaitingConsent?: boolean;
  error?: string;
}

const HEX32 = /^[0-9a-f]{64}$/;

/**
 * A delegate must be a key BOOK.
 *
 * `verifyIsNotPage` in update_key_page.go refuses a page, so this is caught locally rather than by
 * spending a transaction to be told. A page URL is a book URL with a trailing index -- that is the
 * only difference between `acc://bank.acme/alice/book` and `acc://bank.acme/alice/book/1`, and one of
 * them is a seat while the other is an error.
 */
function delegateBook(u: string): string {
  const v = String(u ?? '').trim();
  if (!/^acc:\/\/[^/]+\/.+/i.test(v)) {
    throw new Error(`delegate must be an acc:// key book URL, got ${JSON.stringify(u)}`);
  }
  if (/\/\d+$/.test(v)) {
    throw new Error(`delegate ${v} is a key page — a delegate must be a key book, not a page (drop the trailing index)`);
  }
  return v;
}

/** acc:// URLs are not case-sensitive, and a seat spelled differently is not a second seat. */
const sameUrl = (a: string, b: string): boolean => a.toLowerCase().replace(/\/+$/, '') === b.toLowerCase().replace(/\/+$/, '');

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

      case 'add-delegate': {
        const book = delegateBook(req.delegate);
        if (before.entries.some((e) => e.delegate && sameUrl(e.delegate, book))) {
          throw new Error(`${book} already holds a seat on ${page}`);
        }
        const tx = await signAndSubmit({ accumulate, signer, logger }, page, {
          type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: book } }],
        }, 'updateKeyPage/add-delegate');

        // NOT confirmed, and deliberately not waited for. The protocol holds this transaction until the
        // new delegate signs it too, so polling the page would block for the full timeout and then
        // report a timeout -- a working control, described as a fault, with an obvious and wrong fix.
        // One read, so the answer is what the page says rather than what we assume.
        const after = await readPage(accumulate, page).catch(() => before);
        const seated = after.entries.some((e) => e.delegate && sameUrl(e.delegate, book));
        logger.info({ page, delegate: book, seated }, seated ? 'delegate seat added' : "delegate seat proposed — awaiting the delegate's own signature");
        return { ok: true, op: req.op, submitted: [tx], before, after, ...(seated ? {} : { awaitingConsent: true }) };
      }

      case 'remove-delegate': {
        const book = delegateBook(req.delegate);
        if (!before.entries.some((e) => e.delegate && sameUrl(e.delegate, book))) {
          throw new Error(`${book} is not on ${page}`);
        }
        // The same protection remove-key has: a page with no entries authorises nothing, forever.
        if (before.entries.length <= 1) throw new Error('refusing to remove the only entry on the page — the role would become permanently unexercisable');
        const tx = await signAndSubmit({ accumulate, signer, logger }, page, {
          type: 'updateKeyPage', operation: [{ type: 'remove', entry: { delegate: book } }],
        }, 'updateKeyPage/remove-delegate');
        // Removal confirms, unlike the proposal: nobody else is being asked for anything, so the page
        // moves on the next block and a caller may rely on the result.
        const after = await confirmPage(accumulate, page, { delegatesAbsent: [book], minVersion: before.version + 1 }, logger, timeoutMs);
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
