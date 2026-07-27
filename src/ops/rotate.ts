/**
 * Key rotation for the Accumulate key page. See docs/OPERATIONS.md for when to use which mode.
 *
 * Rotation is signed by the key being replaced, so it works for BOTH key postures: a local seed or a
 * Vault-held key (we only ever need `EdSigner.sign`, never the private key itself).
 *
 * Three modes. They differ in a way that MATTERS FOR COMPROMISE, not just in convenience — the page
 * version is the network's key-state guard, and only the UpdateKeyPage path advances it:
 *
 *   'updateKey'       ONE transaction (`UpdateKey{newKeyHash}`), atomic. Replaces the key hash in place
 *                     and — per the executor, explicitly — does NOT change the page version. Nonces are
 *                     therefore not reset, and signatures already made at the current version remain
 *                     valid. Right for routine/scheduled rotation. WRONG for a compromised key.
 *
 *   'update'          ONE `UpdateKeyPage{[{update, oldEntry, newEntry}]}` transaction. Atomic, AND it
 *                     bumps the page version, which resets the page's nonces and invalidates signatures
 *                     made at the old version. THIS is the mode for a suspected key compromise.
 *
 *   'add-then-remove' TWO UpdateKeyPage transactions: add the new key, then remove the old one (version
 *                     bumps twice). The page briefly holds BOTH keys, which is what makes it
 *                     zero-downtime: bring the wallet up on the new key while the old one still works,
 *                     confirm it is signing, and only then remove the old key. Do NOT use this for a
 *                     compromised key — it leaves the attacker's key valid during the window.
 *
 * Every mode CONFIRMS on-chain: it polls the key page until its listed key hashes actually reflect the
 * change (and the page version has advanced). A submitted transaction is not a rotated key — Accumulate
 * executes asynchronously, and a rotation you did not confirm is a rotation you cannot rely on.
 */
import { createHash } from 'node:crypto';
import { RawAccumulateClient } from '../accumulate/raw-client.js';
import { EdSigner } from '../signer/signer.js';
import { core } from '../accumulate/sdk.js';
import {
  buildPreimage, buildSigMetaHash, buildSignatureObject, buildSubmitEnvelope, bytesToHex, computeTimestamp, hexToBytes,
} from '../accumulate/signing.js';
import { Logger } from '../logger.js';

export type RotateMode = 'updateKey' | 'update' | 'add-then-remove';

export interface RotateDeps {
  accumulate: RawAccumulateClient;
  signer: EdSigner;          // the CURRENT key (the one on the page today)
  logger: Logger;
  now?: () => number;
}

export interface RotateOptions {
  page: string;              // acc://org.acme/book/1
  newKeyHash: string;        // sha256(new public key), 64 hex
  mode?: RotateMode;         // default 'updateKey'
  confirmTimeoutMs?: number; // default 120s
  pollIntervalMs?: number;   // default 3s
}

export interface PageState {
  version: number;
  keyHashes: string[];
}

export interface RotateResult {
  ok: boolean;
  mode: RotateMode;
  oldKeyHash: string;
  newKeyHash: string;
  submitted: string[];       // tx hashes
  before: PageState;
  after: PageState;
  error?: string;
}

/** Read the key page's version and the key hashes it actually lists. This is the source of truth. */
export async function readPage(acc: RawAccumulateClient, page: string): Promise<PageState> {
  const rec: any = await acc.query(page);
  const account = rec?.account ?? rec?.data ?? rec;
  const keyHashes: string[] = (account?.keys ?? [])
    .map((k: any) => String(k?.publicKeyHash ?? '').toLowerCase())
    .filter(Boolean);
  return { version: Number(account?.version ?? 0), keyHashes };
}

/**
 * Sign an arbitrary transaction with our EdSigner as the INITIATOR.
 *
 * Unlike a vote (where the transaction already exists and someone else initiated it), a transaction we
 * originate must carry `header.initiator` — the hash of our signature metadata — or the network rejects
 * it with "missing initiator". That forces the ordering below: metadata hash first, then the header, then
 * the transaction hash, then the thing we actually sign.
 */
export async function signAndSubmit(d: RotateDeps, page: string, body: unknown, label: string): Promise<string> {
  const { accumulate, signer, logger } = d;
  const now = d.now ?? Date.now;
  const info = await accumulate.getSignerInfo(page);

  const params = {
    publicKey: await signer.publicKey(),
    signerUrl: page,
    signerVersion: info.version,
    timestamp: computeTimestamp(info.lastUsedOn, now() * 1000),
    vote: 'approve' as const,   // Accept(0): marshals as absent, the initiator's normal form
  };
  const initiator = buildSigMetaHash(params);
  const tx = new core.Transaction({ header: { principal: page, initiator }, body });
  const txHash = tx.hash();

  const pre = buildPreimage(txHash, params);   // recomputes the identical sigMdHash == initiator
  const sig = buildSignatureObject(pre, await signer.sign(pre.dataForSignature), bytesToHex(txHash));
  const res = await accumulate.submit(buildSubmitEnvelope(tx.asObject(), sig));
  if (!res.ok) throw new Error(`${label} rejected by the network: ${res.error ?? res.code}`);
  logger.info({ tx: bytesToHex(txHash), op: label }, 'rotation transaction submitted');
  return bytesToHex(txHash);
}

/**
 * Poll the key page until it reflects the rotation. Returns the confirmed page state.
 * `expectPresent` / `expectAbsent` are key hashes that MUST / MUST NOT be listed for the rotation to count.
 */
export async function confirmPage(
  acc: RawAccumulateClient,
  page: string,
  expect: { present?: string[]; absent?: string[]; minVersion?: number },
  logger: Logger,
  timeoutMs = 120_000,
  pollMs = 3_000,
): Promise<PageState> {
  const deadline = (Date.now?.() ?? 0) + timeoutMs;
  let last: PageState = { version: 0, keyHashes: [] };
  for (;;) {
    last = await readPage(acc, page).catch(() => last);
    const has = (h: string) => last.keyHashes.includes(h.toLowerCase());
    const presentOk = (expect.present ?? []).every(has);
    const absentOk = (expect.absent ?? []).every((h) => !has(h));
    const versionOk = expect.minVersion === undefined || last.version >= expect.minVersion;
    if (presentOk && absentOk && versionOk) {
      logger.info({ page, version: last.version, keys: last.keyHashes.length }, 'rotation confirmed on-chain');
      return last;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `rotation NOT confirmed within ${timeoutMs}ms — page ${page} still shows version=${last.version} ` +
        `keys=[${last.keyHashes.join(',')}]. The key may not have rotated; do not decommission the old key.`,
      );
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

export async function rotateKey(d: RotateDeps, o: RotateOptions): Promise<RotateResult> {
  const mode = o.mode ?? 'updateKey';
  const newKeyHash = o.newKeyHash.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(newKeyHash)) throw new Error('newKeyHash must be 64 hex chars (sha256 of the new public key)');

  const { accumulate, logger } = d;
  const oldKeyHash = createHash('sha256').update(await d.signer.publicKey()).digest('hex');

  const before = await readPage(accumulate, o.page);
  logger.info({ page: o.page, mode, oldKeyHash, newKeyHash, version: before.version }, 'starting key rotation');

  if (!before.keyHashes.includes(oldKeyHash)) {
    throw new Error(`refusing to rotate: our current key (${oldKeyHash}) is not on ${o.page} — we cannot sign this rotation`);
  }
  if (before.keyHashes.includes(newKeyHash)) {
    throw new Error(`refusing to rotate: the new key (${newKeyHash}) is ALREADY on ${o.page}`);
  }

  const submitted: string[] = [];
  const timeout = o.confirmTimeoutMs ?? 120_000;
  const poll = o.pollIntervalMs ?? 3_000;
  let after: PageState;

  try {
    // Confirmation asserts on the page's LISTED KEY HASHES — that is what authority means — plus the
    // version, but ONLY where the protocol actually bumps it. The two executors differ deliberately:
    //
    //   UpdateKey     (internal/core/execute/v2/chain/update_key.go)
    //                 "Store the update, but do not change the page version" — version is untouched, so
    //                 nonces are NOT reset and signatures made at the old version stay valid.
    //   UpdateKeyPage (update_key_page.go -> didUpdateKeyPage) — `page.Version += 1` and
    //                 "We're changing the height of the key page, so reset all the nonces".
    //
    // Requiring a version bump after UpdateKey would report a *successful* rotation as a failure and tell
    // the operator to keep trusting a key that no longer has authority — the worst lie this tool could tell.
    if (mode === 'updateKey') {
      // Atomic: the key that signs this transaction is the key that gets replaced. Version unchanged.
      submitted.push(await signAndSubmit(d, o.page, { type: 'updateKey', newKeyHash: hexToBytes(newKeyHash) }, 'updateKey'));
      after = await confirmPage(accumulate, o.page, { present: [newKeyHash], absent: [oldKeyHash] }, logger, timeout, poll);
      if (after.version !== before.version) {
        logger.warn({ before: before.version, after: after.version }, 'updateKey changed the page version — protocol behaviour differs from the executor we verified against');
      }
    } else if (mode === 'update') {
      // UpdateKeyPage: the version MUST advance (didUpdateKeyPage), which also resets the page's nonces
      // and invalidates signatures made at the old version. Assert it — a rotation that did not bump the
      // version did not do what this mode promises.
      submitted.push(await signAndSubmit(d, o.page, {
        type: 'updateKeyPage',
        operation: [{ type: 'update', oldEntry: { keyHash: hexToBytes(oldKeyHash) }, newEntry: { keyHash: hexToBytes(newKeyHash) } }],
      }, 'updateKeyPage/update'));
      after = await confirmPage(accumulate, o.page,
        { present: [newKeyHash], absent: [oldKeyHash], minVersion: before.version + 1 }, logger, timeout, poll);
    } else {
      // Zero-downtime: ADD the new key and confirm it is live BEFORE removing the old one. If the add
      // does not confirm, we stop — never remove a key while it is still the only one that works.
      submitted.push(await signAndSubmit(d, o.page, {
        type: 'updateKeyPage',
        operation: [{ type: 'add', entry: { keyHash: hexToBytes(newKeyHash) } }],
      }, 'updateKeyPage/add'));
      const withBoth = await confirmPage(accumulate, o.page,
        { present: [oldKeyHash, newKeyHash], minVersion: before.version + 1 }, logger, timeout, poll);
      logger.info({ keys: withBoth.keyHashes.length }, 'new key is live alongside the old one — switch the wallet over now, then remove the old key');

      submitted.push(await signAndSubmit(d, o.page, {
        type: 'updateKeyPage',
        operation: [{ type: 'remove', entry: { keyHash: hexToBytes(oldKeyHash) } }],
      }, 'updateKeyPage/remove'));
      after = await confirmPage(accumulate, o.page,
        { present: [newKeyHash], absent: [oldKeyHash], minVersion: withBoth.version + 1 }, logger, timeout, poll);
    }
  } catch (e) {
    const err = (e as Error).message;
    logger.error({ err, page: o.page }, 'key rotation FAILED — verify the page state before touching the old key');
    return { ok: false, mode, oldKeyHash, newKeyHash, submitted, before, after: await readPage(accumulate, o.page).catch(() => before), error: err };
  }

  return { ok: true, mode, oldKeyHash, newKeyHash, submitted, before, after };
}
