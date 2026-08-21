/**
 * Reference enrollment module — proving control of an Accumulate ADI before biometric capture.
 *
 * THIS IS YOUR HALF OF ENROLLMENT. It is a companion to `policy-engine.mjs`, not a replacement: that
 * file answers "should this transaction execute?" (reauth). This one answers the question that has to
 * be settled BEFORE reauth can mean anything — "does the person enrolling actually control
 * acc://their-adi.acme?"
 *
 * Copy this file, replace ONE function (`onEnrolled`), fill in CONFIG, and you are integrated.
 *
 * ── Why a page that just signs a nonce is not enough ──────────────────────────────────────────────
 *
 * The obvious design is: issue a random nonce, have the user sign it with an ADI key, verify the
 * signature against the key page. It works, and it is weaker than it looks:
 *
 *   - It proves possession of ONE key that is currently listed on SOME page. If the ADI's book is
 *     2-of-3, one key is not the authority — a single compromised key would bind an attacker's
 *     biometric to the identity forever.
 *   - Keys rotate. A binding to a key, a page, or even a specific book goes stale the moment the user
 *     reorganises their governance, and you have no way to notice.
 *   - The proof lives in your database. It proves nothing to a third party later.
 *
 * This module instead makes the CHAIN do the authority resolution. You submit a transaction that
 * cannot complete without the user's key book approving it, and you let Accumulate decide what
 * "approving" means — one key, 2-of-3, a delegation chain, whatever the ADI's governance actually is.
 * You never learn the structure and you never track rotations.
 *
 * ── The mechanic ─────────────────────────────────────────────────────────────────────────────────
 *
 * You write a data entry to YOUR OWN data account, and name the user's key book as an ADDITIONAL
 * AUTHORITY in the transaction header:
 *
 *      principal:              acc://trust-stamp.acme/enrollments   <- yours. you own it, you pay.
 *      header.authorities:   [ acc://alice.acme/book ]              <- theirs. must also approve.
 *      header.expire.atTime:   now + windowMs                       <- unsigned in time => fails
 *
 * You sign as initiator. The transaction then sits PENDING until the user's book approves it, and
 * Accumulate refuses to execute until it does — additional authorities are required, not advisory.
 * When it executes, that IS the proof, and it is threshold-correct by construction.
 *
 * Three terminal outcomes, all settled by the chain, none needing a timer on your side:
 *
 *      delivered  -> ENROLLED   the user's book reached its threshold and accepted
 *      rejected   -> DECLINED   the user cast reject/abstain, or named an invalid book
 *      expired    -> LAPSED     the deadline passed unsigned
 *
 * The executed entry is your enrollment record, on your account, signed by your key. Keep it or prune
 * it; it is yours. An auditor can point at it later and see exactly which identity enrolled and when.
 *
 * ── Where it goes in your flow ───────────────────────────────────────────────────────────────────
 *
 *      1. user supplies their ADI + key book       -> preflight()
 *      2. start the enrollment                     -> startEnrollment()
 *      3. hand the user the signing URL            -> your UI
 *      4. poll                                     -> awaitEnrollment()
 *      5. on ENROLLED, capture biometrics          -> onEnrolled()   <- the function you replace
 *
 * Nothing in your `/decision` endpoint changes. Enrollment is purely additive.
 *
 * ── The browser half ─────────────────────────────────────────────────────────────────────────────
 *
 * This module is server-side. Step 5 happens in your page, and it is a TWO-STEP flow — key
 * selection, then signature. Both steps are required; see `signPendingWithProvider` below, which
 * implements them:
 *
 *      const p = window.certen || window.accumulate;
 *      if (typeof p?.selectKey !== 'function' || typeof p?.signHash !== 'function') {
 *        throw new Error('Install or update the Certen Key Vault extension');   // not a TypeError
 *      }
 *      const sel = await p.selectKey({ keyType: 'ed25519', purpose: '…' });   // 1. picker
 *      const sig = await p.signHash({ hash: preimage, address: keyPageUrl,     // 2. approval
 *                                     keyType: 'ed25519', humanReadable: { … } });
 *
 * Do NOT feature detect on `isCerten` — a second Certen extension injects `window.certen` and sets
 * that flag without implementing these methods, so the check passes and the call fails as
 * undefined-is-not-a-function deep inside a promise.
 *
 * And do not reach for `signPendingTransaction`. It exists, but `signHash` is what certen-web-app
 * ships and what has been verified end to end against a live extension.
 *
 * ── Requirements ─────────────────────────────────────────────────────────────────────────────────
 *
 *   npm install accumulate-sdk-opendlt
 *
 *   An ADI, a key page with credits, and a data account you own. The key page pays for every
 *   enrollment it initiates, so watch its credit balance like any other operational budget.
 *
 *   A network running executor version >= 6 (Baikonur). Additional authorities do not exist below
 *   that, and a transaction naming them would sit pending until it expired rather than failing —
 *   so every enrollment would silently "lapse". `preflight` checks this and refuses to continue.
 */

import {
  Accumulate,
  Ed25519KeyPair,
  SimpleExternalKey,
  Address,
  TxBody,
  core,
  messaging,
} from 'accumulate-sdk-opendlt';

// ── CONFIG ────────────────────────────────────────────────────────────────────────────────────────

export const CONFIG = {
  /** 'kermit' (testnet) | 'mainnet' | 'devnet'. Start on kermit. */
  network: process.env.ACC_NETWORK ?? 'kermit',

  /** Your data account. Enrollment records are written here. You must own and fund it. */
  dataAccount: process.env.TS_DATA_ACCOUNT ?? 'acc://trust-stamp.acme/enrollments',

  /** Your key page — the signer that initiates and PAYS for each enrollment. */
  signerUrl: process.env.TS_SIGNER_URL ?? 'acc://trust-stamp.acme/book/1',

  /** Your Ed25519 private key, hex. 64 bytes (seed||public) or 32 bytes (seed). */
  privateKeyHex: process.env.TS_PRIVATE_KEY ?? '',

  /**
   * How long the user has to sign before the enrollment lapses.
   *
   * Accumulate caps pending transactions at `Limits.PendingMajorBlocks` (default 14 major blocks,
   * roughly two weeks) whether or not you set this, so `expire` can only ever SHORTEN the window.
   * An enrollment session should be hours, not a fortnight — a stale half-finished enrollment is a
   * support ticket waiting to happen.
   */
  windowMs: Number(process.env.TS_ENROLLMENT_WINDOW_MS ?? 4 * 60 * 60 * 1000),

  /**
   * Where to send the user to sign — a CONVENIENCE, not a dependency.
   *
   * CONFIRM THIS WITH CERTEN BEFORE SHIPPING. It is the one value in this file that is not derivable
   * from the chain, and a wrong one fails silently as "the user never signed".
   *
   * If you do not want to depend on it at all, you do not have to: `signPending()` below casts the
   * vote from the txHash alone, so any signer you can drive — your own page calling the extension,
   * a CLI, a custody service — closes the enrollment. The URL is only the shortest path for a user
   * who already has the Key Vault installed.
   */
  signingUrlTemplate:
    process.env.TS_SIGNING_URL ?? 'https://app.certen.io/sign?txid={txHash}&signer={keyBook}',
};

/** Executor version that introduced additional authorities (Baikonur). */
const MIN_EXECUTOR_VERSION = 6;

/** Enrollment states. Only PENDING is non-terminal. */
export const EnrollmentState = {
  PENDING: 'pending',
  ENROLLED: 'enrolled',
  DECLINED: 'declined',
  LAPSED: 'lapsed',
};

// ── Client ────────────────────────────────────────────────────────────────────────────────────────

let _client;

export function client() {
  if (_client) return _client;
  switch (CONFIG.network) {
    case 'mainnet': _client = Accumulate.forMainnet(); break;
    case 'devnet':  _client = Accumulate.forDevnet();  break;
    default:        _client = Accumulate.forKermit();  break;
  }
  return _client;
}

/** v2 query responses are sometimes {data:{...}} and sometimes {...}. Normalise once, here. */
function unwrap(res) {
  return res?.data ?? res ?? {};
}

/** Accumulate URLs are case-insensitive and tolerate a trailing slash. Compare them normalised. */
function sameUrl(a, b) {
  const norm = (u) => String(u ?? '').trim().toLowerCase().replace(/\/+$/, '');
  return norm(a) !== '' && norm(a) === norm(b);
}

// ── 1. preflight ──────────────────────────────────────────────────────────────────────────────────

/**
 * Validate an (ADI, key book) pair BEFORE spending a transaction on it.
 *
 * +---------------------------------------------------------------------------------------------+
 * |  DO NOT REIMPLEMENT OR SHORTEN THIS FUNCTION.                                                |
 * |                                                                                              |
 * |  The check that matters is the third one: the book must be IN THE ADI'S AUTHORITY SET. It is |
 * |  tempting to skip it, because `acc://alice.acme/book` so obviously "belongs to"              |
 * |  `acc://alice.acme` — the URL says so. It does not follow.                                   |
 * |                                                                                              |
 * |  Alice can create additional key books under her own ADI and populate them with other         |
 * |  people's keys. Such a book is a child of `alice.acme` by URL and is NOT an authority of it.  |
 * |  Whoever holds a key in that book controls the book — not the identity. Accept one as proof   |
 * |  and you bind a biometric template to an identity the enrollee does not control, which is the |
 * |  worst failure this system can have: that person's face now approves Alice's transactions,    |
 * |  permanently.                                                                                |
 * |                                                                                              |
 * |  Inferring authority from the URL prefix is the bug. Read the authority set.                  |
 * +---------------------------------------------------------------------------------------------+
 *
 * Cheap: three reads, no chain writes, no credits at risk. Run it on every enrollment — reading the
 * authority set at verification time is also what makes key rotation a non-event.
 *
 * @returns {Promise<{ok: boolean, reason?: string, adi?: string, keyBook?: string}>}
 */
export async function preflight(adiUrl, keyBookUrl) {
  const c = client();

  // (0) The network must actually support additional authorities.
  try {
    const status = await c.v3.networkStatus();
    const raw = status?.executorVersion;
    const version = typeof raw === 'number' ? raw : Number(raw ?? NaN);
    // Compare numerically and never by name: the enum's names have drifted between SDK releases,
    // and an unrecognised name would parse as NaN and skip the check silently.
    if (Number.isFinite(version) && version > 0 && version < MIN_EXECUTOR_VERSION) {
      return {
        ok: false,
        reason: `network executor version ${version} < ${MIN_EXECUTOR_VERSION} (Baikonur); additional authorities are not supported`,
      };
    }
  } catch (err) {
    return { ok: false, reason: `could not read network status: ${err?.message ?? err}` };
  }

  // (1) The book must exist and be a key book. Naming anything else — an ADI, a data account, a
  //     typo — makes the network auto-ABSTAIN on its behalf, and any non-accept vote rejects the
  //     transaction outright. That costs you a transaction and the credits to record its failure.
  let book;
  try {
    book = unwrap(await c.queryAccount(keyBookUrl));
  } catch {
    return { ok: false, reason: `key book ${keyBookUrl} does not exist` };
  }
  if (String(book?.type ?? '').toLowerCase() !== 'keybook') {
    return { ok: false, reason: `${keyBookUrl} is a ${book?.type ?? 'unknown account'}, not a key book` };
  }

  // (2) The ADI must exist.
  let adi;
  try {
    adi = unwrap(await c.queryAccount(adiUrl));
  } catch {
    return { ok: false, reason: `ADI ${adiUrl} does not exist` };
  }

  // (3) THE ONE THAT MATTERS. Is this book an authority OF that ADI?
  const authorities = adi?.authorities ?? adi?.accountAuth?.authorities ?? [];
  if (!Array.isArray(authorities) || authorities.length === 0) {
    return { ok: false, reason: `could not read the authority set of ${adiUrl}` };
  }
  const entry = authorities.find((a) => sameUrl(a?.url ?? a, keyBookUrl));
  if (!entry) {
    return {
      ok: false,
      reason: `${keyBookUrl} is not an authority of ${adiUrl} — it may exist under that ADI without governing it`,
    };
  }
  // A disabled authority does not speak for the identity. Treat it as not-control.
  if (entry?.disabled === true) {
    return { ok: false, reason: `${keyBookUrl} is a disabled authority of ${adiUrl}` };
  }

  return { ok: true, adi: adiUrl, keyBook: keyBookUrl };
}

// ── 2. startEnrollment ────────────────────────────────────────────────────────────────────────────

function signerKey() {
  const hex = CONFIG.privateKeyHex?.trim();
  if (!hex) throw new Error('CONFIG.privateKeyHex is empty — set TS_PRIVATE_KEY');
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.length !== 32 && bytes.length !== 64) {
    throw new Error(`CONFIG.privateKeyHex must be 32 or 64 bytes, got ${bytes.length}`);
  }
  return Ed25519KeyPair.fromPrivateKey(bytes).toKey();
}

async function signerVersion() {
  const page = unwrap(await client().queryAccount(CONFIG.signerUrl));
  const v = Number(page?.version ?? 1);
  return Number.isFinite(v) && v > 0 ? v : 1;
}

/**
 * Build, sign, and submit the enrollment transaction.
 *
 * Runs `preflight` first — do not add a way to skip it.
 *
 * @param {{adiUrl: string, keyBookUrl: string, enrollmentId: string, record?: object}} args
 * @returns {Promise<{txHash: string, signingUrl: string, expiresAt: string}>}
 */
export async function startEnrollment({ adiUrl, keyBookUrl, enrollmentId, record = {} }) {
  if (!enrollmentId) {
    throw new Error('enrollmentId is required — it is what makes each enrollment distinct');
  }

  const check = await preflight(adiUrl, keyBookUrl);
  if (!check.ok) throw new Error(`preflight failed: ${check.reason}`);

  const c = client();
  const key = signerKey();
  const expiresAt = new Date(Date.now() + CONFIG.windowMs);

  // The entry that becomes the on-chain enrollment record. `enrollmentId` must be single-use on your
  // side: it is what stops a previously executed enrollment being replayed as a fresh one, and it is
  // what makes each transaction hash distinct.
  const entry = JSON.stringify({
    v: 1,
    kind: 'certen.enrollment',
    enrollmentId,
    adi: adiUrl,
    keyBook: keyBookUrl,
    issuedAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    ...record,
  });

  const txn = new core.Transaction({
    header: {
      principal: CONFIG.dataAccount,
      // The whole mechanic, in one field: the user's book MUST also approve. Accumulate treats
      // additional authorities as required, and resolves the book's own threshold itself.
      authorities: [keyBookUrl],
      expire: { atTime: expiresAt },
      memo: `certen-enrollment:${enrollmentId}`,
    },
    body: TxBody.writeData([entry]),
  });

  const sig = await key.sign(txn, {
    signer: CONFIG.signerUrl,
    signerVersion: await signerVersion(),
    timestamp: Date.now() * 1000,
  });

  const submitted = await c.v2.execute(new messaging.Envelope({ transaction: [txn], signatures: [sig] }));

  // Hash AFTER signing, and never before. Signing populates `header.initiator`, which is part of the
  // preimage, so a hash taken earlier identifies no transaction on the network.
  //
  // Worse: `hash()` MEMOISES. Calling it before signing does not merely return the wrong value once —
  // it caches that value on the transaction, and every later call returns the same stale hash even
  // though the initiator is now set. So "hash it early for a log line, hash it again properly later"
  // silently yields a dead txid that polls as PENDING forever. Hash once, here.
  const txHash = Buffer.from(txn.hash()).toString('hex');

  // Cross-check our locally computed hash against the one the NETWORK assigned.
  //
  // This is the single most valuable guard in the file. Co-signing is a hash-matching exercise: the
  // second signer signs a hash, and if that hash is off by one bit it signs a transaction that does
  // not exist. Nothing rejects it — the signature is perfectly valid, just for nothing. The vote
  // never lands, the real transaction stays pending, and it eventually lapses with no error anywhere.
  //
  // Every header field is in the preimage, so anything the SDK encodes differently from the node —
  // a field it drops, a field number it disagrees on — produces exactly that silent failure. Compare
  // the hashes once, here, where a mismatch is one loud exception instead of a lapsed enrollment and
  // a support ticket.
  const networkHash = String(submitted?.transactionHash ?? '').toLowerCase();
  if (networkHash && networkHash !== txHash) {
    throw new Error(
      `transaction hash mismatch: computed ${txHash}, network assigned ${networkHash}. `
      + 'Do NOT sign the computed hash — it identifies no transaction. This means the SDK and the '
      + 'node disagree about how to encode the transaction header.',
    );
  }

  return {
    txHash,
    expiresAt: expiresAt.toISOString(),
    signingUrl: CONFIG.signingUrlTemplate
      .replace('{txHash}', txHash)
      .replace('{keyBook}', encodeURIComponent(keyBookUrl)),
  };
}

// ── 3. checkEnrollment / awaitEnrollment ──────────────────────────────────────────────────────────

/**
 * One non-blocking read of an enrollment's state.
 *
 * Do not infer "enrolled" from the presence of a signature. A signature is not a threshold, and
 * anyone may sign a pending transaction — a stranger's key page can cast a vote that appears in the
 * signature set and is only rejected later, at the authority stage. The transaction's own status is
 * the only authoritative verdict.
 *
 * @returns {Promise<{state: string, code?: string, txHash: string}>}
 */
export async function checkEnrollment(txHash) {
  let res;
  try {
    res = await client().queryTx(txHash);
  } catch (err) {
    // A query that does not resolve means one of two very different things, and reporting both as
    // PENDING — which this function used to do — hides the one that matters.
    //
    //   1. The transaction was just submitted and is not indexed yet. Transient; keep waiting.
    //   2. NO TRANSACTION HAS THIS HASH. Permanent. You are polling a hash that identifies nothing,
    //      and it will read as "pending" until the heat death of the universe.
    //
    // (2) is the signature of a hash computed wrong, and it is the single most confusing bug in
    // this whole flow because every symptom says "the user just hasn't signed yet". Surface it as
    // its own state so a caller can tell "waiting" from "waiting forever".
    return {
      state: EnrollmentState.PENDING,
      unresolved: true,
      error: err?.message ?? String(err),
      txHash,
    };
  }

  const code = String(res?.status?.code ?? unwrap(res)?.status?.code ?? '').toLowerCase();

  switch (code) {
    case 'delivered':
      return { state: EnrollmentState.ENROLLED, code, txHash };
    case 'rejected':
      // The user voted reject/abstain, or an authority named in the header was invalid.
      return { state: EnrollmentState.DECLINED, code, txHash };
    case 'expired':
      return { state: EnrollmentState.LAPSED, code, txHash };
    case 'pending':
    case 'remote':
    case '':
      return { state: EnrollmentState.PENDING, code, txHash };
    default:
      // Any other failure code is terminal, and is not a decline by the user.
      return { state: EnrollmentState.DECLINED, code, txHash };
  }
}

/**
 * Poll until the enrollment reaches a terminal state.
 *
 * Every call here is async by design — there is no callback to register and no inbound endpoint to
 * expose. If you would rather drive this from your own job runner, use `checkEnrollment` directly.
 */
export async function awaitEnrollment(
  txHash,
  { intervalMs = 5000, timeoutMs = CONFIG.windowMs } = {},
) {
  const deadline = Date.now() + timeoutMs;
  // A transaction that never resolves is not "pending", it is a hash that identifies nothing. Give
  // indexing a fair grace period, then stop pretending the wait is meaningful.
  const graceMs = Math.max(intervalMs * 6, 45_000);
  const started = Date.now();

  for (;;) {
    const status = await checkEnrollment(txHash);
    if (status.state !== EnrollmentState.PENDING) return status;

    if (status.unresolved && Date.now() - started > graceMs) {
      throw new Error(
        `no transaction found with hash ${txHash} after ${Math.round((Date.now() - started) / 1000)}s. `
        + 'This is not a slow signer — it means the hash identifies no transaction, so any signature '
        + `cast against it votes on nothing. Last query error: ${status.error}`,
      );
    }

    if (Date.now() >= deadline) return { ...status, timedOut: true };
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

// ── 3b. Signing a pending transaction by txHash ───────────────────────────────────────────────────

/**
 * Per-message result codes that mean the vote did NOT land.
 *
 * A signature-only envelope normalises into TWO messages — your signature, and a RemoteTransaction
 * placeholder for the transaction being voted on — and they get INDEPENDENT status codes:
 *
 *     [{ txID: "acc://<placeholder>@<your signer>",  code: "notFound" },   <-- the vote is LOST
 *      { txID: "acc://<txHash>@unknown",             code: "ok"        }]  <-- looks fine!
 *
 * `v2.execute` will not raise this. It checks `res.result.error`, but `result` here is an ARRAY of
 * per-message statuses with no top-level error, so a dropped vote returns "success".
 */
function droppedCodes(resp) {
  return (Array.isArray(resp?.result) ? resp.result : [])
    .filter((r) => r?.code && !['ok', 'delivered', 'pending'].includes(r.code));
}

/**
 * Cast a vote on an ALREADY-SUBMITTED, on-chain pending transaction, holding only its hash.
 *
 * In production the user does this in the browser, via the Key Vault extension. You need it here for
 * two reasons: to test the whole flow end to end without a browser, and because the SDK ships no
 * example of it — every multi-signature example it has (`example_10_threshold_updates`,
 * `example_15_co_signing`, `examples/advanced/delegated`) collects all signatures IN MEMORY and
 * submits once. That pattern needs the original envelope object, which a second signer arriving
 * minutes later, from another machine, does not have. They have a txHash.
 *
 * The trick is that the SDK's `Signable` type is just `{ hash(): Uint8Array }` — it does not have to
 * be a Transaction. `BaseKey.sign` guards its initiator logic with `message instanceof Transaction`,
 * so a bare hash shim skips that branch cleanly rather than throwing on the missing header. The
 * resulting signature is BYTE-IDENTICAL to what you would get by co-signing the full transaction
 * object, which is what makes this safe: it is the same signature, produced without the object.
 *
 * If you want that confirmed independently, the Python SDK's `SmartSigner.sign_existing` documents
 * the same formula in prose:
 *
 *     preimage = SHA256(cosigner_sig_metadata_hash + existing_tx_hash)
 *
 * Note what is NOT in it: the transaction. Only its hash. Python takes an envelope purely to
 * recompute that hash locally — and cannot be used for THIS transaction, because its header encoder
 * stops at field 4 ("Fields 5-7: Expire, HoldUntil, Authorities - not implemented for basic use"),
 * so it would hash a truncated header and sign a transaction that does not exist. This SDK encodes
 * all seven fields with the same numbering as Go, which is why enrollment is built on it.
 *
 * The envelope is then the signature-only form — `txHash` set, `transaction` omitted.
 *
 * Note this is NOT the "submitting between signatures trips replay protection" case that
 * `example_15_co_signing` warns about. That warning is about re-submitting the SAME signature. Here
 * a different key, under a different signer, votes once on a transaction already on chain — which is
 * the ordinary pending-transaction flow.
 *
 * A successful return means the node ACCEPTED the envelope, not that the vote is recorded and the
 * transaction executed. Those are separate events, and on a busy network the gap can be tens of
 * seconds. Always confirm with `checkEnrollment`/`awaitEnrollment` rather than treating this
 * function returning as proof of enrollment.
 *
 * The good news is that this fails in the safe direction: a vote that is submitted but never lands
 * leaves the transaction PENDING, and it eventually LAPSES. It cannot produce a false ENROLLED.
 *
 * @param {string} txHash  64-char hex, from `startEnrollment`.
 * @param {{signerUrl: string, privateKeyHex: string, vote?: 'accept'|'reject'}} opts
 */
export async function signPending(
  txHash, { signerUrl, privateKeyHex, vote = 'accept', attempts = 5, backoffMs = 6000 },
) {
  const c = client();
  const bytes = Buffer.from(privateKeyHex.trim(), 'hex');
  if (bytes.length !== 32 && bytes.length !== 64) {
    throw new Error(`privateKeyHex must be 32 or 64 bytes, got ${bytes.length}`);
  }
  const key = Ed25519KeyPair.fromPrivateKey(bytes).toKey();

  // Wait until the transaction actually RESOLVES before voting on it.
  //
  // This is the race that eats votes. The enrollment transaction is submitted on the PRINCIPAL's
  // partition; a vote is submitted on the SIGNER's. Until the transaction has propagated to the
  // signer's partition, a signature against it has nothing to attach to and is silently discarded —
  // see the result-code check below. Signing six seconds after submission loses the vote; signing
  // once it resolves does not.
  for (let i = 0; i < attempts; i++) {
    if (!(await checkEnrollment(txHash)).unresolved) break;
    if (i === attempts - 1) {
      throw new Error(
        `transaction ${txHash} still does not resolve after ${attempts} attempts; refusing to sign. `
        + 'A vote cast now would be valid but would attach to nothing.',
      );
    }
    await new Promise((r) => setTimeout(r, backoffMs));
  }

  const page = unwrap(await c.queryAccount(signerUrl));
  const version = Number(page?.version ?? 1);

  const signOnce = () => key.sign(
    // The shim. Anything with hash() is Signable.
    { hash: () => Buffer.from(txHash, 'hex') },
    {
      signer: signerUrl,
      signerVersion: Number.isFinite(version) && version > 0 ? version : 1,
      // Timestamps must strictly increase per key, or the network rejects the signature as a replay.
      // This is also why a retry must RE-SIGN rather than resubmit the same envelope.
      timestamp: Date.now() * 1000,
      vote: vote === 'reject' ? core.VoteType.Reject : core.VoteType.Accept,
    },
  );

  const submit = async () => c.v2.execute(
    new messaging.Envelope({ signatures: [await signOnce()], txHash: Buffer.from(txHash, 'hex') }),
  );

  // Retry a dropped vote. `notFound` means the transaction had not reached this partition yet, which
  // is transient — but the retry needs a FRESH signature, because the timestamp must advance.
  let resp = await submit();
  for (let i = 1; i < attempts && droppedCodes(resp).length; i++) {
    await new Promise((r) => setTimeout(r, backoffMs));
    resp = await submit();
  }

  // INSPECT THE PER-MESSAGE RESULTS. This is not optional bookkeeping — it is the difference between
  // an enrollment that works and one that silently never completes.
  //
  // A signature-only envelope normalises into TWO messages: your signature, and a RemoteTransaction
  // placeholder standing in for the transaction being voted on. They get INDEPENDENT status codes:
  //
  //     [{ txID: "acc://<placeholder>@<your signer>",  code: "notFound" },   <-- the failure
  //      { txID: "acc://<txHash>@unknown",             code: "ok"        }]  <-- looks fine!
  //
  // `notFound` on the placeholder means the signer's partition does not know about that transaction
  // yet. Your signature is cryptographically perfect and is dropped on the floor. The transaction
  // stays pending, nothing errors, and it eventually lapses.
  //
  // `v2.execute` will NOT raise this. It checks `res.result.error`, but here `result` is an ARRAY of
  // per-message statuses and there is no top-level error — so a dropped vote returns "success".
  //
  // The usual cause is signing too early: the enrollment transaction is submitted on the PRINCIPAL's
  // partition and must propagate to the SIGNER's before a vote against it can attach. Confirm with
  // `checkEnrollment` that the transaction actually resolves before calling this.
  const failed = droppedCodes(resp);
  if (failed.length) {
    throw new Error(
      `vote was NOT recorded after ${attempts} attempts: `
      + `${failed.map((r) => `${r.code} (${r.txID})`).join('; ')}. `
      + 'The signature is valid but had nothing to attach to.',
    );
  }

  return { txHash, signerUrl, vote };
}

// ── 3c. Signing in the BROWSER, via the Key Vault extension ───────────────────────────────────────

/**
 * Sign in the BROWSER, via the Certen Key Vault extension (Chrome, Edge, Firefox).
 *
 * This is the route that lets enrollment happen on one page. It matters because enrollment ends in a
 * biometric capture, which needs a camera — the user is already in a browser, and sending them to a
 * terminal mid-flow to sign is a drop-off point in the funnel.
 *
 * The alternative, equally valid and verified end to end on Kermit, is the terminal:
 *   `certen pending sign <hash|TxID|inbox-id>` then `certen pending submit`.
 * Use it for agents, for CI, for air-gapped signers, and for anyone without the extension.
 *
 * NOT a route: having the gateway hold the user's key and sign for them. Certen runs the gateway and
 * does not hold user keys, so a "just let the server sign it" shortcut is not available here by
 * design, however convenient it would look in a browser flow.
 *
 * ── Verification status, so nobody over-reads this ───────────────────────────────────────────────
 *
 * The SIGNATURE CONSTRUCTION is verified: building the vote through `SimpleExternalKey` produces
 * bytes identical to the locally-signed path, vote included, and the preimage handed to the
 * extension matches a hand-computed `SHA256(SHA256(encode(metadata)) || txHash)`.
 *
 * What is NOT yet verified is the round trip through a real installed extension — the postMessage
 * hop, the approval popup, and the shape the extension returns. That needs a browser with the Key
 * Vault installed. Treat the plumbing below as correct-by-construction but unexercised.
 *
 * The same vote as `signPending`, but signed by the user's extension instead of a local private key.
 *
 * Runs in the BROWSER — it needs `window.certen`, so bundle this module (or just this function) into
 * your enrollment page. Everything else in this file is server-side.
 *
 * ── Use `signHash`, not `signPendingTransaction` ─────────────────────────────────────────────────
 *
 * Both exist on `window.certen`. `signHash` is the one the Certen web app actually ships
 * (`certen-web-app/src/services/keyvault.service.ts`) and the one verified end to end against a real
 * installed extension: it returned a signature that verified over the preimage and drove the
 * transaction to `delivered` on Kermit.
 *
 *     provider.signHash({ hash, address, keyType: 'ed25519', humanReadable })
 *
 * where `hash` is the COMPLETE PREIMAGE, not the transaction hash:
 *
 *     hash = SHA256( SHA256(encode(signature metadata)) || txHash )
 *
 * with metadata {type, publicKey, signer, signerVersion, timestamp, vote}. Computed here via the
 * SDK's `SimpleExternalKey`, which derives it exactly as the local signing path does — verified
 * byte-identical, vote included.
 *
 * The extension is a SIGNING ORACLE, not a submitter: it returns `{ signature, publicKey }` and
 * stops. Assembling the envelope and submitting is yours, and is done below, so your page needs no
 * backend for it.
 *
 * ── "Vault is locked" usually means you skipped selectKey ────────────────────────────────────────
 *
 * The single most expensive thing to get wrong here. Call the signer without `selectKey` first and
 * the extension answers:
 *
 *     Vault is locked. Please unlock first.
 *
 * — no matter how unlocked the vault is. The message names the wrong cause. Verified against a live
 * installed extension: repeated `signHash` calls failed with exactly that error through half a dozen
 * unlocks, and the identical call succeeded immediately once `selectKey` preceded it.
 *
 * If you see it, check that you called `selectKey` BEFORE assuming anything about lock state.
 *
 * NEVER retry automatically. Each rejected call opens a popup, so a timer-driven retry buries the
 * user in windows within seconds. Offer a button; let the user choose to try again.
 *
 * The vault genuinely can be locked too, and `keyvault.service.ts` exports `isVaultLockedError` and
 * an `action: 'unlock'` hint for that case — it is recoverable, not a failed enrollment. It matters
 * for enrollment because biometric capture can sit between unlock and signature. But rule out the
 * missing first step before you believe the error.
 *
 * @param {string} txHash
 * @param {{provider: object, signerUrl: string, publicKeyHex: string,
 *          signerVersion?: number, vote?: 'accept'|'reject', humanReadable?: object}} opts
 */
export async function signPendingWithProvider(
  txHash, { provider, signerUrl, publicKeyHex, signerVersion, vote = 'accept', humanReadable },
) {
  // Feature-detect the METHOD, never the `isCerten` flag. Two different Certen extensions inject
  // `window.certen` and both set that flag; only the Key Vault implements this call. Checking the
  // flag fails later as "undefined is not a function", from inside a promise, with no useful stack.
  if (typeof provider?.signPendingTransaction !== 'function') {
    throw new Error('Certen Key Vault not available — install or update the extension');
  }

  const c = client();
  for (let i = 0; i < 5; i++) {
    if (!(await checkEnrollment(txHash)).unresolved) break;
    if (i === 4) throw new Error(`transaction ${txHash} does not resolve; refusing to sign`);
    await new Promise((r) => setTimeout(r, 6000));
  }

  const version = Number(
    signerVersion ?? unwrap(await c.queryAccount(signerUrl))?.version ?? 1,
  );
  const timestamp = Date.now() * 1000;
  const pub = Buffer.from(publicKeyHex.replace(/^0x/, ''), 'hex');

  // STEP 1 of 2 — KEY SELECTION. Do not skip this.
  //
  // The Key Vault is a TWO-STEP flow: `selectKey` opens the key picker, then the signing call opens
  // the approval screen. Calling the signer without it answers `Vault is locked. Please unlock
  // first.` — however unlocked the vault actually is. The message names the wrong cause, and it
  // costs hours if you believe it: you will chase unlock state while the real problem is a missing
  // first step. Every caller in certen-web-app does this (AuthorityEditor.tsx:1535,
  // CreateIdentityWizard.tsx:159, OnboardingFlow.tsx:244) before it signs anything.
  const selected = await provider.selectKey({
    keyType: 'ed25519',
    purpose: humanReadable?.description ?? `Prove control of ${signerUrl}`,
  });
  if (!selected?.publicKey) throw new Error('no key selected (user cancelled?)');

  // The preimage is computed FOR a specific public key. A signature from any other key verifies
  // against nothing and the vote is dropped in silence, so refuse the mismatch here.
  const chosen = String(selected.publicKey).replace(/^0x/, '').toLowerCase();
  if (chosen !== publicKeyHex.replace(/^0x/, '').toLowerCase()) {
    throw new Error(
      `selected key ${chosen.slice(0, 16)}… is not the key this signature was prepared for `
      + `(${publicKeyHex.slice(0, 16)}…). Ask the user to pick the key on ${signerUrl}.`,
    );
  }

  // STEP 2 of 2 — the signature. `signHash` takes the COMPLETE PREIMAGE as `hash`, and its
  // parameter names differ from every other method here: `address`, not `signer`.
  const key = new SimpleExternalKey(
    Address.fromKey(core.SignatureType.ED25519, pub),
    async (preimage) => {
      const r = await provider.signHash({
        hash: Buffer.from(preimage).toString('hex'),
        address: signerUrl,
        keyType: 'ed25519',
        humanReadable: humanReadable ?? {
          action: 'Sign Accumulate Transaction',
          memo: `Prove control of ${signerUrl} to complete enrollment`,
        },
      });
      if (!r?.signature) throw new Error('extension returned no signature (user rejected?)');
      return Buffer.from(String(r.signature).replace(/^0x/, ''), 'hex');
    },
  );

  const sig = await key.sign({ hash: () => Buffer.from(txHash, 'hex') }, {
    signer: signerUrl,
    signerVersion: version,
    timestamp,
    vote: vote === 'reject' ? core.VoteType.Reject : core.VoteType.Accept,
  });

  const resp = await c.v2.execute(
    new messaging.Envelope({ signatures: [sig], txHash: Buffer.from(txHash, 'hex') }),
  );
  const failed = droppedCodes(resp);
  if (failed.length) {
    throw new Error(
      `vote was NOT recorded: ${failed.map((r) => `${r.code} (${r.txID})`).join('; ')}`,
    );
  }

  return { txHash, signerUrl, vote };
}

// ── 4. THE FUNCTION YOU REPLACE ───────────────────────────────────────────────────────────────────

/**
 * Called exactly once, when the chain has confirmed the user controls the ADI.
 *
 * THIS IS THE ONLY FUNCTION YOU NEED TO CHANGE. Everything above is protocol mechanics; this is your
 * business logic. Capture the biometric template here, bind it to `adiUrl`, and store `txHash`
 * alongside it — that hash is your durable, third-party-verifiable evidence that enrollment was
 * authorised, and you will want it the first time someone disputes an approval.
 *
 * Bind to the ADI, not to the key book and not to a key. The book was how control was proven this
 * time; it is not the identity, and it may not be the book that proves control next time.
 */
export async function onEnrolled({ adiUrl, keyBookUrl, enrollmentId, txHash }) {
  console.log(`[enrollment] ENROLLED  adi=${adiUrl}  tx=${txHash}`);
  // ── replace me ────────────────────────────────────────────────────────────────────────────────
  //   await trustStamp.captureBiometric({ subject: adiUrl, evidence: txHash, enrollmentId });
  // ──────────────────────────────────────────────────────────────────────────────────────────────
  return { adiUrl, keyBookUrl, enrollmentId, txHash };
}

// ── 5. Orchestration ──────────────────────────────────────────────────────────────────────────────

/**
 * The whole flow, end to end. `presentSigningUrl` is how you get the URL in front of the user —
 * render it, email it, push it into an existing session, whatever your enrollment UI already does.
 */
export async function runEnrollment({ adiUrl, keyBookUrl, enrollmentId, presentSigningUrl }) {
  const started = await startEnrollment({ adiUrl, keyBookUrl, enrollmentId });

  await presentSigningUrl(started.signingUrl, started);

  const result = await awaitEnrollment(started.txHash);

  if (result.state === EnrollmentState.ENROLLED) {
    return {
      ...result,
      ...(await onEnrolled({ adiUrl, keyBookUrl, enrollmentId, txHash: started.txHash })),
    };
  }

  // DECLINED is an explicit refusal and LAPSED means it simply never happened. In both cases: store
  // no template, and do not retry silently. A user who comes back starts a NEW enrollment with a NEW
  // enrollmentId — reusing the old one would point at a transaction that is already terminal.
  return result;
}

// ── Demo ──────────────────────────────────────────────────────────────────────────────────────────

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`) {
  const [adiUrl, keyBookUrl] = process.argv.slice(2);
  if (!adiUrl || !keyBookUrl) {
    console.error('usage: node enrollment.mjs acc://alice.acme acc://alice.acme/book');
    process.exit(2);
  }

  runEnrollment({
    adiUrl,
    keyBookUrl,
    enrollmentId: `demo-${Date.now()}`,
    presentSigningUrl: async (url) => {
      console.log('\n  Open this and sign with the Certen Key Vault:\n');
      console.log(`    ${url}\n`);
      console.log('  Waiting for the chain...\n');
    },
  })
    .then((r) => {
      console.log(`\n  -> ${String(r.state).toUpperCase()}  (${r.txHash})\n`);
      process.exit(r.state === EnrollmentState.ENROLLED ? 0 : 1);
    })
    .catch((err) => {
      console.error(`\n  x ${err?.message ?? err}\n`);
      process.exit(1);
    });
}
