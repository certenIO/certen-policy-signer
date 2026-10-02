/**
 * GATEWAY backend — vote through the Certen api-gateway's external-signing seam.
 *
 *   POST /v1/sign                     -> { sign_request_id, signing_data{ data_for_signature, ... }, submit_url }
 *   POST /v1/sign/:id/signature       -> { status, tx_hash, signature_count, is_ready, awaiting_authorities }
 *
 * The org's key never leaves us. The gateway computes what must be signed; WE decide whether to sign it,
 * and we alone can produce the signature. The policy gate is unchanged and still ours.
 *
 * Three properties of the gateway's contract shape this client, and each one bites if ignored:
 *
 * 1. THE VOTE IS FIXED WHEN THE SIGNING DATA IS ISSUED. Accumulate folds the vote into the signature
 *    metadata hash, so approve and reject are different preimages. We therefore pass the vote to
 *    /v1/sign — we cannot decide it later.
 *
 * 2. A SIGN REQUEST IS SINGLE-USE. The gateway claims the row atomically on submit; a replay, an expiry,
 *    or a failed submission consumes it (its status becomes `failed`). So a retry must start over at
 *    /v1/sign for FRESH signing data — resubmitting the same signature to the same id just 404s.
 *
 * 4. WE NEVER SIGN THE GATEWAY'S BYTES ON TRUST (G-47). The gateway's `data_for_signature` is a claim. We
 *    rebuild the preimage ourselves -- buildPreimage, the same code the direct backend signs with -- from
 *    the transaction WE resolved (its hash), OUR key and its type, OUR page, the vote WE decided, and the
 *    signer version and timestamp the gateway will submit with (both sanity-checked), and sign only that.
 *    An absent, empty or different transaction hash, signer page or preimage is a refusal: a gateway that
 *    hands back bytes for another transaction, another page or another vote gets nothing out of us.
 *
 * 3. WE MUST DECLARE OUR PUBLIC KEY. The preimage is computed for a specific key. If the org's signer is
 *    not the identity's default bound key, and we do not send `public_key`, the gateway hands us bytes
 *    for the *wrong* key and Accumulate rejects the resulting signature. We always send it.
 *
 * Note what this backend does NOT do: discovery, and intent decoding. The gateway's pending list carries
 * no transaction body — no amounts, no legs — so the policy engine could not gate on it. And its poller
 * is anchored on accounts the org owns, so it does not reliably surface transactions where the org is only
 * a per-tx `Header.Authorities` entry. We keep our own discovery and decode from the chain, and use the
 * gateway's `type: 'pending_tx'` path (which exists for exactly this) to sign by hash.
 */
import axios, { AxiosInstance } from 'axios';
import { createHash } from 'node:crypto';
import { Keyring } from '../../signer/keyring.js';
import { Logger } from '../../logger.js';
import { Vote } from '../../types.js';
import { buildPreimage, bytesToHex, hexToBytes } from '../../accumulate/signing.js';
import { CastOptions, VoteBackend, VotableTx, VoteResult } from '../backend.js';

export interface GatewayOptions {
  url: string;             // https://gateway.internal:8090
  apiKey: string;          // ck_live_...
  identity: string;        // the org's ADI url — required for type: 'pending_tx'
  signerUrl?: string;      // defaults, gateway-side, to the identity's key page
  timeoutMs?: number;
  maxRetries?: number;     // fresh signing data + re-sign, on a stale-version rejection
}

export interface SigningData {
  signRequestId: string;
  dataForSignature: string;   // hex digest — sign these bytes RAW
  transactionHash: string;
  signerUrl: string;
  signerVersion: number;
  timestamp: number;
  submitUrl: string;
}

export class GatewayClient {
  private readonly http: AxiosInstance;

  constructor(private readonly o: GatewayOptions, private readonly logger: Logger) {
    this.http = axios.create({
      baseURL: o.url.replace(/\/$/, ''),
      timeout: o.timeoutMs ?? 20_000,
      headers: { 'content-type': 'application/json', 'x-api-key': o.apiKey },
      validateStatus: () => true,
    });
  }

  /**
   * Transactions the gateway knows are awaiting us. Its own discovery misses header-authority txs.
   * Never throws: a gateway outage must not stop us discovering work on chain, which is the path that
   * actually finds our transactions. (`validateStatus` covers HTTP replies; a refused connection still
   * rejects, so the network error is caught here too.)
   */
  async listPending(): Promise<string[]> {
    let res;
    try {
      res = await this.http.get('/v1/pending', { params: { identity: this.o.identity, limit: 500 } });
    } catch (e) {
      this.logger.warn({ err: (e as Error).message }, 'gateway: GET /v1/pending unreachable');
      return [];
    }
    if (res.status !== 200) {
      this.logger.warn({ status: res.status, err: res.data?.error ?? res.data }, 'gateway: GET /v1/pending failed');
      return [];
    }
    return (res.data?.actions ?? [])
      .map((a: { tx_hash?: string }) => String(a?.tx_hash ?? '').replace(/^acc:\/\//, '').split('@')[0].toLowerCase())
      .filter((h: string) => /^[0-9a-f]{64}$/.test(h));
  }

  /** Ask for the bytes to sign for THIS vote. The vote is baked into them; it cannot change later. */
  async requestSigningData(txHash: string, vote: Vote, publicKey: Uint8Array): Promise<SigningData> {
    const res = await this.http.post('/v1/sign', {
      type: 'pending_tx',              // by hash: does not depend on the gateway's poller having seen it
      target_id: txHash,
      identity: this.o.identity,
      ...(this.o.signerUrl ? { signer_url: this.o.signerUrl } : {}),
      vote,
      public_key: bytesToHex(publicKey),   // or the gateway computes the preimage for the wrong key
    });
    if (res.status !== 201) {
      throw new Error(`gateway POST /v1/sign -> ${res.status}: ${JSON.stringify(res.data?.error ?? res.data).slice(0, 200)}`);
    }
    const d = res.data?.signing_data ?? {};
    const dataForSignature = String(d.data_for_signature ?? '');
    if (!/^[0-9a-f]{64}$/i.test(dataForSignature)) {
      throw new Error('gateway returned no usable data_for_signature');
    }
    return {
      signRequestId: String(res.data.sign_request_id),
      dataForSignature,
      // Absent stays EMPTY (and is refused by the backend): defaulting to the hash we asked for would let a
      // gateway skip the one statement that binds its bytes to our transaction.
      transactionHash: String(d.transaction_hash ?? ''),
      signerUrl: String(d.signer_url ?? ''),
      signerVersion: Number(d.signer_version ?? 0),
      timestamp: Number(d.timestamp ?? 0),
      submitUrl: String(res.data.submit_url ?? `/v1/sign/${res.data.sign_request_id}/signature`),
    };
  }

  /** Hand back the signature. The sign request is consumed by this call, pass or fail. */
  async submitSignature(sd: SigningData, signature: Uint8Array, publicKey: Uint8Array): Promise<{ ok: boolean; status?: string; signatureCount?: number; error?: string }> {
    const res = await this.http.post(sd.submitUrl, {
      signature: bytesToHex(signature),
      public_key: bytesToHex(publicKey),
    });
    if (res.status === 200) {
      return { ok: true, status: String(res.data?.status ?? ''), signatureCount: Number(res.data?.signature_count ?? 0) };
    }
    return {
      ok: false,
      error: `gateway POST ${sd.submitUrl} -> ${res.status}: ${JSON.stringify(res.data?.error ?? res.data).slice(0, 200)}`,
    };
  }
}

export class GatewayVoteBackend implements VoteBackend {
  constructor(
    private readonly gw: GatewayClient,
    private readonly keyring: Keyring,
    private readonly logger: Logger,
    private readonly maxRetries = 3,
  ) {}

  async cast(tx: VotableTx, vote: Vote, castOpts: CastOptions = {}): Promise<VoteResult> {
    // The key on THIS tx's page — and, when the decision named an approver, THAT approver's key (T29),
    // exactly as DirectVoteBackend resolves it. Runbook F24: this used to ignore `keyRef` and always
    // sign with the page's own key, so a named approver's vote was cast by the organisation's key and
    // recorded as theirs.
    //
    // Fail closed, no fallback: `forPage` throws for a page we hold no key for and for a ref that page
    // has no key under. Nothing is requested from the gateway in either case — the preimage is computed
    // for the public key we declare, so the key must be settled before the first call.
    const signer = this.keyring.forPage(tx.signerUrl, castOpts.keyRef);
    if (castOpts.keyRef) {
      this.logger.info({ tx: tx.txHash, page: tx.signerUrl, keyRef: castOpts.keyRef, via: 'gateway' },
        'signing as the named approver rather than as the organisation');
    }
    const publicKey = await signer.publicKey();

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let sd: SigningData;
      try {
        sd = await this.gw.requestSigningData(tx.txHash, vote, publicKey);
      } catch (e) {
        return { ok: false, error: (e as Error).message };
      }

      // G-47: the gateway's signing data is a claim, checked against what WE decided, and then not used:
      // we sign the preimage we build ourselves. Every refusal below happens before anything is signed.
      const got = sd.transactionHash.replace(/^0x/, '').toLowerCase();
      if (got !== tx.txHash.toLowerCase()) {
        this.logger.error({ tx: tx.txHash, gatewayTx: got || '(none)' }, 'gateway signing data names a DIFFERENT (or no) transaction — refusing to sign');
        return { ok: false, error: 'gateway signing data transaction mismatch' };
      }
      const page = (u: string) => u.toLowerCase().replace(/\/+$/, '');
      if (!sd.signerUrl || page(sd.signerUrl) !== page(tx.signerUrl)) {
        this.logger.error({ tx: tx.txHash, page: tx.signerUrl, gatewayPage: sd.signerUrl || '(none)' }, 'gateway signing data is for a DIFFERENT (or no) signer page — refusing to sign');
        return { ok: false, error: 'gateway signing data signer mismatch' };
      }
      if (!Number.isSafeInteger(sd.signerVersion) || sd.signerVersion < 1 || !Number.isSafeInteger(sd.timestamp) || sd.timestamp <= 0) {
        this.logger.error({ tx: tx.txHash, signerVersion: sd.signerVersion, timestamp: sd.timestamp }, 'gateway signing data has an unusable signer version or timestamp — refusing to sign');
        return { ok: false, error: 'gateway signing data metadata invalid' };
      }
      const pre = buildPreimage(hexToBytes(tx.txHash), {
        publicKey, signatureType: signer.signatureType, signerUrl: tx.signerUrl,
        signerVersion: sd.signerVersion, timestamp: sd.timestamp, vote,
      });
      const ours = bytesToHex(pre.dataForSignature);
      if (ours !== sd.dataForSignature.toLowerCase()) {
        this.logger.error({ tx: tx.txHash, ours, gateway: sd.dataForSignature }, 'gateway preimage differs from the one we built for this transaction, key, page and vote — refusing to sign');
        return { ok: false, error: 'gateway signing data preimage mismatch' };
      }

      // Same rule as the direct backend: a key source that cannot sign produces no signature, and the vote
      // is withheld. The spent sign request is simply abandoned.
      let signature: Uint8Array;
      try {
        signature = await signer.sign(pre.dataForSignature, { txHash: tx.txHash, principal: tx.account, page: tx.signerUrl });
      } catch (e) {
        const msg = (e as Error).message;
        this.logger.error({ tx: tx.txHash, page: tx.signerUrl, err: msg, via: 'gateway' }, 'signing failed; vote withheld');
        return { ok: false, error: `signing failed: ${msg}` };
      }
      let res: { ok: boolean; status?: string; error?: string };
      try {
        res = await this.gw.submitSignature(sd, signature, publicKey);
      } catch (e) {
        // No answer from the gateway (timeout, dropped connection): the outcome is UNKNOWN, not a refusal.
        // The sign request is spent either way; this vote is reported failed-to-confirm and retried next poll.
        const msg = (e as Error).message;
        this.logger.warn({ tx: tx.txHash, err: msg, via: 'gateway' }, 'gateway submit got no answer: vote outcome UNKNOWN; will retry');
        return { ok: false, error: `gateway submit outcome unknown (${msg})` };
      }
      if (res.ok) {
        this.logger.info(
          { tx: tx.txHash, vote, via: 'gateway', signRequest: sd.signRequestId, signerVersion: sd.signerVersion, status: res.status },
          'vote submitted',
        );
        const scope = this.keyring.scopeFor(tx.signerUrl);
        return {
          ok: true, signatureHash: ours, timestamp: sd.timestamp,
          // What satisfied the vote (F4 / A5): the page the gateway computed the preimage for, and the
          // key that actually signed — the named approver's when a keyRef was given.
          signedBy: {
            page: tx.signerUrl,
            signatureType: signer.signatureType,
            publicKeyHash: createHash('sha256').update(publicKey).digest('hex'),
            delegators: [],
            ...(scope.actsFor ? { onBehalfOf: scope.actsFor } : {}),
          },
        };
      }

      // The sign request is now spent. If the key page moved under us, the ONLY recovery is fresh signing
      // data — resubmitting to the same id would 404.
      if (attempt < this.maxRetries) {
        this.logger.warn({ tx: tx.txHash, attempt: attempt + 1, err: res.error }, 'gateway submit failed; re-requesting signing data');
        continue;
      }
      return { ok: false, error: res.error };
    }
    return { ok: false, error: 'exhausted gateway signing retries' };
  }
}
