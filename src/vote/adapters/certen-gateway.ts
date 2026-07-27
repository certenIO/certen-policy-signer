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
import { Keyring } from '../../signer/keyring.js';
import { Logger } from '../../logger.js';
import { Vote } from '../../types.js';
import { bytesToHex, hexToBytes } from '../../accumulate/signing.js';
import { VoteBackend, VotableTx, VoteResult } from '../backend.js';

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
      transactionHash: String(d.transaction_hash ?? txHash),
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

  async cast(tx: VotableTx, vote: Vote): Promise<VoteResult> {
    const signer = this.keyring.forPage(tx.signerUrl); // the key on THIS tx's page (fail-closed if unknown)
    const publicKey = await signer.publicKey();

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let sd: SigningData;
      try {
        sd = await this.gw.requestSigningData(tx.txHash, vote, publicKey);
      } catch (e) {
        return { ok: false, error: (e as Error).message };
      }

      // The gateway asked for a signature over a hash that is not the transaction we decided on.
      // Refuse: we sign for what the policy engine approved, not for whatever we are handed.
      const got = sd.transactionHash.replace(/^0x/, '').toLowerCase();
      if (got && got !== tx.txHash.toLowerCase()) {
        this.logger.error({ tx: tx.txHash, gatewayTx: got }, 'gateway signing data is for a DIFFERENT transaction — refusing to sign');
        return { ok: false, error: 'gateway signing data transaction mismatch' };
      }

      const signature = await signer.sign(hexToBytes(sd.dataForSignature));
      const res = await this.gw.submitSignature(sd, signature, publicKey);
      if (res.ok) {
        this.logger.info(
          { tx: tx.txHash, vote, via: 'gateway', signRequest: sd.signRequestId, signerVersion: sd.signerVersion, status: res.status },
          'vote submitted',
        );
        return { ok: true, signatureHash: sd.dataForSignature, timestamp: sd.timestamp };
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
