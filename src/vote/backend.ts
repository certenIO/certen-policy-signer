/**
 * How a decided vote actually reaches the chain.
 *
 * Two backends, same orchestrator above them:
 *
 *   DIRECT   — we build the Accumulate signature preimage ourselves and submit the envelope to a v3 node.
 *              Self-contained; nothing else needs to exist. This is the proven pilot path.
 *
 *   GATEWAY  — we ask the Certen api-gateway for the signing data, sign it, and hand the signature back
 *              (`POST /v1/sign` -> `POST /v1/sign/:id/signature`). The org's key still never leaves us:
 *              the gateway hands us bytes to sign, and we decide whether to sign them.
 *
 * The vote is fixed when the signing data is requested — Accumulate folds the vote into the signature
 * metadata hash — so an approve and a reject are different preimages, not the same one with a flag.
 */
import { AccumulateClient } from '../accumulate/client.js';
import { Keyring } from '../signer/keyring.js';
import { Logger } from '../logger.js';
import { Vote } from '../types.js';
import {
  buildPreimage, buildSignatureObject, buildDelegatedSignatureObject, buildSubmitEnvelope,
  bytesToHex, computeTimestamp, hexToBytes,
} from '../accumulate/signing.js';

/** The subset of a resolved tx a backend needs to cast a vote on it. */
export interface VotableTx {
  txHash: string;
  signerUrl: string;
  signerVersion: number;
  rawTransaction: unknown;
  lastUsedOn: number;
  account: string;
}

export interface VoteResult {
  ok: boolean;
  error?: string;
  signatureHash?: string;
  timestamp?: number;
}

export interface VoteBackend {
  /** Sign and cast `vote` on `tx`. Must be safe to call again if it fails. */
  cast(tx: VotableTx, vote: Vote): Promise<VoteResult>;
}

export interface DirectVoteOptions {
  maxBadVersionRetries?: number;
  delegators?: string[];
  now?: () => number;
}

/**
 * DIRECT: build the preimage, sign, submit the envelope to Accumulate.
 * Retries when the key page's version moves under us — that is a benign race, not a failure.
 */
export class DirectVoteBackend implements VoteBackend {
  private readonly now: () => number;
  constructor(
    private readonly accumulate: AccumulateClient,
    private readonly keyring: Keyring,
    private readonly logger: Logger,
    private readonly opts: DirectVoteOptions = {},
  ) {
    this.now = opts.now ?? Date.now;
  }

  async cast(tx: VotableTx, vote: Vote): Promise<VoteResult> {
    const maxRetries = this.opts.maxBadVersionRetries ?? 3;
    let signerVersion = tx.signerVersion;
    let lastUsedOn = tx.lastUsedOn;
    // Pick the key that sits on THIS tx's page. Throws (fail-closed) if we hold no key for it.
    const signer = this.keyring.forPage(tx.signerUrl);

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const publicKey = await signer.publicKey();
      const timestamp = computeTimestamp(lastUsedOn, this.now() * 1000);
      const delegators = this.opts.delegators;
      const pre = buildPreimage(hexToBytes(tx.txHash), { publicKey, signerUrl: tx.signerUrl, signerVersion, timestamp, vote, delegators });
      const sigBytes = await signer.sign(pre.dataForSignature);
      const sigObj = delegators?.length
        ? buildDelegatedSignatureObject(pre, sigBytes, tx.txHash)
        : buildSignatureObject(pre, sigBytes, tx.txHash);

      const res = await this.accumulate.submit(buildSubmitEnvelope(tx.rawTransaction, sigObj));
      if (res.ok || res.code === 'alreadySigned') {
        this.logger.info({ tx: tx.txHash, vote, signerVersion, timestamp, via: 'direct' }, 'vote submitted');
        return { ok: true, signatureHash: bytesToHex(pre.sigMdHash), timestamp };
      }
      if (res.code === 'badSignerVersion' && attempt < maxRetries) {
        const info = await this.accumulate.getSignerInfo(tx.signerUrl);
        this.logger.warn({ tx: tx.txHash, old: signerVersion, next: info.version }, 'badSignerVersion; re-resolving');
        signerVersion = info.version;
        lastUsedOn = info.lastUsedOn;
        continue;
      }
      this.logger.error({ tx: tx.txHash, code: res.code, err: res.error }, 'submit failed');
      return { ok: false, error: res.error ?? res.code ?? 'submit_failed' };
    }
    return { ok: false, error: 'exhausted badSignerVersion retries' };
  }
}
