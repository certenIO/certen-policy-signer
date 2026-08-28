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
import { AccumulateSignatureType } from '../signer/signer.js';
import { createHash } from 'node:crypto';
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

/**
 * What actually satisfied a vote. Runbook F Phase F4.
 *
 * Three facts and no verdict. The question this exists to answer is whether a PERSON approved
 * something or whether the organisation approved it in their name, and every honest answer rests on
 * all three -- any one alone is a guess. The algorithm is the tempting one and it is a heuristic: an
 * organisation may hold an ECDSA key, which F2 made configurable, so "ecdsaSha256 means somebody's
 * certificate" will be wrong in a deployment nobody has built yet.
 *
 * A classification computed here would be this process's opinion, frozen at the moment of signing and
 * impossible to check against the chain afterwards. The facts can be checked; the opinion could not.
 */
export interface VoteAttribution {
  /** The key page the signature was made on. For a delegated vote, the INNER one -- whose key it was. */
  page: string;
  signatureType: AccumulateSignatureType;
  /** sha256 of the public key: what a key page entry IS, and therefore comparable to one. */
  publicKeyHash: string;
  /** The seats this satisfied, outermost last. Empty for an ordinary vote on our own page. */
  delegators: string[];
  /**
   * Whose behalf this key is held on, when the deployment declared that it is somebody's.
   *
   * Present means THE ORGANISATION SIGNED IN A PERSON'S NAME: the key is ours, on a page inside their
   * identity, and nothing about their consent or presence is established by it. Absent is the ordinary
   * case -- the organisation signing as itself -- and stays silent, because an alarm that fires on
   * every transaction is worth nothing within a week.
   *
   * Declared rather than inferred: nothing on a key page distinguishes a person's certificate from a
   * software key, so this is the deployment's statement about its own key. See config.ts `acts_for`.
   */
  onBehalfOf?: string;
}

export interface VoteResult {
  ok: boolean;
  error?: string;
  signatureHash?: string;
  timestamp?: number;
  /**
   * Present only when the vote was ACCEPTED. A record naming the key that "signed" a transaction
   * carrying no signature is worse than one that says nothing.
   */
  signedBy?: VoteAttribution;
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
    const scope = this.keyring.scopeFor(tx.signerUrl);
    const signer = this.keyring.forPage(tx.signerUrl);

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const publicKey = await signer.publicKey();
      const timestamp = computeTimestamp(lastUsedOn, this.now() * 1000);
      const delegators = this.opts.delegators;
      // The key declares its own algorithm; the metadata must say the same thing, because the type is
      // inside the hash that gets signed. Never assume Ed25519 here — a PKI key on the page is normal.
      const pre = buildPreimage(hexToBytes(tx.txHash), { publicKey, signatureType: signer.signatureType, signerUrl: tx.signerUrl, signerVersion, timestamp, vote, delegators });
      const sigBytes = await signer.sign(pre.dataForSignature);
      const sigObj = delegators?.length
        ? buildDelegatedSignatureObject(pre, sigBytes, tx.txHash)
        : buildSignatureObject(pre, sigBytes, tx.txHash);

      const res = await this.accumulate.submit(buildSubmitEnvelope(tx.rawTransaction, sigObj));
      if (res.ok || res.code === 'alreadySigned') {
        this.logger.info({ tx: tx.txHash, vote, signerVersion, timestamp, via: 'direct' }, 'vote submitted');
        return {
          ok: true,
          signatureHash: bytesToHex(pre.sigMdHash),
          timestamp,
          // The page we signed ON, which for a delegated vote is the inner one -- whose key it was --
          // with the seats it satisfied kept beside it rather than replacing it. Flattening to the
          // outer page would record every seated approval as the role having approved itself.
          signedBy: {
            page: tx.signerUrl,
            signatureType: signer.signatureType,
            publicKeyHash: createHash('sha256').update(publicKey).digest('hex'),
            delegators: [...(delegators ?? [])],
            ...(scope.actsFor ? { onBehalfOf: scope.actsFor } : {}),
          },
        };
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
