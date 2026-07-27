/**
 * Core Accumulate signing — the exact preimage construction, matching
 * api-bridge (getPendingTransactionSigningData / submitVoteOnPendingTransaction)
 * and the vendored SDK's ed25519 signRaw.
 *
 *   sigMdHash        = SHA256( encode(ED25519Signature{ meta... }) )
 *   dataForSignature = SHA256( sigMdHash || txHash )        // 32 bytes  <- signed
 *
 * Zero-valued vote (approve = Accept = 0) is omitted by Accumulate's binary
 * marshaling, so setting vote:0 and omitting it are byte-identical.
 */
import { ED25519Signature, DelegatedSignature, sha256, encode, AccURL } from './sdk.js';
import { Vote, VOTE_CODE } from '../types.js';

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(clean, 'hex'));
}
export function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
/** SHA-256 of a UTF-8 string as hex (used for audit refs, e.g. assertion hash). */
export function sha256Hex(s: string): string {
  return bytesToHex(sha256(new Uint8Array(Buffer.from(s, 'utf8'))));
}
export function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

/**
 * Accumulate anti-replay timestamp (microseconds): strictly greater than the
 * key's lastUsedOn and ahead of wall-clock. Matches AccumulateService.getNextTimestamp.
 */
export function computeTimestamp(lastUsedOnMicros: number, nowMicros: number): number {
  return Math.max(lastUsedOnMicros + 2_000_000, nowMicros + 1_000_000);
}

export interface PreimageParams {
  publicKey: Uint8Array;   // 32 bytes
  signerUrl: string;
  signerVersion: number;
  timestamp: number;       // micros
  vote: Vote;
  /** Delegate model: outer->inner delegator page URLs wrapping the key signature. */
  delegators?: string[];
}

export interface Preimage {
  dataForSignature: Uint8Array;  // 32 bytes — the thing to Ed25519-sign
  sigMdHash: Uint8Array;         // 32 bytes
  metadata: {
    type: 'ed25519';
    publicKey: Uint8Array;
    signer: string;
    signerVersion: number;
    timestamp: number;
    voteCode: number;
    delegators?: string[];
  };
}

/** Build the (possibly delegator-wrapped) signature-metadata object the network re-encodes. */
function buildSigMetaObject(p: PreimageParams) {
  const voteCode = VOTE_CODE[p.vote];
  const fields: Record<string, unknown> = {
    type: 'ed25519',
    publicKey: p.publicKey,
    signer: AccURL.parse(p.signerUrl),
    signerVersion: p.signerVersion,
    timestamp: p.timestamp,
    vote: voteCode, // 0 (Accept) is omitted by marshaling; mirrors api-bridge
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let sig: any = new ED25519Signature(fields);
  for (const del of p.delegators ?? []) sig = new DelegatedSignature({ signature: sig, delegator: AccURL.parse(del) });
  return sig;
}

/**
 * SHA256(encode(signature metadata)) — the `sigMdHash`.
 *
 * For a VOTE this is an internal step (the transaction already exists, initiated by someone else).
 * For a transaction WE originate (e.g. key rotation) this same hash is the transaction header's
 * `initiator` field: Accumulate rejects an un-initiated transaction with "missing initiator". Note the
 * ordering that implies — the initiator must be known BEFORE the transaction is hashed, so:
 *   sigMdHash -> header.initiator -> tx.hash() -> dataForSignature = SHA256(sigMdHash || txHash)
 */
export function buildSigMetaHash(p: PreimageParams): Uint8Array {
  return sha256(encode(buildSigMetaObject(p)));
}

export function buildPreimage(txHash: Uint8Array, p: PreimageParams): Preimage {
  const sigMd = buildSigMetaObject(p);
  const sigMdHash = sha256(encode(sigMd));
  const dataForSignature = sha256(concatBytes(sigMdHash, txHash));
  return {
    dataForSignature,
    sigMdHash,
    metadata: {
      type: 'ed25519',
      publicKey: p.publicKey,
      signer: p.signerUrl,
      signerVersion: p.signerVersion,
      timestamp: p.timestamp,
      voteCode: VOTE_CODE[p.vote],
      delegators: p.delegators,
    },
  };
}

/** VoteType wire form is the lowercase string enum (SDK VoteType.getName / core String()); 0=Accept is omitted. */
const VOTE_NAME: Record<number, string> = { 1: 'reject', 2: 'abstain', 3: 'suggest' };

/** The signature object submitted in the envelope's `signatures[]`. */
export interface SignatureObject {
  type: 'ed25519';
  signature: string;        // 128 hex
  publicKey: string;        // 64 hex
  signer: string;
  signerVersion: number;
  timestamp: number;
  transactionHash: string;  // 64 hex
  vote?: string;            // lowercase enum ('reject'|'abstain'|'suggest'); omitted when Accept(0)
}

export function buildSignatureObject(
  pre: Preimage,
  signatureBytes: Uint8Array,
  txHashHex: string,
): SignatureObject {
  const obj: SignatureObject = {
    type: 'ed25519',
    signature: bytesToHex(signatureBytes),
    publicKey: bytesToHex(pre.metadata.publicKey),
    signer: pre.metadata.signer,
    signerVersion: pre.metadata.signerVersion,
    timestamp: pre.metadata.timestamp,
    transactionHash: txHashHex.startsWith('0x') ? txHashHex.slice(2) : txHashHex,
  };
  if (pre.metadata.voteCode !== 0) obj.vote = VOTE_NAME[pre.metadata.voteCode] ?? String(pre.metadata.voteCode);
  return obj;
}

/**
 * Delegate model: build the wire-form (asObject) DelegatedSignature wrapping the
 * signed ED25519Signature. Used when the org is attached as a delegate on the user's page.
 */
export function buildDelegatedSignatureObject(
  pre: Preimage,
  signatureBytes: Uint8Array,
  txHashHex: string,
): unknown {
  const inner = new ED25519Signature({
    type: 'ed25519',
    publicKey: pre.metadata.publicKey,
    signer: AccURL.parse(pre.metadata.signer),
    signerVersion: pre.metadata.signerVersion,
    timestamp: pre.metadata.timestamp,
    ...(pre.metadata.voteCode !== 0 ? { vote: pre.metadata.voteCode } : {}),
    signature: signatureBytes,
    transactionHash: hexToBytes(txHashHex),
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let sig: any = inner;
  for (const del of pre.metadata.delegators ?? []) sig = new DelegatedSignature({ signature: sig, delegator: AccURL.parse(del) });
  return sig.asObject();
}

/** The envelope submitted to Accumulate v3 `submit`. */
export function buildSubmitEnvelope(rawTransaction: unknown, sig: SignatureObject | unknown) {
  return { transaction: [rawTransaction], signatures: [sig] };
}
