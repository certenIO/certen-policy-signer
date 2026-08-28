/**
 * Core Accumulate signing — the exact preimage construction, matching
 * api-bridge (getPendingTransactionSigningData / submitVoteOnPendingTransaction)
 * and the vendored SDK's ed25519 signRaw.
 *
 *   sigMdHash        = SHA256( encode(Signature{ meta... }) )
 *   dataForSignature = SHA256( sigMdHash || txHash )        // 32 bytes  <- signed
 *
 * The second line is the same for EVERY signature type — protocol/signature_utils.go `signingHash` takes
 * one path for Ed25519, ECDSA-SHA256 and RSA-SHA256 alike. So supporting a bank's existing PKI key is not
 * a second signing scheme; it is the same preimage with a different type enum in the metadata, and a
 * different signature encoding coming back out of the key. test/signature-algorithms.test.ts pins that
 * against vectors the Go protocol generated.
 *
 * Zero-valued vote (approve = Accept = 0) is omitted by Accumulate's binary
 * marshaling, so setting vote:0 and omitting it are byte-identical.
 */
import { DelegatedSignature, SIGNATURE_CLASS, sha256, encode, AccURL } from './sdk.js';
import { Vote, VOTE_CODE } from '../types.js';
import { AccumulateSignatureType } from '../signer/signer.js';

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
  /** The key as its signature type carries it: raw for Ed25519, PKIX/SPKI DER for ECDSA, PKCS#1 for RSA. */
  publicKey: Uint8Array;
  /**
   * Defaults to ed25519 when absent. The default exists because the governance paths in src/ops/ are
   * Ed25519 by construction — they sign with the org's own key — and making them all say so would be
   * noise. The VOTE path never relies on it: it passes the key's own declared type. When a non-Ed25519
   * key governs (F2/F3), those call sites must pass `signer.signatureType` too, or the network will
   * reject a signature whose metadata claims the wrong algorithm.
   */
  signatureType?: AccumulateSignatureType;
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
    type: AccumulateSignatureType;
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
  const type = p.signatureType ?? 'ed25519';
  const Signature = SIGNATURE_CLASS[type];
  if (!Signature) throw new Error(`no signature class for type ${type}`);
  const fields: Record<string, unknown> = {
    type,
    publicKey: p.publicKey,
    signer: AccURL.parse(p.signerUrl),
    signerVersion: p.signerVersion,
    timestamp: p.timestamp,
    vote: voteCode, // 0 (Accept) is omitted by marshaling; mirrors api-bridge
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let sig: any = new Signature(fields);
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
      type: p.signatureType ?? 'ed25519',
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
  type: AccumulateSignatureType;
  signature: string;        // hex: 64 bytes for Ed25519, ASN.1 DER for ECDSA, PKCS#1 v1.5 for RSA
  publicKey: string;        // hex: 32 bytes for Ed25519, PKIX DER for ECDSA, PKCS#1 DER for RSA
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
    type: pre.metadata.type,
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
 * Delegate model: build the wire-form (asObject) DelegatedSignature wrapping the signed key signature.
 * Used when the org is attached as a delegate on the user's page.
 *
 * The wrapper preserves the inner signer's page URL, algorithm and public key — which is what lets a
 * record distinguish an employee signing with her certificate from the institution signing inside her
 * book, so keep the inner type from the preimage rather than assuming one.
 */
export function buildDelegatedSignatureObject(
  pre: Preimage,
  signatureBytes: Uint8Array,
  txHashHex: string,
): unknown {
  const Signature = SIGNATURE_CLASS[pre.metadata.type];
  if (!Signature) throw new Error(`no signature class for type ${pre.metadata.type}`);
  const inner = new Signature({
    type: pre.metadata.type,
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
