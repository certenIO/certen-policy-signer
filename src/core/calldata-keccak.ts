/**
 * Keccak-256 and what the calldata module needs it for (DAX-7A, DESIGN.md sections 1 and 4 D12, D13).
 *
 * node:crypto offers SHA3-256 (padding byte 0x06) but not Keccak-256 (padding byte 0x01, the hash Ethereum uses), so the
 * hash is written here as a pure function over 64-bit lanes held in BigInt. It serves three purposes:
 *   - the execution commitment of a single call, recomputed from the raw calldata: CertenAccountV7.computeSingleCommitment is
 *     keccak256(abi.encodePacked(block.chainid, target, value, keccak256(data))) (standard fact F4);
 *   - the calldata hash a RAW approval must show;
 *   - the EIP-55 checksum, so that a displayed address in checksum case is accepted only when the checksum is right.
 * Every function answers null instead of throwing for an argument that has no answer.
 */
import { ADDRESS_RE, concat, fromHex, isAmount, toHex, utf8 } from './bytes.js';

const MASK = (1n << 64n) - 1n;
const RATE = 136;

/** the 24 round constants of Keccak-f[1600] */
const RC: readonly bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** rotation offsets, lane index x + 5y */
const ROT: readonly number[] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

const rotl = (x: bigint, n: number): bigint => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK);

function keccakF(s: bigint[]): void {
  const c: bigint[] = [0n, 0n, 0n, 0n, 0n];
  const b: bigint[] = new Array<bigint>(25).fill(0n);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) c[x] = s[x]! ^ s[x + 5]! ^ s[x + 10]! ^ s[x + 15]! ^ s[x + 20]!;
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5]! ^ rotl(c[(x + 1) % 5]!, 1);
      for (let y = 0; y < 25; y += 5) s[y + x] = s[y + x]! ^ d;
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y]!, ROT[x + 5 * y]!);
    for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) s[y + x] = b[y + x]! ^ (~b[y + ((x + 1) % 5)]! & MASK & b[y + ((x + 2) % 5)]!);
    s[0] = s[0]! ^ RC[round]!;
  }
}

/** Keccak-256 of the bytes (the original Keccak padding, not the NIST SHA3 one). */
export function keccak256(data: Uint8Array): Uint8Array {
  const padded = new Uint8Array(Math.floor(data.length / RATE) * RATE + RATE);
  padded.set(data);
  padded[data.length] = padded[data.length]! ^ 0x01;
  padded[padded.length - 1] = padded[padded.length - 1]! ^ 0x80;
  const s: bigint[] = new Array<bigint>(25).fill(0n);
  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      let lane = 0n;
      for (let k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + k]!);
      s[i] = s[i]! ^ lane;
    }
    keccakF(s);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = s[i]!;
    for (let k = 0; k < 8; k++) {
      out[i * 8 + k] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

/** `0x` plus the 64 lowercase hex digits of keccak256(data). */
export const keccak256Hex = (data: Uint8Array): string => '0x' + toHex(keccak256(data));

/** EIP-55 checksum form of a lowercase `0x` + 40 hex address; null for anything that is not exactly that. */
export function toChecksumAddress(address: unknown): string | null {
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) return null;
  const digits = address.slice(2);
  const h = toHex(keccak256(utf8(digits)));
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i]!, 16) >= 8 ? digits[i]!.toUpperCase() : digits[i]!;
  return out;
}

const word = (n: bigint): Uint8Array => fromHex(n.toString(16).padStart(64, '0'));

/**
 * The commitment of ONE call: keccak256( chainid as 32 bytes || target as 20 bytes || value as 32 bytes || keccak256(data) ),
 * exactly the abi.encodePacked of CertenAccountV7.computeSingleCommitment. Null when an argument has no commitment (a chain id
 * that is not a safe integer from 1, a target that is not a lowercase address, a value that is not a decimal amount of at most
 * 2^256-1, data that is not bytes). A multi-leg batch commitment is a different form and is not computed here.
 */
export function singleCommitment(chainId: unknown, target: unknown, value: unknown, data: unknown): string | null {
  if (typeof chainId !== 'number' || !Number.isSafeInteger(chainId) || chainId < 1) return null;
  if (typeof target !== 'string' || !ADDRESS_RE.test(target)) return null;
  if (!isAmount(value)) return null;
  if (!(data instanceof Uint8Array)) return null;
  return keccak256Hex(concat(word(BigInt(chainId)), fromHex(target.slice(2)), word(BigInt(value)), keccak256(data)));
}
