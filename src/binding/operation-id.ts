/**
 * The VALIDATOR's operation id, recomputed from the four blobs of a pending transaction's own data entry (DECISION.md
 * section 2, DE-64, DAX-4-A17).
 *
 * Three ids exist for one intent and DAX-4 binds exactly one of them:
 *   - the blob-0 `intent_id` UUID: a correlation id the signer has always read as `operationId` (decoder, certen-intent.ts);
 *   - the `intent_hash` the bridge writes into blob 3: a hash taken with that very field blanked;
 *   - the validator's `CertenIntent.OperationID()`: `ComputeCanonical4BlobHash` over the four blobs AS PUBLISHED, intent_hash
 *     included, the identity the batch leaf binds (independant_validator pkg/consensus/intent.go:432-441,
 *     pkg/proof/canonical_blob_hash.go:65-83). It is what executes, and it needs no member of the intent to be trusted.
 *
 * ComputeCanonical4BlobHash: each blob is json.Unmarshal-ed into interface{}, its object keys sorted (sort.Strings: byte
 * order of the UTF-8 key), re-marshalled with Go's encoder, written to a SHA-256 behind a 4-byte big-endian length. This file
 * reproduces that serialisation for the values a JSON text can hold: Go's string escaping (HTML characters and U+2028/9 as
 * \u00XX forms, control characters, U+FFFD for a lone surrogate), numbers as float64 in Go's shortest form (ES6-like), `-0`.
 * Go 1.22 or later is assumed for the escapes of \b and \f (the recorded Go run used golang:1.25). A blob that is not valid
 * UTF-8, not valid JSON, or holds a number a float64 cannot (Go refuses it too) is refused here, by name, and the caller
 * refuses the request: it never guesses.
 */
import { createHash } from 'node:crypto';

export class OperationIdError extends Error {
  constructor(readonly reason: string, readonly detail?: string) {
    super(detail === undefined ? reason : `${reason} ${detail}`);
  }
}

const HEX = '0123456789abcdef';

/** Go's encoding/json string encoding with HTML escaping on (the default of json.Marshal). */
function goString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 0x20 || c === 0x3c || c === 0x3e || c === 0x26) out += '\\u00' + HEX[(c >> 4) & 0xf] + HEX[c & 0xf];
    else if (c === 0x2028) out += '\\u2028';
    else if (c === 0x2029) out += '\\u2029';
    else if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d >= 0xdc00 && d <= 0xdfff) {
        out += s[i]! + s[i + 1]!;
        i++;
      } else out += '�';
    } else if (c >= 0xdc00 && c <= 0xdfff) out += '�';
    else out += s[i]!;
  }
  return out + '"';
}

function goNumber(n: number): string {
  if (!Number.isFinite(n)) throw new OperationIdError('blob_number_overflow');
  if (Object.is(n, -0)) return '-0';
  // JavaScript's shortest round-trip form and Go's AppendFloat(-1) agree on digits; both switch to an exponent below 1e-6 and
  // from 1e21, and Go's `e-09` clean-up gives `e-9`, which is what String() prints.
  return String(n);
}

const byUtf8 = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

function goMarshal(v: unknown): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return goNumber(v);
  if (typeof v === 'string') return goString(v);
  if (Array.isArray(v)) return '[' + v.map(goMarshal).join(',') + ']';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort(byUtf8);
    return '{' + keys.map((k) => goString(k) + ':' + goMarshal(o[k])).join(',') + '}';
  }
  throw new OperationIdError('blob_value_unsupported', typeof v);
}

const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** The bytes Go's CanonicalizeJSON would produce for one blob (the bytes of the data-entry element). */
export function canonicalBlob(bytes: Uint8Array): Uint8Array {
  let text: string;
  try {
    text = utf8Strict.decode(bytes);
  } catch {
    throw new OperationIdError('blob_not_utf8');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new OperationIdError('blob_not_json');
  }
  return Buffer.from(goMarshal(parsed), 'utf8');
}

/** `0x` + 64 hex: SHA-256 over, for each of the four blobs, a 4-byte big-endian length and the canonical bytes. */
export function validatorOperationId(blobs: Uint8Array[]): string {
  if (blobs.length !== 4) throw new OperationIdError('blob_count', String(blobs.length));
  const h = createHash('sha256');
  for (const b of blobs) {
    const canon = canonicalBlob(b);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(canon.length, 0);
    h.update(len);
    h.update(canon);
  }
  return '0x' + h.digest('hex');
}
