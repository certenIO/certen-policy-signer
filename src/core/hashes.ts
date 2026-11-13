/**
 * Every domain-tagged hash of the core (DAX-2 hash goldens gh-01 to gh-16). Each hash is
 * SHA-256( lp(tag) || lp(field) || ... ) with lp(x) = four-byte big-endian length followed by x, shown as 0x plus
 * lowercase hex (the proof v2 convention). `*Preimage` returns the bytes that are hashed so that an implementer can find
 * which step differs; `hash*` returns the digest. These helpers throw CoreError on input that has no hash.
 */
import { ACTION_KINDS, canonicalGrant } from './grant-profile.js';
import { canonicalRegistration } from './registry-profile.js';
import { CoreError, address20, be64, concat, hash32, isAmount, isPlainObject, lp, sha256, toHex, utf8 } from './bytes.js';
import { canonicalize } from './jcs.js';

export const TAGS = {
  grant: 'certen:grant:v1',
  policy: 'certen:policy:v1',
  request: 'certen:request:v1',
  decision: 'certen:decision:v1',
  exception: 'certen:exception:v1',
  subject: 'certen:subject:v1',
  subject2: 'certen:subject:v2',
  envelopeSig: 'certen:envelope-sig:v1',
  declog: 'certen:declog:v1',
  declogGenesis: 'certen:declog:d0/v1',
} as const;

export const digestHex = (preimage: Uint8Array): string => '0x' + toHex(sha256(preimage));

/** lp(tag) followed by lp(field) for every field. */
export function taggedPreimage(tag: string, fields: Uint8Array[]): Uint8Array {
  return concat(lp(utf8(tag)), ...fields.map((f) => lp(f)));
}

/** The framing check of the goldens (test-only tags): every field is UTF-8 text. */
export function framedPreimage(tag: string, fieldsUtf8: string[]): Uint8Array {
  return taggedPreimage(tag, fieldsUtf8.map((f) => utf8(f)));
}

// ---- grant, subject registration -----------------------------------------------------------------------------

export function grantPreimage(grant: unknown): Uint8Array {
  return taggedPreimage(TAGS.grant, [utf8(canonicalGrant(grant))]);
}
export const hashGrant = (grant: unknown): string => digestHex(grantPreimage(grant));

/** The tag a registration is hashed and signed under: certen:subject:v1 for a v1 record, certen:subject:v2 for a lineage version. */
export function registrationTag(registration: unknown): string {
  return isPlainObject(registration) && registration['schema'] === 'certen.subject/v2' ? TAGS.subject2 : TAGS.subject;
}
function registrationPreimage(registration: unknown, tag: string): Uint8Array {
  if (registrationTag(registration) !== tag) throw new CoreError('registration_schema_invalid', tag);
  return taggedPreimage(tag, [utf8(canonicalRegistration(registration))]);
}
/** gh-12: the certen.subject/v1 record. */
export const subjectPreimage = (registration: unknown): Uint8Array => registrationPreimage(registration, TAGS.subject);
/** gh-17: the certen.subject/v2 lineage version. */
export const subject2Preimage = (registration: unknown): Uint8Array => registrationPreimage(registration, TAGS.subject2);
/** The registration hash of either schema (the tag follows the schema). */
export const hashRegistration = (registration: unknown): string => digestHex(taggedPreimage(registrationTag(registration), [utf8(canonicalRegistration(registration))]));

// ---- policy --------------------------------------------------------------------------------------------------

/** policyHash = SHA-256( lp("certen:policy:v1") || lp(canonical rule set) || lp(canonical signer ceilings) ). */
export function policyPreimage(ruleSet: unknown, ceilings: unknown): Uint8Array {
  return taggedPreimage(TAGS.policy, [utf8(canonicalize(ruleSet)), utf8(canonicalize(ceilings))]);
}
export const hashPolicy = (ruleSet: unknown, ceilings: unknown): string => digestHex(policyPreimage(ruleSet, ceilings));

// ---- request -------------------------------------------------------------------------------------------------

const REQUEST_KEYS = ['chainId', 'kind', 'source', 'target', 'beneficiary', 'asset', 'amount', 'executionCommitment', 'operationId', 'txHash'];

/**
 * requestHash preimage: chainId as be64, kind and asset and amount as UTF-8, source, target and beneficiary as their
 * 20 raw bytes, executionCommitment, operationId and the Accumulate transaction hash as their 32 raw bytes.
 */
export function requestPreimage(request: unknown): Uint8Array {
  if (!isPlainObject(request)) throw new CoreError('request_malformed');
  for (const k of Object.keys(request)) if (!REQUEST_KEYS.includes(k)) throw new CoreError('request_unknown_field', k);
  for (const k of REQUEST_KEYS) if (!(k in request)) throw new CoreError('request_missing_field', k);
  const chainId = request['chainId'];
  if (typeof chainId !== 'number' || !Number.isSafeInteger(chainId) || chainId < 1) throw new CoreError('request_field_invalid', 'chainId');
  const kind = request['kind'];
  if (typeof kind !== 'string' || !(ACTION_KINDS as readonly string[]).includes(kind)) throw new CoreError('request_field_invalid', 'kind');
  const asset = request['asset'];
  if (asset !== 'native') address20(asset, 'asset');
  const amount = request['amount'];
  if (!isAmount(amount)) throw new CoreError('request_field_invalid', 'amount');
  return taggedPreimage(TAGS.request, [
    be64(chainId),
    utf8(kind),
    address20(request['source'], 'source'),
    address20(request['target'], 'target'),
    address20(request['beneficiary'], 'beneficiary'),
    utf8(asset as string),
    utf8(amount),
    hash32(request['executionCommitment'], 'executionCommitment'),
    hash32(request['operationId'], 'operationId'),
    hash32(request['txHash'], 'txHash'),
  ]);
}
export const hashRequest = (request: unknown): string => digestHex(requestPreimage(request));

// ---- decision record, exception (hash only; their objects are built in DAX-4 and AGT-4) --------------------------

function schemaObjectPreimage(tag: string, schema: string, value: unknown, what: string): Uint8Array {
  if (!isPlainObject(value)) throw new CoreError(what + '_malformed');
  if (value['schema'] !== schema) throw new CoreError(what + '_schema_invalid');
  return taggedPreimage(tag, [utf8(canonicalize(value))]);
}
export const decisionPreimage = (record: unknown): Uint8Array => schemaObjectPreimage(TAGS.decision, 'certen.decision/v1', record, 'decision');
export const hashDecision = (record: unknown): string => digestHex(decisionPreimage(record));
export const exceptionPreimage = (exception: unknown): Uint8Array => schemaObjectPreimage(TAGS.exception, 'certen.exception/v1', exception, 'exception');
export const hashException = (exception: unknown): string => digestHex(exceptionPreimage(exception));

// ---- envelope signature digest -------------------------------------------------------------------------------

/**
 * What a key signs: SHA-256( lp("certen:envelope-sig:v1") || lp(payloadTag) || lp(payloadHash bytes) || lp(page URL) ).
 * This returns the preimage; envelopeDigest returns the 32-byte digest.
 */
export function envelopeSigPreimage(payloadTag: string, payloadHash: string, page: string): Uint8Array {
  return taggedPreimage(TAGS.envelopeSig, [utf8(payloadTag), hash32(payloadHash, 'payloadHash'), utf8(page)]);
}
export const envelopeDigest = (payloadTag: string, payloadHash: string, page: string): Uint8Array => sha256(envelopeSigPreimage(payloadTag, payloadHash, page));

// ---- decision log --------------------------------------------------------------------------------------------

export const genesisPreimage = (logId: string): Uint8Array => taggedPreimage(TAGS.declogGenesis, [utf8(logId)]);
export const genesisHash = (logId: string): string => digestHex(genesisPreimage(logId));

export interface LogEntryFields {
  prev: string;
  seq: number;
  kind: string;
  payload: unknown;
  at: number;
}

/** entry hash = SHA-256( lp(tag) || lp(prev) || lp(be64 seq) || lp(kind) || lp(SHA-256(canonical payload)) || lp(be64 at) ) */
export function logEntryPreimage(e: LogEntryFields): Uint8Array {
  return taggedPreimage(TAGS.declog, [hash32(e.prev, 'prev'), be64(e.seq), utf8(e.kind), sha256(utf8(canonicalize(e.payload))), be64(e.at)]);
}
export const logEntryHash = (e: LogEntryFields): string => digestHex(logEntryPreimage(e));
