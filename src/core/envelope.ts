/**
 * The signature envelope (GRANT.md sections 4 and 5): {payloadTag, payloadHash, signatures[]} with each signature
 * {alg, page, publicKey, signature}. The signed message is the digest of hashes.ts envelopeDigest, so a signature
 * cannot be moved to another payload, another object type or another page.
 *
 * The envelope is EVIDENCE of authorship for a reader that holds a snapshot of the key pages; Accumulate's own
 * authority check on the WriteData transaction is the control. This module only verifies; the keys that sign live
 * outside the library (it never signs for anyone).
 *
 * Key forms (GRANT.md section 4, GR-42): the key hash that matches a key-page entry is SHA-256 of the public key bytes
 * exactly as the envelope carries them. ed25519 carries the 32 raw bytes. ecdsa-p256-sha256 carries the 91-byte PKIX
 * SubjectPublicKeyInfo DER, the form Accumulate stores and hashes; the 65-byte uncompressed point is accepted only
 * against a snapshot that does not declare keyHashConvention "accumulate".
 */
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { CoreError, HASH_RE, fromHex, isPlainObject, sha256, toHex, utf8, utf8Decode, utf8Length, type Json } from './bytes.js';
import { isAccUrl, isUnderAdi, parseGrantTextUnhashed, validateGrant, type Grant } from './grant-profile.js';
import { envelopeDigest, hashGrant, hashRegistration, registrationTag, TAGS } from './hashes.js';
import { canonicalize, parseJson } from './jcs.js';
import { parseRegistrationTextUnhashed, validateRegistration, type Registration } from './registry-profile.js';

export type SignatureAlg = 'ed25519' | 'ecdsa-p256-sha256';
export const SUPPORTED_ALGS: readonly string[] = ['ed25519', 'ecdsa-p256-sha256'];

export interface EnvelopeSignature { alg: string; page: string; publicKey: string; signature: string }
export interface Envelope { payloadTag: string; payloadHash: string; signatures: EnvelopeSignature[] }
export interface PageSnapshot { book: string; keyHashes: string[]; threshold: number }
export interface ChainSnapshot {
  pages: Record<string, PageSnapshot>;
  dataAccountAuthorities: string[];
  /** "accumulate" when the snapshot was taken from a real Accumulate key page (key hashes over the stored key bytes) */
  keyHashConvention?: 'accumulate';
}

export type EnvelopeVerdict = { ok: true; pages: string[] } | { ok: false; reason: string; detail?: string };

/** GR-46 */
export const ENVELOPE_LIMITS = { textBytes: 16384, signatures: 16 };
const LOWER_HEX_RE = /^([0-9a-f]{2})+$/;
/** DER prefix of a P-256 SubjectPublicKeyInfo; the 65-byte uncompressed point (04, X, Y) follows. */
const P256_SPKI_PREFIX_HEX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

/** SHA-256 of the public key bytes as carried in the envelope; the key hash used to match a key-page entry. */
export function keyHashHex(publicKeyHex: string): string {
  return toHex(sha256(fromHex(publicKeyHex)));
}

function b64url(bytes: Uint8Array): string {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += A[(n >> 18) & 63]! + A[(n >> 12) & 63]!;
    if (i + 1 < bytes.length) out += A[(n >> 6) & 63]!;
    if (i + 2 < bytes.length) out += A[n & 63]!;
  }
  return out;
}

// ---- structure -----------------------------------------------------------------------------------------------

export type EnvelopeValidation = { ok: true; envelope: Envelope } | { ok: false; reason: string; detail: string };

const bad = (reason: string, detail: string): EnvelopeValidation => ({ ok: false, reason, detail });

function signatureShape(s: unknown, i: number): EnvelopeValidation | null {
  if (!isPlainObject(s)) return bad('envelope_malformed', 'signature ' + i);
  const keys = Object.keys(s);
  const want = ['alg', 'page', 'publicKey', 'signature'];
  for (const k of keys) if (!want.includes(k)) return bad('envelope_unknown_field', 'signature ' + i + ' ' + k);
  for (const k of want) if (!keys.includes(k)) return bad('envelope_missing_field', 'signature ' + i + ' ' + k);
  if (typeof s['alg'] !== 'string' || !isAccUrl(s['page'])) return bad('envelope_malformed', 'signature ' + i);
  const pk = s['publicKey'];
  const sg = s['signature'];
  if (typeof pk !== 'string' || typeof sg !== 'string' || !LOWER_HEX_RE.test(pk) || !LOWER_HEX_RE.test(sg)) return bad('envelope_malformed', 'signature ' + i);
  let ok = true;
  if (s['alg'] === 'ed25519') ok = pk.length === 64 && sg.length === 128;
  // P-256 keys are carried either as the 65-byte uncompressed point (the form of the older vectors) or as the 91-byte
  // SubjectPublicKeyInfo DER, the form Accumulate stores and hashes for an ecdsaSha256 key (GR-42)
  else if (s['alg'] === 'ecdsa-p256-sha256') ok = sg.length === 128 && ((pk.length === 130 && pk.startsWith('04')) || (pk.length === 182 && pk.startsWith(P256_SPKI_PREFIX_HEX + '04')));
  return ok ? null : bad('envelope_malformed', 'signature ' + i);
}

export function validateEnvelope(v: unknown): EnvelopeValidation {
  if (!isPlainObject(v)) return bad('envelope_malformed', 'not an object');
  const keys = Object.keys(v);
  const want = ['payloadTag', 'payloadHash', 'signatures'];
  for (const k of keys) if (!want.includes(k)) return bad('envelope_unknown_field', k);
  for (const k of want) if (!keys.includes(k)) return bad('envelope_missing_field', k);
  if (typeof v['payloadTag'] !== 'string' || v['payloadTag'].length === 0 || v['payloadTag'].length > 128) return bad('envelope_malformed', 'payloadTag');
  if (typeof v['payloadHash'] !== 'string' || !HASH_RE.test(v['payloadHash'])) return bad('envelope_malformed', 'payloadHash');
  const sigs = v['signatures'];
  if (!Array.isArray(sigs) || sigs.length === 0) return bad('envelope_malformed', 'signatures');
  if (sigs.length > ENVELOPE_LIMITS.signatures) return bad('envelope_too_large', 'signatures');
  for (let i = 0; i < sigs.length; i++) {
    const r = signatureShape(sigs[i], i);
    if (r !== null) return r;
  }
  let text: string;
  try {
    text = canonicalize(v);
  } catch (e) {
    if (e instanceof CoreError) return bad('envelope_malformed', e.code);
    throw e;
  }
  if (utf8Length(text) > ENVELOPE_LIMITS.textBytes) return bad('envelope_too_large', 'text');
  return { ok: true, envelope: parseJson(text, { integersOnly: true }) as unknown as Envelope };
}

/** Assembles an envelope from signatures a caller's signer produced; it checks the shape, it signs nothing. */
export function buildEnvelope(payloadTag: string, payloadHash: string, signatures: EnvelopeSignature[]): Envelope {
  const v = validateEnvelope({ payloadTag, payloadHash, signatures });
  if (!v.ok) throw new CoreError(v.reason, v.detail);
  return v.envelope;
}

export function canonicalEnvelope(envelope: unknown): string {
  const v = validateEnvelope(envelope);
  if (!v.ok) throw new CoreError(v.reason, v.detail);
  return canonicalize(v.envelope);
}

export type ParseEnvelopeResult = { ok: true; envelope: Envelope; canonical: string } | { ok: false; reason: string; detail?: string };

/** Strict parse of envelope text: size, duplicates, lone surrogates, number spellings, then the closed members. */
export function parseEnvelopeText(text: string): ParseEnvelopeResult {
  if (utf8Length(text) > ENVELOPE_LIMITS.textBytes) return { ok: false, reason: 'envelope_too_large' };
  let value: Json;
  try {
    value = parseJson(text, { integersOnly: true });
  } catch (e) {
    if (e instanceof CoreError) return { ok: false, reason: 'envelope_' + e.code };
    throw e;
  }
  const v = validateEnvelope(value);
  return v.ok ? { ok: true, envelope: v.envelope, canonical: canonicalize(v.envelope) } : { ok: false, reason: v.reason, detail: v.detail };
}

// ---- verification --------------------------------------------------------------------------------------------

function signatureValid(alg: string, publicKeyHex: string, signatureHex: string, digest: Uint8Array): boolean {
  try {
    const pk = fromHex(publicKeyHex);
    const sig = fromHex(signatureHex);
    if (alg === 'ed25519') {
      const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(pk) }, format: 'jwk' });
      return cryptoVerify(null, digest, key, sig);
    }
    if (alg === 'ecdsa-p256-sha256') {
      const point = pk.length === 65 ? pk : pk.subarray(26);
      const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64url(point.subarray(1, 33)), y: b64url(point.subarray(33, 65)) }, format: 'jwk' });
      return cryptoVerify('sha256', digest, { key, dsaEncoding: 'ieee-p1363' }, sig);
    }
    return false;
  } catch {
    return false;
  }
}

function chainOk(chain: unknown): chain is ChainSnapshot {
  if (!isPlainObject(chain) || !isPlainObject(chain['pages']) || !Array.isArray(chain['dataAccountAuthorities'])) return false;
  const conv = chain['keyHashConvention'];
  if (conv !== undefined && conv !== 'accumulate') return false;
  if (!chain['dataAccountAuthorities'].every((a) => isAccUrl(a))) return false;
  for (const [url, p] of Object.entries(chain['pages'])) {
    if (!isAccUrl(url) || !isPlainObject(p)) return false;
    if (!isAccUrl(p['book']) || !Array.isArray(p['keyHashes']) || !p['keyHashes'].every((h) => typeof h === 'string' && LOWER_HEX_RE.test(h) && h.length === 64)) return false;
    if (typeof p['threshold'] !== 'number' || !Number.isSafeInteger(p['threshold']) || p['threshold'] < 1) return false;
  }
  return true;
}

/** The names a verdict uses: the grantor's for a Grant, the principal's for a registration (GR-53). */
interface VerdictNames { signerNot: string; signedBySubject: string; hashMismatch: string; authorityIncludesSubject: string; notAuthority: string }
const GRANT_NAMES: VerdictNames = { signerNot: 'signer_not_grantor', signedBySubject: 'grant_signed_by_subject', hashMismatch: 'grant_hash_mismatch', authorityIncludesSubject: 'grant_authority_includes_subject', notAuthority: 'grantor_not_authority' };
const REGISTRATION_NAMES: VerdictNames = { signerNot: 'signer_not_principal', signedBySubject: 'registration_signed_by_subject', hashMismatch: 'registration_hash_mismatch', authorityIncludesSubject: 'registration_authority_includes_subject', notAuthority: 'principal_not_authority' };

export interface VerifyEnvelopeArgs {
  tag: string;
  payloadHash: string;
  envelope: unknown;
  chain: unknown;
  /** the key book whose page threshold authorizes the payload (the grantor's book, or the principal's) */
  ownerBook: string;
  /** the subject's ADI and the books of the subject (read from its authority set) */
  subjectAdi: string;
  subjectBooks: unknown;
  /** which vocabulary the verdict uses; default the Grant's */
  names?: 'grant' | 'registration';
}

/**
 * GR-14 order: malformed envelope, tag mismatch, hash mismatch, a data-account authority set that includes the
 * subject, one that lacks the owner book; then per signature (in envelope order) an unsupported algorithm, a key form
 * the snapshot's convention refuses, a subject key, a key that is not on a page of the owner book, an invalid
 * signature; finally a threshold no page reaches.
 */
export function verifyEnvelope(a: VerifyEnvelopeArgs): EnvelopeVerdict {
  const N = a.names === 'registration' ? REGISTRATION_NAMES : GRANT_NAMES;
  const ev = validateEnvelope(a.envelope);
  if (!ev.ok) return ev;
  const env = ev.envelope;
  if (!chainOk(a.chain) || !Array.isArray(a.subjectBooks) || !a.subjectBooks.every((b) => isAccUrl(b))) return { ok: false, reason: 'chain_snapshot_malformed' };
  const chain = a.chain;
  const subjectBooks = a.subjectBooks as string[];
  const isSubjectBook = (b: string): boolean => subjectBooks.includes(b) || isUnderAdi(b, a.subjectAdi);

  if (env.payloadTag !== a.tag) return { ok: false, reason: 'payload_tag_mismatch' };
  if (env.payloadHash !== a.payloadHash) return { ok: false, reason: N.hashMismatch };
  if (chain.dataAccountAuthorities.some(isSubjectBook)) return { ok: false, reason: N.authorityIncludesSubject };
  if (!chain.dataAccountAuthorities.includes(a.ownerBook)) return { ok: false, reason: N.notAuthority };

  const subjectKeyHashes = new Set<string>();
  for (const p of Object.values(chain.pages)) if (isSubjectBook(p.book)) for (const h of p.keyHashes) subjectKeyHashes.add(h);

  const signers = new Map<string, Set<string>>();
  for (const s of env.signatures) {
    if (!SUPPORTED_ALGS.includes(s.alg)) return { ok: false, reason: 'signature_alg_unsupported', detail: s.alg };
    if (chain.keyHashConvention === 'accumulate' && s.alg === 'ecdsa-p256-sha256' && s.publicKey.length !== 182) return { ok: false, reason: 'signer_key_form_invalid' };
    const kh = keyHashHex(s.publicKey);
    if (subjectKeyHashes.has(kh)) return { ok: false, reason: N.signedBySubject };
    const page = Object.prototype.hasOwnProperty.call(chain.pages, s.page) ? chain.pages[s.page] : undefined;
    if (page === undefined || page.book !== a.ownerBook || !page.keyHashes.includes(kh)) return { ok: false, reason: N.signerNot };
    if (!signatureValid(s.alg, s.publicKey, s.signature, envelopeDigest(env.payloadTag, env.payloadHash, s.page))) return { ok: false, reason: 'signature_invalid' };
    const set = signers.get(s.page) ?? new Set<string>();
    set.add(kh);
    signers.set(s.page, set);
  }
  const pages = [...signers.entries()].filter(([url, set]) => set.size >= chain.pages[url]!.threshold).map(([url]) => url).sort();
  if (pages.length === 0) return { ok: false, reason: 'threshold_not_met' };
  return { ok: true, pages };
}

export interface VerifyGrantEnvelopeArgs { grant: unknown; envelope: unknown; chain: unknown; subjectBooks: unknown }

/** GR-09, GR-13, GR-14 for a Grant version: the grantor's key book signs the grant hash under certen:grant:v1. */
export function verifyGrantEnvelope(a: VerifyGrantEnvelopeArgs): EnvelopeVerdict {
  const g = validateGrant(a.grant);
  if (!g.ok) return { ok: false, reason: 'grant_malformed', detail: g.reason };
  const grant: Grant = g.grant;
  return verifyEnvelope({ tag: TAGS.grant, payloadHash: hashGrant(grant), envelope: a.envelope, chain: a.chain, ownerBook: grant.grantor.keyBook, subjectAdi: grant.subject.adi, subjectBooks: a.subjectBooks, names: 'grant' });
}

export interface VerifyRegistrationEnvelopeArgs { registration: unknown; envelope: unknown; chain: unknown; subjectBooks: unknown }

/**
 * GR-29, GR-53: the principal's key book signs the registration hash under certen:subject:v2 (certen:subject:v1 for a
 * v1 record); the verdict names the principal, not the grantor.
 */
export function verifyRegistrationEnvelope(a: VerifyRegistrationEnvelopeArgs): EnvelopeVerdict {
  const r = validateRegistration(a.registration);
  if (!r.ok) return { ok: false, reason: 'registration_malformed', detail: r.reason };
  const reg: Registration = r.registration;
  return verifyEnvelope({ tag: registrationTag(reg), payloadHash: hashRegistration(reg), envelope: a.envelope, chain: a.chain, ownerBook: reg.principal.keyBook, subjectAdi: reg.adi, subjectBooks: a.subjectBooks, names: 'registration' });
}

// ---- data entries --------------------------------------------------------------------------------------------

export type EntryAccount = 'grants' | 'subjects';
export type DecodedEntry =
  | { ok: true; account: 'grants'; grant: Grant; envelope: Envelope; hash: string }
  | { ok: true; account: 'subjects'; registration: Registration; envelope: Envelope; hash: string }
  | { ok: false; reason: string; element?: number; detail?: string };

/** GR-07: one data entry, element 0 the UTF-8 canonical Grant, element 1 the UTF-8 canonical envelope. */
export function encodeGrantEntry(grant: unknown, envelope: unknown): Uint8Array[] {
  const g = validateGrant(grant);
  if (!g.ok) throw new CoreError(g.reason, g.detail);
  return [utf8(canonicalize(g.grant)), utf8(canonicalEnvelope(envelope))];
}

/** GR-29: the same shape for a registration. */
export function encodeRegistrationEntry(registration: unknown, envelope: unknown): Uint8Array[] {
  const r = validateRegistration(registration);
  if (!r.ok) throw new CoreError(r.reason, r.detail);
  return [utf8(canonicalize(r.registration)), utf8(canonicalEnvelope(envelope))];
}

const refuseEntry = (reason: string, element?: number, detail?: string): DecodedEntry => {
  const r: { ok: false; reason: string; element?: number; detail?: string } = { ok: false, reason };
  if (element !== undefined) r.element = element;
  if (detail !== undefined) r.detail = detail;
  return r;
};
const TOO_LARGE = ['grant_too_large', 'registration_too_large', 'envelope_too_large'];

/**
 * GR-43: an entry of certen-grants or certen-subjects has exactly two UTF-8 text elements, element 0 the canonical
 * Grant (or registration) and element 1 the canonical envelope, each byte for byte, with the envelope's tag and hash
 * those of element 0. Order of refusals: entry_shape, entry_not_text, entry_undecodable (element 0, then 1),
 * entry_not_canonical (element 0, then 1), payload_tag_mismatch, grant_hash_mismatch or registration_hash_mismatch.
 * An element beyond its size limit is refused by the name of its limit (grant_too_large, ...).
 */
export function decodeEntry(input: { account: unknown; elements: unknown }): DecodedEntry {
  const account = input.account;
  if (account !== 'grants' && account !== 'subjects') return refuseEntry('entry_account_invalid');
  const els = input.elements;
  if (!Array.isArray(els) || els.length !== 2 || !els.every((e) => e instanceof Uint8Array)) return refuseEntry('entry_shape');
  const texts: string[] = [];
  for (let i = 0; i < 2; i++) {
    try {
      texts.push(utf8Decode(els[i] as Uint8Array));
    } catch {
      return refuseEntry('entry_not_text', i);
    }
  }
  const text0 = texts[0]!;
  const text1 = texts[1]!;
  let grant: Grant | undefined;
  let registration: Registration | undefined;
  if (account === 'grants') {
    const p = parseGrantTextUnhashed(text0);
    if (!p.ok) return TOO_LARGE.includes(p.reason) ? refuseEntry(p.reason, 0) : refuseEntry('entry_undecodable', 0, p.reason);
    if (p.canonical !== text0) return refuseEntry('entry_not_canonical', 0);
    grant = p.grant;
  } else {
    const p = parseRegistrationTextUnhashed(text0);
    if (!p.ok) return TOO_LARGE.includes(p.reason) ? refuseEntry(p.reason, 0) : refuseEntry('entry_undecodable', 0, p.reason);
    if (p.canonical !== text0) return refuseEntry('entry_not_canonical', 0);
    registration = p.registration;
  }
  const e = parseEnvelopeText(text1);
  if (!e.ok) return TOO_LARGE.includes(e.reason) ? refuseEntry(e.reason, 1) : refuseEntry('entry_undecodable', 1, e.reason);
  if (e.canonical !== text1) return refuseEntry('entry_not_canonical', 1);
  if (grant !== undefined) {
    const hash = hashGrant(grant);
    if (e.envelope.payloadTag !== TAGS.grant) return refuseEntry('payload_tag_mismatch');
    if (e.envelope.payloadHash !== hash) return refuseEntry('grant_hash_mismatch');
    return { ok: true, account: 'grants', grant, envelope: e.envelope, hash };
  }
  const reg = registration!;
  const hash = hashRegistration(reg);
  if (e.envelope.payloadTag !== registrationTag(reg)) return refuseEntry('payload_tag_mismatch');
  if (e.envelope.payloadHash !== hash) return refuseEntry('registration_hash_mismatch');
  return { ok: true, account: 'subjects', registration: reg, envelope: e.envelope, hash };
}

export type ReadEntriesResult = { ok: true; count: number } | { ok: false; reason: 'account_entry_undecodable'; index: number; cause: string };

/**
 * GR-44: one undecodable or non-canonical entry refuses the WHOLE read of the account (fail closed). A stated limit:
 * whoever can write the account can make reads of its own account fail.
 */
export function readAccountEntries(input: { account: unknown; entries: unknown }): ReadEntriesResult | { ok: false; reason: 'entry_account_invalid' | 'entries_malformed' } {
  if (input.account !== 'grants' && input.account !== 'subjects') return { ok: false, reason: 'entry_account_invalid' };
  if (!Array.isArray(input.entries)) return { ok: false, reason: 'entries_malformed' };
  for (let i = 0; i < input.entries.length; i++) {
    const d = decodeEntry({ account: input.account, elements: input.entries[i] });
    if (!d.ok) return { ok: false, reason: 'account_entry_undecodable', index: i, cause: d.reason };
  }
  return { ok: true, count: input.entries.length };
}
