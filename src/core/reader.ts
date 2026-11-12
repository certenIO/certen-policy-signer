/**
 * The pluggable Accumulate reader (DAX-3 work package 1). The library never talks to a network: the caller injects an
 * AccumulateReader (the Kermit API v3 client in the lab, an in-memory fake in tests) and these functions turn what it
 * returns into the named verdicts of the core. A reader that fails, or returns nothing, is never an allow: the verdict
 * is `authority_unreadable`, `lineage_unreadable`, `registry_unreadable` or an empty lineage, all of which deny.
 */
import { isAccUrl, validateGrant, type Grant } from './grant-profile.js';
import { decodeEntry, verifyGrantEnvelope, verifyRegistrationEnvelope, type ChainSnapshot, type EnvelopeVerdict } from './envelope.js';
import { evaluateLineage, type LineageResult } from './grant.js';
import { hashGrant } from './hashes.js';
import { type Registration } from './registry-profile.js';

export interface KeyPageInfo { url: string; keyHashes: string[]; threshold: number }
export interface DataEntry {
  /** the Accumulate transaction id of the WriteData that carried the entry (a record, never an input to a hash) */
  txId: string;
  /** chain time of the entry, Unix seconds, when the reader knows it */
  time?: number;
  elements: Uint8Array[];
}

export interface AccumulateReader {
  /** the data entries of a data account in chain order, or null when the account cannot be read */
  dataEntries(account: string): Promise<DataEntry[] | null>;
  /** the (enabled) authority key books of an account or ADI, or null when unreadable */
  authorities(account: string): Promise<string[] | null>;
  /** the key pages of a key book, or null when unreadable */
  keyBookPages(book: string): Promise<KeyPageInfo[] | null>;
}

export const GRANTS_ACCOUNT = 'certen-grants';
export const SUBJECTS_ACCOUNT = 'certen-subjects';

type Snapshot = { ok: true; chain: ChainSnapshot; subjectBooks: string[] } | { ok: false; reason: 'authority_unreadable'; detail: string };

async function guarded<T>(what: string, f: () => Promise<T | null>): Promise<{ ok: true; value: T } | { ok: false; detail: string }> {
  try {
    const v = await f();
    return v === null || v === undefined ? { ok: false, detail: what } : { ok: true, value: v };
  } catch {
    return { ok: false, detail: what + ' (reader error)' };
  }
}

/** Reads exactly what the envelope check needs: the data account's authority set, the subject's books, their pages. */
export async function snapshotFor(reader: AccumulateReader, a: { dataAccount: string; ownerBook: string; subjectAdi: string }): Promise<Snapshot> {
  const auths = await guarded('authorities ' + a.dataAccount, () => reader.authorities(a.dataAccount));
  if (!auths.ok) return { ok: false, reason: 'authority_unreadable', detail: auths.detail };
  const subj = await guarded('authorities ' + a.subjectAdi, () => reader.authorities(a.subjectAdi));
  if (!subj.ok) return { ok: false, reason: 'authority_unreadable', detail: subj.detail };
  const pages: ChainSnapshot['pages'] = {};
  for (const book of new Set([a.ownerBook, ...subj.value])) {
    const b = await guarded('keyBookPages ' + book, () => reader.keyBookPages(book));
    if (!b.ok) return { ok: false, reason: 'authority_unreadable', detail: b.detail };
    for (const p of b.value) pages[p.url] = { book, keyHashes: [...p.keyHashes], threshold: p.threshold };
  }
  // the pages come from a real Accumulate key page, so the key hashes are over the stored key bytes (GR-42)
  return { ok: true, chain: { pages, dataAccountAuthorities: [...auths.value], keyHashConvention: 'accumulate' }, subjectBooks: [...subj.value] };
}

/** Verifies a Grant envelope against what the reader returns for the grantor's grants account and the key pages. */
export async function verifyGrantEnvelopeViaReader(reader: AccumulateReader, grant: unknown, envelope: unknown): Promise<EnvelopeVerdict> {
  const g = validateGrant(grant);
  if (!g.ok) return { ok: false, reason: 'grant_malformed', detail: g.reason };
  const snap = await snapshotFor(reader, { dataAccount: g.grant.grantor.adi + '/' + GRANTS_ACCOUNT, ownerBook: g.grant.grantor.keyBook, subjectAdi: g.grant.subject.adi });
  if (!snap.ok) return snap;
  return verifyGrantEnvelope({ grant: g.grant, envelope, chain: snap.chain, subjectBooks: snap.subjectBooks });
}

export interface LineageEntryRecord { txId: string; version: number; hash: string; verdict: string }
export type ReadLineageResult =
  | (LineageResult & { entries?: LineageEntryRecord[] })
  | { ok: false; reason: 'lineage_unreadable'; detail?: string }
  | { ok: false; reason: 'account_entry_undecodable'; index: number; cause: string; txId: string };

/**
 * GR-22 to GR-27 over the chain: reads `<grantor>/certen-grants` in data-entry order, decodes every entry, keeps those of
 * `grantId`, checks each envelope against the key pages the reader returns, and evaluates the lineage. An entry that
 * cannot be decoded refuses the WHOLE read (GR-44: it cannot be attributed to a grantId, so it may be a version of any lineage).
 */
export async function readGrantLineage(reader: AccumulateReader, a: { grantorAdi: string; grantId: string; now: number }): Promise<ReadLineageResult> {
  const account = a.grantorAdi + '/' + GRANTS_ACCOUNT;
  const read = await guarded('dataEntries ' + account, () => reader.dataEntries(account));
  if (!read.ok) return { ok: false, reason: 'lineage_unreadable', detail: read.detail };
  const mine: Array<{ txId: string; grant: Grant; verdict: string }> = [];
  for (let idx = 0; idx < read.value.length; idx++) {
    const entry = read.value[idx]!;
    const d = decodeEntry({ account: 'grants', elements: entry.elements });
    if (!d.ok) return { ok: false, reason: 'account_entry_undecodable', index: idx, cause: d.reason, txId: entry.txId };
    if (d.account !== 'grants' || d.grant.grantId !== a.grantId) continue;
    let verdict: string;
    if (d.grant.grantor.adi !== a.grantorAdi) verdict = 'grantor_mismatch';
    else {
      const v = await verifyGrantEnvelopeViaReader(reader, d.grant, d.envelope);
      verdict = v.ok ? 'ok' : v.reason;
    }
    mine.push({ txId: entry.txId, grant: d.grant, verdict });
  }
  const r = evaluateLineage({ entries: mine.map((m) => ({ grant: m.grant, envelopeVerdict: m.verdict })), now: a.now });
  const records: LineageEntryRecord[] = mine.map((m) => ({ txId: m.txId, version: m.grant.version, hash: hashGrant(m.grant), verdict: m.verdict }));
  return { ...r, entries: records } as ReadLineageResult;
}

export interface RegistryRow { record: Registration; envelopeVerdict: string; txId: string; registrationHash: string }
export type ReadRegistryResult =
  | { ok: true; registry: RegistryRow[] }
  | { ok: false; reason: 'registry_unreadable'; detail?: string }
  | { ok: false; reason: 'account_entry_undecodable'; index: number; cause: string; txId: string };

/** Reads `<principal>/certen-subjects`, decodes and verifies every registration. Anything unreadable denies. */
export async function readSubjectRegistry(reader: AccumulateReader, principalAdi: string): Promise<ReadRegistryResult> {
  if (!isAccUrl(principalAdi)) return { ok: false, reason: 'registry_unreadable', detail: 'principal' };
  const account = principalAdi + '/' + SUBJECTS_ACCOUNT;
  const read = await guarded('dataEntries ' + account, () => reader.dataEntries(account));
  if (!read.ok) return { ok: false, reason: 'registry_unreadable', detail: read.detail };
  const registry: RegistryRow[] = [];
  for (let idx = 0; idx < read.value.length; idx++) {
    const entry = read.value[idx]!;
    const d = decodeEntry({ account: 'subjects', elements: entry.elements });
    if (!d.ok) return { ok: false, reason: 'account_entry_undecodable', index: idx, cause: d.reason, txId: entry.txId };
    if (d.account !== 'subjects') continue;
    let verdict: string;
    if (d.registration.principal.adi !== principalAdi) verdict = 'principal_mismatch';
    else {
      const snap = await snapshotFor(reader, { dataAccount: account, ownerBook: d.registration.principal.keyBook, subjectAdi: d.registration.adi });
      verdict = snap.ok ? (() => { const v = verifyRegistrationEnvelope({ registration: d.registration, envelope: d.envelope, chain: snap.chain, subjectBooks: snap.subjectBooks }); return v.ok ? 'ok' : v.reason; })() : snap.reason;
    }
    registry.push({ record: d.registration, envelopeVerdict: verdict, txId: entry.txId, registrationHash: d.hash });
  }
  return { ok: true, registry };
}

