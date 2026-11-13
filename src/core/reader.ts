/**
 * The pluggable Accumulate reader and the ONLINE readers built on it (GRANT.md section 4a). The library never talks to a
 * network: the caller injects an AccumulateReader (the Kermit API v3 client in the lab, an in-memory fake in tests) and
 * these functions turn what it returns into the named verdicts of the core. A reader that fails, or returns nothing, is
 * never an allow: the verdict is one of the named refusals, all of which deny.
 *
 * WHAT A READER MUST PROVIDE (the interface the gateway, the signer and the Console copy):
 *   dataEntries(account)    the data entries of a data account in chain order, each with its chain time (`time`);
 *   authorities(account)    the authority key books of an account or ADI NOW (null when unreadable);
 *   accountHistory(account) the transaction types of the account's own main chain FROM ITS CREATION, in order, with an
 *                           `incomplete` signal when the chain could not be read back that far (null when unreadable);
 *   keyBookPages(book)      OPTIONAL and ADVISORY ONLY: the key pages of a book now, used for the head envelope advisory.
 * No online verdict reads a key page as of a past time and none requires a key page at all (GR-59).
 *
 * OFFLINE EVIDENCE ONLY, never to be called by an online reader or gateway path: verifyEnvelope, verifyGrantEnvelope,
 * verifyRegistrationEnvelope, verifyRegistrationAccepted, resolveSubjectSigned, resolveSubject (rows with envelope
 * verdicts), snapshotFor and verifyGrantEnvelopeViaReader (they read or need key pages). They decide the envelope
 * signatures against a snapshot that travels with an evidence pack (GR-60) and keep the sr-31..52 behaviour as documented
 * fixtures of the rejected two-role model.
 */
import { isAccUrl, validateGrant } from './grant-profile.js';
import { verifyGrantEnvelope, type ChainSnapshot, type EnvelopeVerdict } from './envelope.js';
import { SAFE_AFTER } from './account.js';
import { readLineageOnline, type LineageOnlineEntry, type LineageOnlineResult } from './lineage-online.js';
import { resolveSubjectOnline, type ResolveSubjectOnlineResult } from './registry-online.js';

export interface KeyPageInfo { url: string; keyHashes: string[]; threshold: number }
export interface DataEntry {
  /** the Accumulate transaction id of the WriteData that carried the entry (a record, never an input to a hash) */
  txId: string;
  /** chain time of the entry, Unix seconds (the execution time); REQUIRED for the registry and acceptance accounts. On Accumulate v3 it is the time of the minor block
   *  that executed the entry (block-time.ts), and the entries are the account's main-chain WriteData transactions (main-chain-entry.ts), NOT the data-chain query,
   *  which dates two entries with identical bytes by the later one */
  time?: number;
  elements: Uint8Array[];
}
/** the account's own main chain from its creation: transaction types in order; `incomplete` when the creation was not reached */
export interface AccountHistory { types: string[]; incomplete: boolean }

export interface AccumulateReader {
  dataEntries(account: string): Promise<DataEntry[] | null>;
  authorities(account: string): Promise<string[] | null>;
  accountHistory(account: string): Promise<AccountHistory | null>;
  /** OPTIONAL, ADVISORY ONLY (the head envelope check); never a gate */
  keyBookPages?(book: string): Promise<KeyPageInfo[] | null>;
}

export const GRANTS_ACCOUNT = 'certen-grants';
export const SUBJECTS_ACCOUNT = 'certen-subjects';
export const ACCEPTANCES_ACCOUNT = 'certen-acceptances';

async function guarded<T>(f: () => Promise<T | null | undefined>): Promise<T | null> {
  try {
    const v = await f();
    return v === undefined ? null : v;
  } catch {
    return null;
  }
}

interface AccountFactsRead {
  authorities: string[] | null;
  history: Array<{ type: string }> | null;
  incomplete: boolean;
  entries: DataEntry[] | null;
}
async function readAccount(reader: AccumulateReader, account: string): Promise<AccountFactsRead> {
  const authorities = await guarded(() => reader.authorities(account));
  const h = await guarded(() => reader.accountHistory(account));
  const entries = await guarded(() => reader.dataEntries(account));
  return { authorities, history: h === null ? null : h.types.map((type) => ({ type })), incomplete: h === null ? false : h.incomplete, entries };
}

export type ReadLineageResult =
  | Exclude<LineageOnlineResult, { ok: true }>
  | (Omit<Extract<LineageOnlineResult, { ok: true }>, 'entries'> & { entries: Array<LineageOnlineEntry & { txId: string }> });

/**
 * The ONLINE read of a Grant lineage (GR-22, GR-24, GR-44, GR-58 to GR-61): the authority facts of
 * `<grantor>/certen-grants`, canonical entries, the owner match and the prior-hash chain. It reads no key page unless
 * `advisory` is asked for AND the reader offers keyBookPages, and then only to fill the advisory `headEnvelopeCurrent`.
 * `grantorBook` is the key book that must own the account.
 */
export async function readGrantLineage(
  reader: AccumulateReader,
  a: { grantorAdi: string; grantorBook: string; grantId: string; now: number; subjectAdi?: string; safeAfter?: readonly string[]; advisory?: boolean },
): Promise<ReadLineageResult> {
  const account = a.grantorAdi + '/' + GRANTS_ACCOUNT;
  const facts = await readAccount(reader, account);
  const subjectBooks = a.subjectAdi === undefined ? [] : await guarded(() => reader.authorities(a.subjectAdi!));
  if (subjectBooks === null) return { ok: false, reason: 'account_authority_unreadable', detail: 'subject books' };
  let chain: ChainSnapshot | undefined;
  if (a.advisory === true && reader.keyBookPages !== undefined && facts.authorities !== null) {
    const pages = await guarded(() => reader.keyBookPages!(a.grantorBook));
    if (pages !== null) {
      chain = { pages: {}, dataAccountAuthorities: facts.authorities, keyHashConvention: 'accumulate' };
      for (const p of pages) chain.pages[p.url] = { book: a.grantorBook, keyHashes: [...p.keyHashes], threshold: p.threshold };
    }
  }
  const r = readLineageOnline({
    account: { ownerBook: a.grantorBook, authorities: facts.authorities, history: facts.history, incomplete: facts.incomplete, safeAfter: a.safeAfter ?? SAFE_AFTER },
    entries: facts.entries === null ? null : facts.entries.map((e) => ({ elements: e.elements, ...(e.time === undefined ? {} : { entryTime: e.time }) })),
    now: a.now,
    grantId: a.grantId,
    subjectBooks,
    ...(chain === undefined ? {} : { chain }),
  });
  if (!r.ok) return r;
  return { ...r, entries: r.entries.map((e) => ({ ...e, txId: facts.entries![e.index]!.txId })) };
}

/**
 * The ONLINE resolution of a Grant's subject (GR-54 to GR-57, GR-62). The registry read is ONLY
 * `<grant.grantor.adi>/certen-subjects`; the consent is `<subject>/certen-acceptances`. Reads no key page.
 */
export async function readSubjectRegistry(
  reader: AccumulateReader,
  a: { grant: unknown; asserted: { adi: string; assertedBy: string }; expectType: string; safeAfter?: readonly string[] },
): Promise<ResolveSubjectOnlineResult> {
  const g = validateGrant(a.grant);
  const grantorBook = g.ok ? g.grant.grantor.keyBook : '';
  const grantorAdi = g.ok ? g.grant.grantor.adi : '';
  const subject = a.asserted.adi;
  if (!g.ok || !isAccUrl(subject)) return resolveSubjectOnline({ grant: a.grant, asserted: a.asserted, expectType: a.expectType, registries: {}, subjectBooks: [] });
  const subjectBooks = await guarded(() => reader.authorities(subject));
  const registry = await readAccount(reader, grantorAdi + '/' + SUBJECTS_ACCOUNT);
  const acceptance = await readAccount(reader, subject + '/' + ACCEPTANCES_ACCOUNT);
  const toEntries = (e: DataEntry[] | null) => (e === null ? null : e.map((x) => ({ elements: x.elements, ...(x.time === undefined ? {} : { entryTime: x.time }) })));
  const acceptanceAbsent = acceptance.authorities === null && acceptance.history === null && acceptance.entries === null;
  return resolveSubjectOnline({
    grant: a.grant,
    asserted: a.asserted,
    expectType: a.expectType,
    registries: registry.entries === null ? { [grantorAdi]: null } : { [grantorAdi]: { account: { ownerBook: grantorBook, authorities: registry.authorities, history: registry.history, incomplete: registry.incomplete }, entries: toEntries(registry.entries) } },
    acceptances: acceptanceAbsent ? null : { account: { ownerBook: (acceptance.authorities ?? [])[0] ?? null, authorities: acceptance.authorities, history: acceptance.history, incomplete: acceptance.incomplete }, entries: toEntries(acceptance.entries) ?? [] },
    subjectBooks: subjectBooks ?? null,
    safeAfter: a.safeAfter ?? SAFE_AFTER,
  });
}

// ---- OFFLINE / ADVISORY helpers: they read key pages; an online path never calls them -------------------------------

type Snapshot = { ok: true; chain: ChainSnapshot; subjectBooks: string[] } | { ok: false; reason: 'authority_unreadable'; detail: string };

/** OFFLINE or ADVISORY: reads the key pages NOW for the pack check or the head advisory. Never an online gate. */
export async function snapshotFor(reader: AccumulateReader, a: { dataAccount: string; ownerBook: string; subjectAdi: string }): Promise<Snapshot> {
  const unreadable = (detail: string): Snapshot => ({ ok: false, reason: 'authority_unreadable', detail });
  if (reader.keyBookPages === undefined) return unreadable('reader offers no key pages');
  const auths = await guarded(() => reader.authorities(a.dataAccount));
  if (auths === null) return unreadable('authorities ' + a.dataAccount);
  const subj = await guarded(() => reader.authorities(a.subjectAdi));
  if (subj === null) return unreadable('authorities ' + a.subjectAdi);
  const pages: ChainSnapshot['pages'] = {};
  for (const book of new Set([a.ownerBook, ...subj])) {
    const b = await guarded(() => reader.keyBookPages!(book));
    if (b === null) return unreadable('keyBookPages ' + book);
    for (const p of b) pages[p.url] = { book, keyHashes: [...p.keyHashes], threshold: p.threshold };
  }
  // the pages come from a real Accumulate key page, so the key hashes are over the stored key bytes (GR-42)
  return { ok: true, chain: { pages, dataAccountAuthorities: [...auths], keyHashConvention: 'accumulate' }, subjectBooks: [...subj] };
}

/** OFFLINE or ADVISORY: verifies a Grant envelope against the key pages NOW. The online reader reports this only as `headEnvelopeCurrent`. */
export async function verifyGrantEnvelopeViaReader(reader: AccumulateReader, grant: unknown, envelope: unknown): Promise<EnvelopeVerdict> {
  const g = validateGrant(grant);
  if (!g.ok) return { ok: false, reason: 'grant_malformed', detail: g.reason };
  const snap = await snapshotFor(reader, { dataAccount: g.grant.grantor.adi + '/' + GRANTS_ACCOUNT, ownerBook: g.grant.grantor.keyBook, subjectAdi: g.grant.subject.adi });
  if (!snap.ok) return snap;
  return verifyGrantEnvelope({ grant: g.grant, envelope, chain: snap.chain, subjectBooks: snap.subjectBooks });
}
