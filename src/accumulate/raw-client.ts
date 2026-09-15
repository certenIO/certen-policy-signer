/**
 * RawAccumulateClient — Accumulate v3 via raw JSON-RPC (axios), bypassing the SDK's
 * typed client (whose internal circular deps are fragile under bundlers). Version-independent.
 * Signing still uses accumulate.js encoding (see signing.ts); only transport is raw here.
 */
import axios, { AxiosInstance } from 'axios';
import { createHash } from 'node:crypto';
import { AccumulateClient, ChainSignature, PendingTxResult, SignerInfo, SubmitResult, TxSignatures } from './client.js';
import { Logger } from '../logger.js';
import { extractTxHeader } from './header.js';

/**
 * Every signature message in a v3 transaction record, however deeply the node nests them.
 *
 * The shape is `signatures.records[].signatures.records[].message.signature`, and each level is a
 * paginated record set that may or may not be expanded — so this walks rather than indexes. A reader
 * that assumed one fixed depth would return nothing the first time the node nested differently, and
 * "no signatures" is precisely the answer that must never be produced by accident.
 */
function collectSignatureMessages(node: unknown, out: Record<string, unknown>[], depth = 0): void {
  if (!node || typeof node !== 'object' || depth > 8) return;

  // An array may BE the node, not only a value under a known key — `signatures` is sometimes the list
  // itself rather than `{ records: [...] }`. Walking only the named keys missed that entirely and
  // returned no signatures at all, which is the one wrong answer this function must never give.
  if (Array.isArray(node)) {
    for (const c of node) collectSignatureMessages(c, out, depth + 1);
    return;
  }

  const n = node as Record<string, unknown>;

  const message = n['message'] as Record<string, unknown> | undefined;
  if (message && typeof message === 'object' && message['signature']) out.push(message);

  for (const key of ['records', 'signatures', 'value', 'message']) {
    const child = n[key];
    if (Array.isArray(child)) for (const c of child) collectSignatureMessages(c, out, depth + 1);
    else if (child && typeof child === 'object') collectSignatureMessages(child, out, depth + 1);
  }
}

/**
 * Unwrap a delegated signature to the key that actually signed, recording the authorities on the way.
 *
 * A delegated signature nests — `{ type: 'delegated', delegator, signature: { … } }`, possibly several
 * deep. The public key is at the bottom; the delegators are the path taken to reach it. Both matter:
 * the key hash is what a page entry holds, and the delegators are what ties a signature to a seat the
 * roster recorded.
 */
function unwrapDelegation(sig: Record<string, unknown>): { inner: Record<string, unknown>; delegators: string[] } {
  const delegators: string[] = [];
  let inner = sig;
  for (let i = 0; i < 8; i++) {
    const delegator = inner['delegator'];
    if (typeof delegator === 'string' && delegator) delegators.push(delegator);
    const nested = inner['signature'];
    if (nested && typeof nested === 'object') inner = nested as Record<string, unknown>;
    else break;
  }
  return { inner, delegators };
}

export class RawAccumulateClient implements AccumulateClient {
  private http: AxiosInstance;
  constructor(private readonly endpoint: string, private readonly logger: Logger, timeoutMs = 15_000) {
    this.http = axios.create({ baseURL: endpoint, timeout: timeoutMs, headers: { 'content-type': 'application/json' } });
  }

  private async rpc<T = any>(method: string, params: unknown): Promise<T> {
    const res = await this.http.post('', { jsonrpc: '2.0', id: 1, method, params });
    if (res.data?.error) {
      const e = res.data.error;
      const err = new Error(typeof e === 'string' ? e : e.message ?? JSON.stringify(e));
      (err as any).rpc = e;
      throw err;
    }
    return res.data?.result as T;
  }

  async query<T = any>(scope: string, query?: unknown): Promise<T> {
    return this.rpc<T>('query', { scope, query: query ?? { queryType: 'default' } });
  }

  async getPendingTx(txHash: string, signerUrl: string): Promise<PendingTxResult> {
    const hash = txHash.replace(/^0x/, '');
    const signer = signerUrl.replace(/^acc:\/\//, '');
    try {
      const rec: any = await this.query(`acc://${hash}@${signer}`);
      // v3 message record: { recordType:'message'|'txID', message:{ transaction }, status?, sequence? }
      const message = rec?.message ?? rec?.value?.message ?? rec;
      const rawTransaction = message?.transaction ?? rec?.transaction;
      const body = rawTransaction?.body;
      if (!rawTransaction || !body) return { found: false };
      const status: string = (rec?.status ?? '').toString();
      const executed = /delivered|executed/i.test(status);
      const expired = /expired/i.test(status);
      const principal = rawTransaction?.header?.principal ?? '';
      return {
        found: true,
        rawTransaction,
        body: { type: String(body.type ?? 'unknown'), ...body },
        principal: String(principal),
        // The header as Accumulate recorded it — principal, additional authorities, on-chain deadline,
        // memo — for every body type, not only CERTEN intents (decision 0028). Task 2.5.
        header: extractTxHeader(rawTransaction, String(principal)),
        executed,
        expired,
      };
    } catch (e) {
      // "The chain has no such record" and "we could not reach the chain" are different answers, and the
      // caller turns the first one into a TERMINAL status. Returning `found: false` for a timeout or a
      // 502 therefore retired live transactions on one bad query — silently, since this was logged at
      // debug. Only a definitive answer from the node counts as gone; everything else is retryable.
      const msg = (e as Error).message ?? String(e);
      if (isDefinitiveNotFound(msg)) {
        this.logger.debug({ tx: hash, err: msg }, 'getPendingTx: the chain reports no such record');
        return { found: false };
      }
      this.logger.warn({ tx: hash, err: msg }, 'getPendingTx: could not query the node — will retry');
      return { found: false, unavailable: true };
    }
  }

  /**
   * What the chain says about a transaction and the signatures on it. T32.
   *
   * The console cannot ask this itself — invariant F-1 keeps chain work in the signer — and until now
   * nothing asked it at all. So the record could say *the organisation signed in her name*, because our
   * own signer made that signature and knew which key it used, and could not say *she signed*, because
   * her certificate signs on chain and nobody read it back. Somebody was eventually going to read the
   * absence of an alarm as proof that she had.
   *
   * `publicKeyHash` is `sha256(publicKey)`, which is what a key page entry holds — so a caller can
   * compare a signature against a page, or against a seat the roster recorded. It is computed here
   * rather than passed raw because the console is forbidden from computing it, and a key hash it cannot
   * derive is one it cannot be tempted to derive.
   */
  async getTxSignatures(txHash: string, principal: string): Promise<TxSignatures> {
    const hash = txHash.replace(/^0x/, '');
    const scope = `acc://${hash}@${principal.replace(/^acc:\/\//, '')}`;

    let rec: any;
    try {
      rec = await this.query(scope);
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      // "No such record" is an answer; anything else is a failure to ask. A caller must never read the
      // second as "nobody signed" — the same distinction `getPendingTx` draws, for the same reason.
      this.logger.debug({ tx: hash, err: msg }, 'getTxSignatures: could not read the transaction');
      return { status: '', delivered: false, signatures: [], unavailable: msg };
    }

    const status = String(rec?.status ?? '');
    const messages: Record<string, unknown>[] = [];
    collectSignatureMessages(rec?.signatures ?? rec, messages);

    const signatures: ChainSignature[] = [];
    for (const message of messages) {
      const raw = message['signature'];
      if (!raw || typeof raw !== 'object') continue;
      const { inner, delegators } = unwrapDelegation(raw as Record<string, unknown>);

      const publicKey = inner['publicKey'];
      // No public key means an authority or a system signature rather than somebody signing. Counting
      // one would inflate "how many people signed this", which is the number a reader trusts most.
      if (typeof publicKey !== 'string' || publicKey === '') continue;

      const signerUrl = inner['signer'];
      signatures.push({
        type: String(inner['type'] ?? 'unknown'),
        publicKeyHash: createHash('sha256').update(Buffer.from(publicKey, 'hex')).digest('hex'),
        delegators,
        ...(typeof signerUrl === 'string' && signerUrl ? { signer: signerUrl } : {}),
      });
    }

    return { status, delivered: /delivered|executed/i.test(status), signatures };
  }

  async getSignerInfo(signerUrl: string): Promise<SignerInfo> {
    const rec: any = await this.query(signerUrl);
    const acct = rec?.account ?? rec?.value?.account ?? rec;
    const version = Number(acct?.version ?? 1);
    let lastUsedOn = 0;
    for (const k of acct?.keys ?? []) {
      const lu = Number(k?.lastUsedOn ?? 0);
      if (lu > lastUsedOn) lastUsedOn = lu;
    }
    return { version, lastUsedOn, creditBalance: Number(acct?.creditBalance ?? 0) };
  }

  async listPendingForSigner(signerUrl: string): Promise<string[]> {
    try {
      const res: any = await this.query(signerUrl, { queryType: 'pending', range: { expand: true } });
      const records: any[] = res?.records ?? res?.value ?? [];
      return records
        .map((r: any) => String(r?.id ?? r?.value?.id ?? r?.txID ?? '').replace(/^acc:\/\//, '').split('@')[0])
        .filter(Boolean);
    } catch (e) {
      this.logger.warn({ signer: signerUrl, err: (e as Error).message }, 'listPendingForSigner failed');
      return [];
    }
  }

  /**
   * Discover txs where we are an additional (header) authority, by walking the book's signature chain.
   *
   * The chain is paged from the newest entry backwards. A single fixed window is not safe: if more than
   * one page of signature entries lands between two polls, an older *still-pending* intent falls outside
   * the window and would never be discovered — the wallet would just never vote on it. So we page back
   * until a whole page yields no new signature requests, bounded by `maxEntries` to keep a poll cycle
   * cheap. Hitting that bound is logged, never silent.
   */
  async listPendingViaSignatureChain(bookUrl: string, maxEntries = 500, pageSize = 50): Promise<string[]> {
    const txIds = new Set<string>();
    try {
      for (let offset = 0; offset < maxEntries; offset += pageSize) {
        const res: any = await this.query(bookUrl, {
          queryType: 'chain',
          name: 'signature',
          range: { start: offset, count: pageSize, fromEnd: true, expand: true },
        });
        const records: any[] = res?.records ?? [];
        const before = txIds.size;
        for (const id of extractSignatureRequestTxIds(records)) txIds.add(id);
        // End of chain, or a full page that told us nothing new: stop walking back.
        if (records.length < pageSize) break;
        if (txIds.size === before) break;
        if (offset + pageSize >= maxEntries) {
          this.logger.warn({ book: bookUrl, maxEntries },
            'signature-chain walk hit its bound; older pending txs may not be visible this cycle');
        }
      }
    } catch (e) {
      this.logger.warn({ book: bookUrl, err: (e as Error).message }, 'listPendingViaSignatureChain failed');
      return [];
    }
    // A signatureRequest can reference a tx that has since executed/expired — confirm each is still pending.
    const out: string[] = [];
    for (const id of txIds) {
      const { hash, principal } = splitTxId(id);
      if (!hash) continue;
      const p = await this.getPendingTx(hash, principal || bookUrl).catch(() => ({ found: false } as PendingTxResult));
      if (p.found && !p.executed && !p.expired) out.push(hash);
    }
    return [...new Set(out)];
  }

  async submit(envelope: unknown): Promise<SubmitResult> {
    try {
      const res: any = await this.rpc('submit', { envelope });
      const arr = Array.isArray(res) ? res : [res];
      for (const s of arr) {
        const ok = s?.success ?? s?.status?.delivered ?? true;
        const errMsg: string = String(s?.status?.error?.message ?? s?.message ?? s?.error?.message ?? '');
        if (s?.success === false || (errMsg && !/^\s*$/.test(errMsg))) {
          return { ok: false, code: classify(errMsg), error: errMsg || 'submit rejected' };
        }
        if (!ok && errMsg) return { ok: false, code: classify(errMsg), error: errMsg };
      }
      return { ok: true, result: res };
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      return { ok: false, code: classify(msg), error: msg };
    }
  }
}

/**
 * Extract produced transaction IDs from `signatureRequest` records on a book's signature chain.
 * Faithful to certen-pending-service scanSignatureChains: keep `value.message.type==='signatureRequest'`,
 * read `value.produced.records[].value|id` (and fall back to `value.message.txID`). Pure — unit-tested
 * against the live Kermit record shape.
 */
export function extractSignatureRequestTxIds(records: any[]): string[] {
  const out = new Set<string>();
  for (const rec of records ?? []) {
    const value = rec?.value ?? rec;
    const message = value?.message ?? {};
    if (String(message?.type ?? '') !== 'signatureRequest') continue;
    const produced: any[] = value?.produced?.records ?? [];
    for (const p of produced) {
      const id = String(p?.value ?? p?.id ?? '');
      if (id) out.add(id);
    }
    if (message?.txID) out.add(String(message.txID));
  }
  return [...out];
}

/** One signature on a transaction, as the relay reports it. FACTS read off the record, nothing inferred. */
export interface RelaySignature {
  /** The key page (keyed signature) or originating page (authority signature). */
  signer: string;
  /** The book that page belongs to — the authority a header names. */
  book: string;
  type: string;
  vote: 'accept' | 'reject' | 'abstain';
  /** sha256(publicKey), which is what a key page entry holds. Absent for authority signatures. */
  keyHash?: string;
  delegators: string[];
  timestamp?: number | string;
}

export interface RelayTxRecord {
  txid: string;
  hash: string;
  status: string;
  statusNo: number | null;
  principal: string;
  header: { principal: string; authorities: string[]; expireAtTime?: string | number; memo?: string };
  body: unknown;
  signatures: RelaySignature[];
}

/** The book a page URL belongs to: `acc://org.acme/book/1` → `acc://org.acme/book`. */
function bookOfPage(page: string): string {
  const i = page.lastIndexOf('/');
  return i > 'acc://'.length ? page.slice(0, i) : page;
}

/**
 * v3 JSON omits the vote when it is the zero value (accept). Anything present and unrecognised is NOT
 * mapped to accept — an unreadable vote reported as an approval is the one wrong answer that matters —
 * so the signature is dropped by the caller instead.
 */
function readVote(v: unknown): RelaySignature['vote'] | undefined {
  if (v === undefined || v === null || v === 'accept' || v === 0) return 'accept';
  if (v === 'reject' || v === 1) return 'reject';
  if (v === 'abstain' || v === 2) return 'abstain';
  return undefined;
}

/**
 * Normalize a v3 transaction message record for the read-only relay (runbook Phase 5.3, decision P2).
 *
 * Uses the same signature walk and delegation unwrap as `getTxSignatures`, so the two can never disagree
 * about which signatures a record holds. Keyed signatures carry a key hash; authority signatures (the
 * network's record that a book's page reached its threshold) carry the originating page and authority
 * book and no key hash. Signatures that name no signer (system/partition signatures) are omitted.
 * The header is passed through as recorded — `expireAtTime` is not reinterpreted here.
 */
export function normalizeTxRecord(rec: any): RelayTxRecord {
  const message = rec?.message ?? rec?.value?.message ?? {};
  const tx = message?.transaction ?? rec?.transaction ?? {};
  const h = tx?.header && typeof tx.header === 'object' ? tx.header : {};
  const principal = typeof h.principal === 'string' ? h.principal : '';
  const txid = String(rec?.id ?? message?.id ?? '');
  const hash = (/^(?:acc:\/\/)?([0-9a-fA-F]{64})@/.exec(txid)?.[1] ?? '').toLowerCase();

  const header: RelayTxRecord['header'] = {
    principal,
    authorities: Array.isArray(h.authorities) ? h.authorities.filter((a: unknown): a is string => typeof a === 'string' && a !== '') : [],
  };
  const atTime = h.expire && typeof h.expire === 'object' ? h.expire.atTime : undefined;
  if (typeof atTime === 'string' || typeof atTime === 'number') header.expireAtTime = atTime;
  if (typeof h.memo === 'string' && h.memo !== '') header.memo = h.memo;

  const messages: Record<string, unknown>[] = [];
  collectSignatureMessages(rec?.signatures ?? [], messages);

  const seen = new Set<string>();
  const signatures: RelaySignature[] = [];
  for (const m of messages) {
    const raw = m['signature'];
    if (!raw || typeof raw !== 'object') continue;
    const { inner, delegators } = unwrapDelegation(raw as Record<string, unknown>);
    const type = String(inner['type'] ?? 'unknown');
    const vote = readVote(inner['vote']);
    if (!vote) continue;

    let entry: RelaySignature | undefined;
    const publicKey = inner['publicKey'];
    if (typeof publicKey === 'string' && publicKey !== '' && typeof inner['signer'] === 'string' && inner['signer']) {
      const signer = inner['signer'] as string;
      entry = {
        signer, book: bookOfPage(signer), type, vote,
        keyHash: createHash('sha256').update(Buffer.from(publicKey, 'hex')).digest('hex'),
        delegators,
      };
    } else if (typeof inner['origin'] === 'string' && inner['origin'] && typeof inner['authority'] === 'string' && inner['authority']) {
      // Authority signature: `delegator` is a list of the delegation path here, not a nested wrapper.
      const path = Array.isArray(inner['delegator']) ? (inner['delegator'] as unknown[]).filter((d): d is string => typeof d === 'string') : [];
      entry = { signer: inner['origin'] as string, book: inner['authority'] as string, type, vote, delegators: [...delegators, ...path] };
    }
    if (!entry) continue;
    const ts = inner['timestamp'];
    if (typeof ts === 'number' || (typeof ts === 'string' && ts !== '')) entry.timestamp = ts;

    // The same signature can appear under the signer's set and the principal's set; report it once.
    const key = JSON.stringify(entry);
    if (seen.has(key)) continue;
    seen.add(key);
    signatures.push(entry);
  }

  const statusNo = Number(rec?.statusNo);
  return {
    txid, hash, status: String(rec?.status ?? ''), statusNo: Number.isFinite(statusNo) && rec?.statusNo !== undefined ? statusNo : null,
    principal, header, body: tx?.body ?? null, signatures,
  };
}

/** Split an Accumulate txID `acc://<hash>@<principal>` into its hash and principal parts. */
export function splitTxId(txId: string): { hash: string; principal: string } {
  const clean = String(txId ?? '').replace(/^acc:\/\//, '');
  const [hash, principal] = clean.split('@');
  return { hash: (hash ?? '').toLowerCase(), principal: principal ?? '' };
}

/**
 * Does this query error mean "the chain has no such record", as opposed to "we could not ask"?
 *
 * Deliberately a whitelist: anything unrecognised — a timeout, ECONNREFUSED, a 502 from a load balancer,
 * an HTML error page — is treated as UNKNOWN and retried, because the cost of being wrong in that
 * direction is one more query, while the other direction abandons a transaction permanently.
 */
export function isDefinitiveNotFound(msg: string): boolean {
  return /not\s*found|does not exist|no such|unknown (record|transaction|url)/i.test(msg);
}

function classify(msg: string): SubmitResult['code'] {
  if (/signer version|bad.*version/i.test(msg)) return 'badSignerVersion';
  if (/credit/i.test(msg)) return 'insufficientCredits';
  if (/already|duplicate/i.test(msg)) return 'alreadySigned';
  if (/expired/i.test(msg)) return 'expired';
  return 'error';
}
