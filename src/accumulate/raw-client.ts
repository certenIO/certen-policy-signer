/**
 * RawAccumulateClient — Accumulate v3 via raw JSON-RPC (axios), bypassing the SDK's
 * typed client (whose internal circular deps are fragile under bundlers). Version-independent.
 * Signing still uses accumulate.js encoding (see signing.ts); only transport is raw here.
 */
import axios, { AxiosInstance } from 'axios';
import { AccumulateClient, PendingTxResult, SignerInfo, SubmitResult } from './client.js';
import { Logger } from '../logger.js';

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
        executed,
        expired,
      };
    } catch (e) {
      this.logger.debug({ tx: hash, err: (e as Error).message }, 'getPendingTx: not found / query error');
      return { found: false };
    }
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

/** Split an Accumulate txID `acc://<hash>@<principal>` into its hash and principal parts. */
export function splitTxId(txId: string): { hash: string; principal: string } {
  const clean = String(txId ?? '').replace(/^acc:\/\//, '');
  const [hash, principal] = clean.split('@');
  return { hash: (hash ?? '').toLowerCase(), principal: principal ?? '' };
}

function classify(msg: string): SubmitResult['code'] {
  if (/signer version|bad.*version/i.test(msg)) return 'badSignerVersion';
  if (/credit/i.test(msg)) return 'insufficientCredits';
  if (/already|duplicate/i.test(msg)) return 'alreadySigned';
  if (/expired/i.test(msg)) return 'expired';
  return 'error';
}
