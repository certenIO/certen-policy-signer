/**
 * Officer signature intake. FICTIONAL Business Transaction Controls lab, Phase 7.
 * Contract: transaction-controls docs/interfaces/phase7-personal-signing-contract.md §4.
 *
 * No human key is ever in this process (§1, P3). A person's own device signs; this signer (P2) is the only
 * component that reads the chain and submits:
 *
 *   GET  /relay/officer/pending/:ref          officer-authenticated view of a tx or a proposal
 *   POST /relay/officer-signature/prepare     officer-authenticated; returns the exact sigMdHash + txHash to sign
 *   POST /relay/officer-signature             self-authenticating: {prepareId, signature}; verify, submit, poll
 *   (POST /relay/governance/proposal lives in relay-clients.ts and calls `propose` here)
 *
 * Fail closed throughout: a prepare record is single use and bound to key, ref, vote, page, delegators, signer
 * version and timestamp; the intake re-reads every page, recomputes every hash and verifies the signature
 * before anything is submitted. Any doubt is a refusal, and a refused signature is never submitted.
 */
import type http from 'node:http';
import { randomUUID } from 'node:crypto';
import { core } from '../accumulate/sdk.js';
import {
  buildDelegatedSignatureObject, buildPreimage, buildSigMetaHash, buildSignatureObject, buildSubmitEnvelope,
  bytesToHex, computeTimestamp, concatBytes, hexToBytes, PreimageParams,
} from '../accumulate/signing.js';
import type { PendingTxResult, SignerInfo, SubmitResult, TxSignatures } from '../accumulate/client.js';
import type { KeyPageOp } from '../ops/keypage.js';
import type { PageState } from '../ops/rotate.js';
import type { PolicyRequest } from '../types.js';
import type { Logger } from '../logger.js';
import { ACC_URL, DOT_SEGMENT, readCapped, send } from '../relay.js';
import { buildProposalDisplay, proposalOperations, tclSummaryV1, withDisplay, DisplayPair } from '../display.js';
import { extractAcceptance, extractGovernance } from '../decode/facts.js';
import type { ActionSummary } from '../types.js';
import { checkKeyPageChange, KeyPageRefusal, operationsFromKeyPageOps } from '../ops/keypage-guard.js';
import { createOfficerAuthenticator, OFFICER_AUTH_FAILED } from './auth.js';
import { P256Key, hexBytes, parseP256Spki, toCanonicalDer, verifyP256Sha256 } from './crypto.js';

export const PREPARE_TTL_MS = 10 * 60_000;
export const PROPOSAL_TTL_MS = 24 * 60 * 60_000;
export const SIGNATURE_INVALID = 'signature_invalid';
const MAX_DELEGATORS = 4;
const MAX_OPEN_PREPARES = 1000;
const MAX_OPEN_PROPOSALS = 1000;

export interface IntakeChain {
  getPendingTx(txHash: string, principal: string): Promise<PendingTxResult>;
  getSignerInfo(page: string): Promise<SignerInfo>;
  getTxSignatures?(txHash: string, principal: string): Promise<TxSignatures>;
  submit(envelope: unknown): Promise<SubmitResult>;
}

export interface OfficerIntakeDeps {
  humanPages: string[];
  chain: IntakeChain;
  readPage: (page: string) => Promise<PageState>;
  /** The stored PolicyRequest for a tx hash (the Console was asked about it). */
  getPolicyRequest: (txHash: string) => Promise<PolicyRequest | undefined>;
  /**
   * Store a request for a transaction this signer submitted that still awaits signatures (a proposal on a page
   * with threshold > 1), so further officers can sign it by tx ref. Absent => not recorded.
   */
  saveAwaiting?: (pr: PolicyRequest) => Promise<void>;
  /** Decode a body for a tx this signer never stored (intake-only). Absent => such refs are 404. */
  decode?: (body: { type: string; [k: string]: unknown }, principal: string) => { summary: ActionSummary; operationId?: string };
  labels?: Record<string, string>;
  landedTimeoutMs: number;
  pollIntervalMs?: number;
  now?: () => number;
  logger: Logger;
}

export interface Proposal {
  id: string;
  page: string;
  operations: KeyPageOp[];
  proposer: string;
  display: DisplayPair[];
  summaryHash: string;
  createdAt: number;
  expiresAt: number;
  /** `submitting`: one intake holds it between its checks and its submit; nothing else may prepare or submit it. */
  status: 'proposed' | 'submitting' | 'submitted' | 'landed';
  txHash?: string;
}

interface PrepareRecord {
  prepareId: string;
  kind: 'transaction' | 'proposal';
  ref: string;
  keyHash: string;
  spki: Uint8Array;
  page: string;
  delegators: string[];
  vote: 'approve' | 'reject';
  signerVersion: number;
  timestamp: number;
  principal: string;
  txHash: string;
  sigMdHash: string;
  proposalId?: string;
  display: DisplayPair[];
  summaryHash: string;
  expiresAt: number;
}

export type OfficerIntakeHandler = (req: http.IncomingMessage, res: http.ServerResponse, url: URL) => Promise<void>;

export interface OfficerIntake {
  handle: OfficerIntakeHandler;
  /** POST /relay/governance/proposal (authenticated by relay-clients.ts). */
  propose(page: string, operations: KeyPageOp[], proposer: string): Promise<{ status: number; body: unknown }>;
  /** For tests and diagnostics. */
  proposals(): Proposal[];
}

export const OFFICER_PATHS = (path: string): boolean =>
  path.startsWith('/relay/officer/') || path === '/relay/officer-signature' || path === '/relay/officer-signature/prepare';

const HEX64 = /^[0-9a-f]{64}$/;
const PROPOSAL_REF = /^proposal:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const sameUrl = (a: string, b: string) => a.toLowerCase().replace(/\/+$/, '') === b.toLowerCase().replace(/\/+$/, '');
const accUrlOk = (u: unknown): u is string => typeof u === 'string' && u.length <= 256 && ACC_URL.test(u) && !DOT_SEGMENT.test(u.slice(6));
const isPageUrl = (u: string) => /\/\d+\/?$/.test(u);
const bookOf = (page: string) => page.replace(/\/+$/, '').replace(/\/\d+$/, '');

export function createOfficerIntake(d: OfficerIntakeDeps): OfficerIntake {
  const now = d.now ?? Date.now;
  const pollMs = d.pollIntervalMs ?? 2_000;
  const authenticate = createOfficerAuthenticator({ humanPages: d.humanPages, readPage: d.readPage, now, logger: d.logger });
  const prepares = new Map<string, PrepareRecord>();
  const proposals = new Map<string, Proposal>();
  const isHumanPage = (u: string) => d.humanPages.some((h) => sameUrl(h, u));

  function sweep() {
    const t = now();
    for (const [k, r] of prepares) if (r.expiresAt <= t) prepares.delete(k);
    for (const [k, p] of proposals) if (p.expiresAt <= t) proposals.delete(k);
  }

  /** Parse `ref` into a tx hash or a live proposal. */
  function parseRef(ref: unknown): { kind: 'transaction'; hash: string } | { kind: 'proposal'; proposal?: Proposal } | undefined {
    if (typeof ref !== 'string') return undefined;
    const r = ref.toLowerCase();
    if (HEX64.test(r)) return { kind: 'transaction', hash: r };
    const m = PROPOSAL_REF.exec(r);
    if (m) return { kind: 'proposal', proposal: proposals.get(m[1]) };
    return undefined;
  }

  /** The view of a tx: the stored PolicyRequest, or (intake-only, principal given) a live decode. */
  async function txView(hash: string, principal: string | undefined): Promise<PolicyRequest | undefined> {
    const stored = await d.getPolicyRequest(hash);
    if (stored) {
      if (principal && !sameUrl(principal, stored.account)) return undefined;
      return stored.display && stored.summaryHash ? stored : withDisplay(stored, { labels: d.labels });
    }
    if (!principal || !d.decode) return undefined;
    const p = await d.chain.getPendingTx(hash, principal);
    if (!p.found || !p.body) return undefined;
    const body = p.body;
    const acct = p.principal || principal;
    if (!sameUrl(acct, principal)) return undefined;
    const { summary, operationId } = d.decode(body, acct);
    const governance = extractGovernance(body, acct);
    const acceptance = extractAcceptance(body, acct);
    return withDisplay({
      requestId: randomUUID(), txHash: hash, ...(operationId ? { operationId } : {}), account: acct,
      chain: summary.chain, actionSummary: summary.action, target: summary.target, value: summary.value, values: summary.values,
      unpricedLegs: summary.unpricedLegs, calldataDecoded: summary.calldataDecoded, bodyType: body.type,
      ...(summary.assets ? { assets: summary.assets } : {}),
      ...(governance ? { governance } : {}), ...(acceptance ? { acceptance } : {}),
      ...(p.header?.header ? { header: p.header.header } : {}),
      expiresAt: new Date(now()).toISOString(),
    }, { labels: d.labels });
  }

  async function txStatus(hash: string, principal: string): Promise<string> {
    const p = await d.chain.getPendingTx(hash, principal).catch(() => ({ found: false, unavailable: true } as PendingTxResult));
    if (p.unavailable) return 'unknown';
    if (!p.found) return 'not_found';
    if (p.executed) return 'executed';
    if (p.expired) return 'expired';
    return 'pending';
  }

  /**
   * Live authority checks (fresh reads, no cache): the key sits on `page`; each delegator lists the previous
   * book as a delegate (delegators[0] wraps the key signature, as buildSigMetaHash wraps them); the outermost
   * signing page is a human page this signer serves. Returns the reason on refusal.
   */
  async function checkAuthority(keyHash: string, page: string, delegators: string[]): Promise<string | undefined> {
    try {
      const st = await d.readPage(page);
      if (!st.keyHashes.map((h) => h.toLowerCase()).includes(keyHash)) return 'key_not_on_page';
      let prevBook = bookOf(page);
      for (const del of delegators) {
        const ds = await d.readPage(del);
        if (!ds.entries.some((e) => e.delegate && sameUrl(e.delegate, prevBook))) return 'delegation_not_on_page';
        prevBook = bookOf(del);
      }
    } catch (e) {
      d.logger.warn({ page, err: (e as Error).message }, 'officer intake: page unreadable');
      return 'page_unreadable';
    }
    const outermost = delegators.length ? delegators[delegators.length - 1] : page;
    if (!isHumanPage(outermost)) return 'not_a_human_page';
    return undefined;
  }

  /**
   * G-65: would approving this change brick the page it changes? Read the page NOW (never a cached copy);
   * an unreadable page is a refusal (`page_unreadable`), never an assumption.
   *
   * Only an APPROVE can carry a change towards execution, so only an approve is checked. A reject vote on a
   * change that would brick the page is exactly what a human should be able to cast, and refusing it would
   * protect nothing.
   */
  async function proposalRefusal(p: Proposal): Promise<KeyPageRefusal | undefined> {
    const v = await checkKeyPageChange(d.readPage, p.page, operationsFromKeyPageOps(p.operations));
    return v.ok ? undefined : v.refusal;
  }
  async function bodyRefusal(body: { type: string; [k: string]: unknown } | undefined, principal: string): Promise<KeyPageRefusal | undefined> {
    if (!body) {
      return { reason: 'unrecognized_operation', page: principal, message: 'the transaction body could not be read, so whether it changes a key page cannot be shown' };
    }
    if (body.type !== 'updateKeyPage') return undefined;
    const g = extractGovernance(body, principal);
    const v = await checkKeyPageChange(d.readPage, principal, g?.operations ?? [{ type: 'unknown', unrecognized: true }]);
    return v.ok ? undefined : v.refusal;
  }
  const refusalStatus = (r: KeyPageRefusal) => (r.reason === 'page_unreadable' ? 503 : 400);

  function sigParams(r: Pick<PrepareRecord, 'spki' | 'page' | 'signerVersion' | 'timestamp' | 'vote' | 'delegators'>): PreimageParams {
    return {
      publicKey: r.spki, signatureType: 'ecdsaSha256', signerUrl: r.page, signerVersion: r.signerVersion,
      timestamp: r.timestamp, vote: r.vote, ...(r.delegators.length ? { delegators: r.delegators } : {}),
    };
  }

  function proposalTx(p: Proposal, initiator: Uint8Array) {
    const operation = proposalOperations(p.operations).map((o) => {
      const entry = o.entry as Record<string, string> | undefined;
      if (entry?.keyHash) return { ...o, entry: { keyHash: hexToBytes(entry.keyHash) } };
      return o;
    });
    return new core.Transaction({ header: { principal: p.page, initiator }, body: { type: 'updateKeyPage', operation } });
  }

  async function readJson(req: http.IncomingMessage): Promise<Record<string, unknown> | undefined> {
    const raw = await readCapped(req, 16 * 1024);
    if (raw === null) return undefined;
    try {
      const b = JSON.parse(raw);
      return b && typeof b === 'object' && !Array.isArray(b) ? b : undefined;
    } catch { return undefined; }
  }

  async function pendingRoute(req: http.IncomingMessage, res: http.ServerResponse, url: URL, refRaw: string) {
    if (req.method !== 'GET') return send(res, 405, { error: 'method not allowed' });
    const officer = await authenticate(req);
    if (!officer) return send(res, 401, { error: OFFICER_AUTH_FAILED });
    sweep();
    const ref = parseRef(decodeURIComponent(refRaw));
    if (!ref) return send(res, 400, { error: 'ref must be a 64-hex transaction hash or proposal:<id>' });
    if (ref.kind === 'proposal') {
      const p = ref.proposal;
      if (!p) return send(res, 404, { error: 'not found' });
      return send(res, 200, {
        ref: `proposal:${p.id}`, kind: 'proposal', principal: p.page, page: p.page, bodyType: 'updateKeyPage',
        display: p.display, summaryHash: p.summaryHash, expiresAt: new Date(p.expiresAt).toISOString(), status: p.status,
        ...(p.txHash ? { txHash: p.txHash } : {}),
      });
    }
    const principal = url.searchParams.get('principal') ?? undefined;
    if (principal !== undefined && !accUrlOk(principal)) return send(res, 400, { error: 'principal must be an acc:// account URL' });
    const pr = await txView(ref.hash, principal);
    if (!pr) return send(res, 404, { error: 'not found' });
    return send(res, 200, {
      ref: ref.hash, kind: 'transaction', principal: pr.account, bodyType: pr.bodyType ?? 'unknown',
      display: pr.display, summaryHash: pr.summaryHash,
      ...(pr.header?.expiresAt ? { expiresAt: pr.header.expiresAt } : {}),
      status: await txStatus(ref.hash, pr.account),
    });
  }

  async function prepareRoute(req: http.IncomingMessage, res: http.ServerResponse) {
    if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
    const officer = await authenticate(req);
    if (!officer) return send(res, 401, { error: OFFICER_AUTH_FAILED });
    sweep();
    const b = await readJson(req);
    if (!b) return send(res, 400, { error: 'body must be a JSON object (≤ 16 KiB)' });
    const ref = parseRef(b.ref);
    if (!ref) return send(res, 400, { error: 'ref must be a 64-hex transaction hash or proposal:<id>' });
    if (!accUrlOk(b.page) || !isPageUrl(b.page)) return send(res, 400, { error: 'page must be an acc:// key page URL' });
    const page = b.page.replace(/\/+$/, '');
    const delegatorsRaw = b.delegators ?? [];
    if (!Array.isArray(delegatorsRaw) || delegatorsRaw.length > MAX_DELEGATORS || !delegatorsRaw.every((x) => accUrlOk(x) && isPageUrl(x))) {
      return send(res, 400, { error: `delegators must be an array of at most ${MAX_DELEGATORS} acc:// key page URLs` });
    }
    const delegators = (delegatorsRaw as string[]).map((x) => x.replace(/\/+$/, ''));
    if (b.vote !== 'approve' && b.vote !== 'reject') return send(res, 400, { error: "vote must be 'approve' or 'reject'" });
    const vote: 'approve' | 'reject' = b.vote;
    if (b.principal !== undefined && !accUrlOk(b.principal)) return send(res, 400, { error: 'principal must be an acc:// account URL' });
    if (prepares.size >= MAX_OPEN_PREPARES) return send(res, 429, { error: 'too many open prepares' });

    const keyHash = officer.key.keyHash;
    const refusal = await checkAuthority(keyHash, page, delegators);
    if (refusal) {
      d.logger.warn({ audit: 'officer_prepare_refused', keyHash, page, delegators, reason: refusal }, 'officer prepare refused');
      return send(res, 403, { error: refusal });
    }

    let info: SignerInfo;
    try { info = await d.chain.getSignerInfo(page); }
    catch { return send(res, 503, { error: 'signer page unreadable' }); }
    const timestamp = computeTimestamp(info.lastUsedOn, now() * 1000);
    const base = { spki: officer.key.spki, page, signerVersion: info.version, timestamp, vote, delegators };
    const sigMdHash = buildSigMetaHash(sigParams(base));

    let kind: PrepareRecord['kind'], refStr: string, principal: string, txHash: string, display: DisplayPair[], summaryHash: string, proposalId: string | undefined;
    if (ref.kind === 'proposal') {
      const p = ref.proposal;
      if (!p) return send(res, 404, { error: 'not found' });
      if (p.status !== 'proposed') return send(res, 409, { error: `proposal already ${p.status}` });
      if (vote !== 'approve') return send(res, 400, { error: 'a proposal is initiated by an approve signature; to reject it, do not sign' });
      // The initiator signs through a page of the book that governs the proposal's page.
      const outermost = delegators.length ? delegators[delegators.length - 1] : page;
      if (!sameUrl(bookOf(outermost), bookOf(p.page))) return send(res, 403, { error: 'signing page is not in the book that governs the proposal page' });
      // G-65: the page may have changed since the proposal was made; measure it again now.
      const brick = await proposalRefusal(p);
      if (brick) {
        d.logger.warn({ audit: 'officer_prepare_refused', keyHash, page, ref: `proposal:${p.id}`, refusal: brick }, 'officer prepare refused: the proposal would brick the page');
        return send(res, refusalStatus(brick), { error: brick.reason, refusal: brick });
      }
      const tx = proposalTx(p, sigMdHash);
      kind = 'proposal'; refStr = `proposal:${p.id}`; principal = p.page; proposalId = p.id;
      txHash = bytesToHex(tx.hash()); display = p.display; summaryHash = p.summaryHash;
    } else {
      const pr = await txView(ref.hash, b.principal as string | undefined);
      if (!pr || !pr.display || !pr.summaryHash) return send(res, 404, { error: 'not found' });
      const st = await txStatus(ref.hash, pr.account);
      if (st !== 'pending') return send(res, 409, { error: `transaction is ${st}` });
      if (vote === 'approve') {
        // G-65: decode the body the chain holds (not a stored summary) and refuse an approve that would brick the page.
        const live = await d.chain.getPendingTx(ref.hash, pr.account).catch(() => ({ found: false, unavailable: true } as PendingTxResult));
        if (live.unavailable || !live.found) return send(res, 503, { error: 'transaction state unreadable' });
        const brick = await bodyRefusal(live.body, live.principal || pr.account);
        if (brick) {
          d.logger.warn({ audit: 'officer_prepare_refused', keyHash, page, ref: ref.hash, refusal: brick }, 'officer prepare refused: the transaction would brick the key page');
          return send(res, refusalStatus(brick), { error: brick.reason, refusal: brick });
        }
      }
      kind = 'transaction'; refStr = ref.hash; principal = pr.account; txHash = ref.hash; display = pr.display; summaryHash = pr.summaryHash;
    }

    const rec: PrepareRecord = {
      prepareId: randomUUID(), kind, ref: refStr, keyHash, ...base, principal, txHash, sigMdHash: bytesToHex(sigMdHash),
      ...(proposalId ? { proposalId } : {}), display, summaryHash, expiresAt: now() + PREPARE_TTL_MS,
    };
    prepares.set(rec.prepareId, rec);
    d.logger.info({ audit: 'officer_prepare', prepareId: rec.prepareId, ref: refStr, keyHash, page, delegators, vote, txHash }, 'officer signature prepared');
    return send(res, 200, {
      prepareId: rec.prepareId, txHash, sigMdHash: rec.sigMdHash, signerVersion: rec.signerVersion, timestamp: rec.timestamp,
      principal, display, summaryHash, expiresAt: new Date(rec.expiresAt).toISOString(),
    });
  }

  async function intakeRoute(req: http.IncomingMessage, res: http.ServerResponse) {
    if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
    sweep();
    const b = await readJson(req);
    if (!b) return send(res, 400, { error: 'body must be a JSON object (≤ 16 KiB)' });
    if (typeof b.prepareId !== 'string') return send(res, 400, { error: 'prepareId required' });
    const rec = prepares.get(b.prepareId);
    if (!rec) return send(res, 404, { error: 'prepare not found or expired' });
    // Single use, whatever the outcome below: a refused attempt must prepare again.
    prepares.delete(rec.prepareId);

    const reject = (reason: string) => {
      d.logger.warn({ audit: 'officer_signature_rejected', prepareId: rec.prepareId, ref: rec.ref, keyHash: rec.keyHash, reason }, 'officer signature REJECTED; nothing submitted');
      return send(res, 400, { error: SIGNATURE_INVALID });
    };

    // Echoed fields, when a client sends them, must be exactly what was prepared.
    const echo: Array<[string, unknown, (v: unknown) => boolean]> = [
      ['ref', b.ref, (v) => typeof v === 'string' && v.toLowerCase() === rec.ref],
      ['vote', b.vote, (v) => v === rec.vote],
      ['timestamp', b.timestamp, (v) => v === rec.timestamp || v === String(rec.timestamp)],
      ['signerVersion', b.signerVersion, (v) => v === rec.signerVersion],
      ['txHash', b.txHash, (v) => typeof v === 'string' && v.toLowerCase() === rec.txHash],
      ['sigMdHash', b.sigMdHash, (v) => typeof v === 'string' && v.toLowerCase() === rec.sigMdHash],
      ['keyHash', b.keyHash, (v) => typeof v === 'string' && v.toLowerCase() === rec.keyHash],
      ['publicKey', b.publicKey, (v) => typeof v === 'string' && v.toLowerCase() === bytesToHex(rec.spki)],
      ['page', b.page, (v) => typeof v === 'string' && sameUrl(v, rec.page)],
      ['principal', b.principal, (v) => typeof v === 'string' && sameUrl(v, rec.principal)],
      ['summaryHash', b.summaryHash, (v) => v === rec.summaryHash],
      ['delegators', b.delegators, (v) => Array.isArray(v) && v.length === rec.delegators.length && v.every((x, i) => typeof x === 'string' && sameUrl(x, rec.delegators[i]))],
    ];
    for (const [name, v, ok] of echo) if (v !== undefined && !ok(v)) return reject(`tampered_${name}`);

    const sigBytes = hexBytes(b.signature, 128);
    if (!sigBytes) return reject('signature_not_hex');
    const der = toCanonicalDer(sigBytes);
    if (!der) return reject('signature_encoding');

    // A proposal is claimed SYNCHRONOUSLY, before the first await below, so two concurrent intakes for the same
    // proposal cannot both pass the open check and each submit a different updateKeyPage transaction.
    let proposal: Proposal | undefined;
    if (rec.kind === 'proposal') {
      proposal = rec.proposalId ? proposals.get(rec.proposalId) : undefined;
      if (!proposal || proposal.status !== 'proposed') return reject('proposal_not_open');
      proposal.status = 'submitting';
    }
    let submitted = false;
    try {
      return await intakeClaimed(res, rec, der, proposal, reject, () => { submitted = true; });
    } finally {
      // Any refusal or failed submit gives the proposal back.
      if (proposal && !submitted && proposal.status === 'submitting') proposal.status = 'proposed';
    }
  }

  async function intakeClaimed(
    res: http.ServerResponse, rec: PrepareRecord, der: Uint8Array, proposal: Proposal | undefined,
    reject: (reason: string) => void, markSubmitted: () => void,
  ) {
    // 2–3. Live authority, fresh reads.
    const refusal = await checkAuthority(rec.keyHash, rec.page, rec.delegators);
    if (refusal) return reject(refusal);

    // 4. Recompute sigMdHash from the bound fields, and the tx hash for a proposal, then verify.
    const key: P256Key | undefined = parseP256Spki(rec.spki);
    if (!key || key.keyHash !== rec.keyHash) return reject('key_mismatch');
    const params = sigParams(rec);
    const sigMd = buildSigMetaHash(params);
    if (bytesToHex(sigMd) !== rec.sigMdHash) return reject('sigmd_mismatch');
    let proposalTransaction: any;
    if (proposal) {
      if (tclSummaryV1(proposal.display) !== rec.summaryHash) return reject('summary_mismatch');
      proposalTransaction = proposalTx(proposal, sigMd);
      if (bytesToHex(proposalTransaction.hash()) !== rec.txHash) return reject('tx_hash_mismatch');
    }
    const txHashBytes = hexToBytes(rec.txHash);
    if (!verifyP256Sha256(key, concatBytes(sigMd, txHashBytes), der)) return reject('bad_signature');

    // 5. A transaction ref must still be pending at its principal.
    let rawTransaction: unknown;
    let pendingBody: { type: string; [k: string]: unknown } | undefined;
    let pendingPrincipal: string | undefined;
    if (rec.kind === 'transaction') {
      const p = await d.chain.getPendingTx(rec.txHash, rec.principal);
      if (p.unavailable) return send(res, 503, { error: 'transaction state unreadable; nothing submitted' });
      if (!p.found || p.executed || p.expired || !p.rawTransaction) {
        d.logger.warn({ audit: 'officer_signature_not_pending', ref: rec.ref, keyHash: rec.keyHash }, 'officer signature not submitted: transaction no longer pending');
        return send(res, 409, { error: 'transaction is no longer pending; nothing submitted' });
      }
      rawTransaction = p.rawTransaction;
      pendingBody = p.body;
      pendingPrincipal = p.principal;
    } else {
      rawTransaction = proposalTransaction.asObject();
    }

    // 5b. G-65, at the last moment and against a fresh read: an approve must not carry a change that would
    // brick the key page it changes. Nothing is submitted on a refusal.
    if (rec.vote === 'approve') {
      const brick = proposal
        ? await proposalRefusal(proposal)
        : await bodyRefusal(pendingBody, pendingPrincipal || rec.principal);
      if (brick) {
        d.logger.warn({ audit: 'officer_signature_refused', prepareId: rec.prepareId, ref: rec.ref, keyHash: rec.keyHash, refusal: brick }, 'officer signature REFUSED: the change would brick the key page; nothing submitted');
        return send(res, refusalStatus(brick), { error: brick.reason, refusal: brick });
      }
    }

    // 6. Submit.
    const pre = buildPreimage(txHashBytes, params);
    const sigObj = rec.delegators.length ? buildDelegatedSignatureObject(pre, der, rec.txHash) : buildSignatureObject(pre, der, rec.txHash);
    const sub = await d.chain.submit(buildSubmitEnvelope(rawTransaction, sigObj));
    if (!sub.ok) {
      d.logger.warn({ audit: 'officer_signature_submit_failed', ref: rec.ref, keyHash: rec.keyHash, code: sub.code, err: sub.error }, 'officer signature refused by the network');
      return send(res, 502, { error: 'submit_rejected', code: sub.code ?? 'error' });
    }
    markSubmitted();
    if (proposal) {
      proposal.status = 'submitted'; proposal.txHash = rec.txHash;
      await recordProposalAwaiting(proposal, rec);
    }
    d.logger.warn({ audit: 'officer_signature_submitted', ref: rec.ref, txHash: rec.txHash, keyHash: rec.keyHash, page: rec.page, delegators: rec.delegators, vote: rec.vote }, 'OFFICER SIGNATURE SUBMITTED');

    // 7. Poll until this key's signature is recorded.
    const status = await pollLanded(rec);
    if (proposal && status === 'landed') proposal.status = 'landed';
    return send(res, 200, { txHash: rec.txHash, status, page: rec.page, keyHash: rec.keyHash });
  }

  /**
   * A proposal on a page needing more than one signature does not execute on the initiator's signature. Record
   * it by tx hash with the proposal's own display and summaryHash (so a link carrying that hash stays valid),
   * so the next officer signs it as a transaction ref.
   */
  async function recordProposalAwaiting(p: Proposal, rec: PrepareRecord): Promise<void> {
    const txHash = rec.txHash;
    if (!d.saveAwaiting) return;
    try {
      // The threshold that governs execution is the SIGNING authority's: the outermost delegator, else the page that signed.
      const signingPage = rec.delegators.length ? rec.delegators[rec.delegators.length - 1] : rec.page;
      const st = await d.readPage(signingPage);
      if (st.threshold <= 1) return;
      const operations = proposalOperations(p.operations).map((o) => ({
        type: String(o.type), ...((o.entry ?? {}) as Record<string, string>), ...(o.threshold !== undefined ? { threshold: o.threshold } : {}),
      }));
      await d.saveAwaiting({
        requestId: `proposal:${p.id}`, txHash, signerUrl: p.page, account: p.page,
        actionSummary: `updateKeyPage on ${p.page} (proposal ${p.id}, awaiting further signatures)`,
        bodyType: 'updateKeyPage', governance: { kind: 'updateKeyPage', principal: p.page, operations },
        header: { principal: p.page }, display: p.display, summaryHash: p.summaryHash,
        expiresAt: new Date(p.expiresAt).toISOString(),
      });
      d.logger.info({ proposalId: p.id, txHash, page: p.page, signingPage, threshold: st.threshold }, 'proposal transaction awaits further signatures; recorded for officer intake');
    } catch (e) {
      d.logger.error({ proposalId: p.id, txHash, err: (e as Error).message }, 'could not record proposal transaction awaiting signatures');
    }
  }

  async function pollLanded(rec: PrepareRecord): Promise<'landed' | 'submitted'> {
    if (!d.chain.getTxSignatures) return 'submitted';
    const want = rec.delegators.map((x) => x.toLowerCase()).sort();
    const deadline = now() + d.landedTimeoutMs;
    for (;;) {
      const sigs = await d.chain.getTxSignatures(rec.txHash, rec.principal).catch(() => undefined);
      const hit = sigs?.signatures.some((s) => s.publicKeyHash === rec.keyHash
        && JSON.stringify(s.delegators.map((x) => x.toLowerCase()).sort()) === JSON.stringify(want));
      if (hit) return 'landed';
      if (now() + pollMs > deadline) return 'submitted';
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  async function propose(page: string, operations: KeyPageOp[], proposer: string): Promise<{ status: number; body: unknown }> {
    sweep();
    if (!isPageUrl(page)) return { status: 400, body: { error: 'page must be an acc:// key page URL' } };
    if (!d.humanPages.some((h) => sameUrl(bookOf(h), bookOf(page)))) {
      return { status: 403, body: { error: 'forbidden: page is not in a book whose human page this signer serves' } };
    }
    if (proposals.size >= MAX_OPEN_PROPOSALS) return { status: 429, body: { error: 'too many open proposals' } };
    // Simulate the operations against the page as it reads now (G-65, keypage-guard.ts): refuse what the
    // network would, and anything that would leave the page unsatisfiable. The same check runs again at
    // prepare and at intake, because the page can change in the 24 hours a proposal stays open.
    for (const o of operations) {
      if (o.op === 'add-delegate' && isPageUrl(o.delegate)) return { status: 400, body: { error: 'a delegate must be a key book, not a page' } };
      if (o.op === 'rotate-key') return { status: 400, body: { error: 'operation cannot be proposed' } };
    }
    const check = await checkKeyPageChange(d.readPage, page, operationsFromKeyPageOps(operations));
    if (!check.ok) {
      d.logger.warn({ audit: 'governance_proposal_refused', page, operations, proposer, refusal: check.refusal }, 'GOVERNANCE PROPOSAL REFUSED: the change would brick the page, or the page is unreadable');
      return { status: refusalStatus(check.refusal), body: { error: check.refusal.message, reason: check.refusal.reason, refusal: check.refusal } };
    }

    const display = buildProposalDisplay(page, operations, { labels: d.labels });
    const p: Proposal = {
      id: randomUUID(), page, operations, proposer, display, summaryHash: tclSummaryV1(display),
      createdAt: now(), expiresAt: now() + PROPOSAL_TTL_MS, status: 'proposed',
    };
    proposals.set(p.id, p);
    d.logger.warn({ audit: 'governance_proposal', proposalId: p.id, page, operations, proposer }, 'GOVERNANCE PROPOSAL CREATED (nothing signed or submitted)');
    return { status: 200, body: { proposalId: `proposal:${p.id}`, display, summaryHash: p.summaryHash } };
  }

  const handle: OfficerIntakeHandler = async (req, res, url) => {
    const path = url.pathname;
    const m = /^\/relay\/officer\/pending\/([^/]+)$/.exec(path);
    if (m) return pendingRoute(req, res, url, m[1]);
    if (path === '/relay/officer-signature/prepare') return prepareRoute(req, res);
    if (path === '/relay/officer-signature') return intakeRoute(req, res);
    return send(res, 404, { error: 'not found' });
  };

  return { handle, propose, proposals: () => [...proposals.values()] };
}
