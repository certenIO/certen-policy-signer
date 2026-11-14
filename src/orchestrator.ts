/** The pipeline: trigger → resolve → decide → sign → submit, with idempotency + retries. */
import { randomUUID } from 'node:crypto';
import { AccumulateClient } from './accumulate/client.js';
import { sha256Hex } from './accumulate/signing.js';
import { Keyring } from './signer/keyring.js';
import { PolicyClient } from './policy/policy.js';
import { Store, humanRecordId } from './store/store.js';
import { Resolver } from './resolver.js';
import { Logger } from './logger.js';
import { VoteBackend, VoteResult, DirectVoteBackend } from './vote/backend.js';
import { Notifier, NotifyEvent, NULL_NOTIFIER } from './notify.js';
import { AttachmentKind, PendingRef, PolicyRequest, Receipt, ResolvedTx, SigningRequest } from './types.js';
import { headerDeadlinePassed } from './accumulate/header.js';
import { withDisplay } from './display.js';
import { bookOf, resolveWrapperPaths, sameUrl, workKey } from './delegation/path.js';
import { WrapperRegistry, wrapperOwning } from './registry/wrappers.js';
import { PageState } from './ops/rotate.js';
import { checkKeyPageChange, KeyPageRefusal } from './ops/keypage-guard.js';
import { finaliseHold, recordHold } from './store/pending-hold.js';
import { advanceAwaitingHuman } from './officer/landed.js';
import { AuthorityVote } from './accumulate/client.js';
import { WrapperCheck, targetsWrapper } from './delegation/wrapper.js';
import { isAdiUrl } from './core/grant-profile.js';
import { BindingOutcome, BindingRules, BindingRuntime, BoundDecision, verifyBinding } from './binding/verify.js';
import { PauseGate } from './binding/pause-store.js';
import { derivedSeat } from './binding/seats.js';
import { buildPresentedRequest, presentOptionsOf } from './binding/request.js';
import { refusalReceiptOf } from './binding/refusals.js';
import { JournalError } from './binding/journal.js';
import { policyBindingOf } from './binding/policy-binding.js';

/** The error a vote reports when the persisted pause stopped it at the moment of signing. */
const PAUSED_AT_CAST = 'paused';

/** One scope's seat: its id (every scope has one) and, when its decisions must be bound, the rules of that binding. */
export interface SeatRules {
  seat: string;
  binding?: BindingRules;
}

/** Who a signature is for, for the pause gate: the seat and every subject the transaction may be about (asserted, resolved). */
interface SignCtx {
  seat: string;
  subjects: Array<string | null>;
}

export interface OrchestratorOptions {
  submitRejectVote?: boolean;   // default false: deny => withhold signature (tx expires)
  maxBadVersionRetries?: number; // default 3
  policyTtlSeconds?: number;    // default 900
  /** SR4 local guard. Receives EVERY leg amount (`values`), not just the representative one, plus the
   *  count of legs whose amount could not be read at all. */
  guard?: (tx: { account: string; summary: string; value?: string; values?: string[]; unpricedLegs?: number }) => boolean;
  delegators?: string[];        // delegate attachment model: user page(s) delegating to our book
  /** Wrapper runbook, change 4: refuse an approval whose evidence has no valid `signatureData`. */
  requireSignatureData?: boolean;
  /** How long to read the chain for our own signature after a submit got no answer (default 30 s). */
  submitOutcomeTimeoutMs?: number;
}

/**
 * The rules one key page runs under, when they differ from the process defaults.
 *
 * A fleet rarely shares one rulebook: a trading agent and a treasury page belong on different engines,
 * under different ceilings. Overrides are keyed by page because that is what the poller already carries —
 * `PendingRef.signerUrl` IS the page the work was discovered for, so no extra plumbing is needed to know
 * whose rules apply.
 *
 * Every field is optional and falls back to the process default; a scope states only what differs.
 */
export interface ScopeRules {
  policy?: PolicyClient;
  guard?: OrchestratorOptions['guard'];
  submitRejectVote?: boolean;
}

export interface OrchestratorDeps {
  accumulate: AccumulateClient;
  /** The default policy client. Used for any page without an override. */
  policy: PolicyClient;
  keyring: Keyring;
  store: Store;
  resolver: Resolver;
  logger: Logger;
  /** How the vote reaches the chain. Defaults to DIRECT (submit to Accumulate ourselves). */
  votes?: VoteBackend;
  /** Outbound notifications. Best-effort and non-blocking by contract — see notify.ts. */
  notifier?: Notifier;
  /** Label carried on every notification so a receiver watching several signers can tell them apart. */
  orgId?: string;
  /** Per-page rule overrides, keyed by the page URL LOWERCASED. Absent pages use the defaults. */
  scopeRules?: Map<string, ScopeRules>;
  /**
   * The persisted pause (SR8, DECISION.md section 6), read before EVERY signature, a reject vote included. Absent = nothing is
   * paused (library and tests; index.ts always wires the persisted one). Replaces the in-memory `isPaused` boolean.
   */
  pauses?: PauseGate;
  /** Seat ids and binding rules, keyed by the page URL LOWERCASED. A page without an entry has a derived seat and no binding. */
  seats?: Map<string, SeatRules>;
  /** The nonce store and the world a bound decision is checked against. Required by any seat that configures `binding`. */
  binding?: BindingRuntime;
  /**
   * `sha256:` + hex of this signer's effective config (secrets removed), computed at startup. Stamped on
   * every PolicyRequest and Receipt so a decision names the signer configuration it was taken under (A6).
   */
  configVersion?: string;
  /** `decoders.labels`, shown beside addresses in the Phase 7 display (`PolicyRequest.display`). */
  displayLabels?: Record<string, string>;
  /**
   * G-65: read a key page off the chain at decision time. Before this signer approves an `updateKeyPage`
   * transaction it applies the body's operations to what this returns and refuses a change that would
   * leave the page unsatisfiable. Absent (or failing) => an `updateKeyPage` is never approved: the page
   * cannot be read, and the guard never assumes a page state.
   */
  readPage?: (page: string) => Promise<PageState>;
  /**
   * G-69: pages that are HUMAN-ONLY seats (`wallet.human_scopes`). Work found for them is resolved, stored
   * and decided like any other (a seat that configures `binding` has its decisions bound and its pause read first), but this
   * signer never signs for them -- approve or reject: a decision that needs a signature is recorded as
   * `awaiting_human`, and a person signs through officer intake. Not combinable with `wrapper`: a wrapper vote travels a
   * delegation path, a human-only page has none.
   */
  humanOnlyPages?: string[];
  /**
   * Wrapper mode (`attachment_model: wrapper`, wrapper runbook change 2). Present = this signer is a
   * delegate on enrolled wrapper pages, and every vote's path is derived per transaction from the human
   * signatures on it. Absent = every existing mode, unchanged.
   */
  wrapper?: WrapperModeOptions;
  options?: OrchestratorOptions;
  now?: () => number; // injectable clock (ms) for tests
}

export interface WrapperModeOptions {
  /** Our book (`acc://truststamp.acme/book`) and page (`…/book/1`). */
  ourBook: string;
  ourPage: string;
  /** Registry + on-chain check: may a path start at this page? Throws = unknown, and nothing is signed. */
  isEnrolledWrapperPage(page: string): Promise<boolean>;
  /** Every enrolled wrapper book: where to read when a reference carries no `wrapperBook` hint. */
  wrapperBooks(): Promise<string[]>;
  /**
   * The on-chain invariant (wrapper runbook, change 5): does this wrapper book still require our vote?
   * Checked for every path before the engine is asked. Absent = not checked (tests of other concerns only;
   * index.ts always wires it).
   */
  checkWrapper?(wrapperBook: string): Promise<WrapperCheck>;
  /** The same, for a transaction ON the wrapper: is it still valid after the change executes? */
  checkWrapperChange?(wrapperBook: string, tx: ResolvedTx): Promise<WrapperCheck>;
  /**
   * Enrolment (wrapper runbook, change 6): the registry to recognise a wrapper being created and to record
   * seats, and a page reader to confirm a seat on chain. Absent = enrolment votes are not recognised and
   * every vote's seat is refused (fail closed).
   */
  registry?: WrapperRegistry;
  readPage?(url: string): Promise<PageState>;
}

/**
 * Does this UpdateKeyPage make `book` a NEW OWNER of the page — an `add` whose entry delegates to it, or an
 * `update` whose new entry does (`chain/update_key_page.go:362-378`)? Matched EXACTLY: the network accepts
 * a new owner's authority signature only when it names that very URL (`chain/utils.go:24`), so an entry
 * naming a page of the book would wait forever for a signature nobody can send.
 */
function addsDelegate(tx: ResolvedTx, book: string): boolean {
  return tx.governance?.kind === 'updateKeyPage' && tx.governance.operations.some((op) =>
    (op.type === 'add' && typeof op.delegate === 'string' && sameUrl(op.delegate, book))
    || (op.type === 'update' && typeof op.newDelegate === 'string' && sameUrl(op.newDelegate, book)));
}

/** The same test on a raw body, for discovery (before the resolver has produced governance facts). */
function bodyAddsDelegate(body: { type: string; [k: string]: unknown } | undefined, book: string): boolean {
  if (body?.type !== 'updateKeyPage' || !Array.isArray(body['operation'])) return false;
  return (body['operation'] as Array<Record<string, any>>).some((op) =>
    (op?.type === 'add' && typeof op?.entry?.delegate === 'string' && sameUrl(op.entry.delegate, book))
    || (op?.type === 'update' && typeof op?.newEntry?.delegate === 'string' && sameUrl(op.newEntry.delegate, book)));
}

/** At most this many enrolment rows are checked per settlement pass, so a backlog cannot stall anything. */
const SETTLE_BATCH = 50;
/** A signed enrolment tx the node keeps reporting as not found is given up on after this many passes. */
const SETTLE_MAX_MISSING = 20;

/** The receipt's key fields: `workKey` only when it differs from the hash, so existing receipts keep their shape. */
function receiptKey(tx: { txHash: string; workKey?: string }): { txHash: string; workKey?: string } {
  return { txHash: tx.txHash, ...(tx.workKey && tx.workKey !== tx.txHash ? { workKey: tx.workKey } : {}) };
}

export class Orchestrator {
  private readonly opt: Required<Pick<OrchestratorOptions, 'maxBadVersionRetries' | 'policyTtlSeconds' | 'submitRejectVote'>> & OrchestratorOptions;
  private readonly now: () => number;
  private readonly votes: VoteBackend;
  private readonly notifier: Notifier;
  private readonly humanOnly: Set<string>;

  constructor(private readonly d: OrchestratorDeps) {
    this.humanOnly = new Set((d.humanOnlyPages ?? []).map((p) => p.toLowerCase().replace(/\/+$/, '')));
    if (this.humanOnly.size > 0 && d.wrapper) throw new Error('orchestrator: human-only seats and wrapper mode cannot be combined (a wrapper vote travels a delegation path; a human-only page has none)');
    this.opt = {
      submitRejectVote: d.options?.submitRejectVote ?? false,
      maxBadVersionRetries: d.options?.maxBadVersionRetries ?? 3,
      policyTtlSeconds: d.options?.policyTtlSeconds ?? 900,
      guard: d.options?.guard,
      delegators: d.options?.delegators,
      requireSignatureData: d.options?.requireSignatureData,
    };
    this.now = d.now ?? Date.now;
    // A seat that configures `binding` cannot run without the nonce store: a missing one would sign unbound decisions. Nor without the pin gate
    // (a seat with no pin decides nothing, DE-93) or the refusal receipts (a refusal is a journal entry, DE-97).
    for (const [page, s] of d.seats ?? []) {
      if (s.binding && !d.binding) throw new Error(`orchestrator: ${page} configures binding but no nonce store is wired`);
      if (s.binding && d.binding && (!d.binding.pins || !d.binding.refusals)) throw new Error(`orchestrator: ${page} configures binding but no ${!d.binding.pins ? 'policy pin gate' : 'refusal receipt log'} is wired`);
    }
    this.notifier = d.notifier ?? NULL_NOTIFIER;
    this.votes = d.votes ?? new DirectVoteBackend(d.accumulate, d.keyring, d.logger, {
      maxBadVersionRetries: this.opt.maxBadVersionRetries,
      delegators: this.opt.delegators,
      now: this.now,
      ...(d.options?.submitOutcomeTimeoutMs ? { submitOutcomeTimeoutMs: d.options.submitOutcomeTimeoutMs } : {}),
    });
  }

  /**
   * The policy engine, local guard, and reject-vote behavior for the page this work belongs to.
   *
   * Falls back field by field rather than all-or-nothing: a scope that overrides only its ceiling keeps
   * the default engine. Matching is case-insensitive because an Accumulate URL is, and a scope written
   * `acc://Agent.acme/book/1` in config must still match the `acc://agent.acme/book/1` the node reports —
   * a miss here would silently run that page under the DEFAULT rules, which is the exact failure the
   * feature exists to prevent.
   */
  private rulesFor(signerUrl: string): Required<Pick<ScopeRules, 'policy' | 'submitRejectVote'>> & Pick<ScopeRules, 'guard'> {
    const o = this.d.scopeRules?.get(signerUrl.toLowerCase());
    return {
      policy: o?.policy ?? this.d.policy,
      guard: o?.guard !== undefined ? o.guard : this.opt.guard,
      submitRejectVote: o?.submitRejectVote ?? this.opt.submitRejectVote,
    };
  }

  /** The seat of a page: its configured one, or the one derived from the page URL. Every scope has one. */
  private seatOf(signerUrl: string): SeatRules {
    return this.d.seats?.get(signerUrl.toLowerCase()) ?? { seat: derivedSeat(signerUrl) };
  }

  /**
   * The subject of a transaction for the pause gate, as an ADI the pause state can name, or null. An asserted subject is a
   * CLAIM of the producer (a seat that requires a Grant also has the registry-resolved one): a lower-case ADI without a trailing
   * slash is the form a pause names, and anything that is not an ADI is no subject for it.
   */
  private subjectAdi(raw: string | undefined): string | null {
    if (raw === undefined) return null;
    const adi = raw.trim().toLowerCase().replace(/\/+$/, '');
    return isAdiUrl(adi) ? adi : null;
  }

  /**
   * May this seat sign this vote? Read from the PERSISTED pause every time (a pause set a moment ago applies). A paused seat or
   * subject, and a pause state that cannot be read, sign nothing: a reject vote included, because a reject vote is a signature.
   */
  private pausedFor(ctx: SignCtx, vote: 'approve' | 'reject'): { reason: string; scope?: string; id?: string } | undefined {
    const pauses = this.d.pauses;
    if (pauses === undefined) return undefined;
    for (const subject of ctx.subjects.length > 0 ? ctx.subjects : [null]) {
      const v = pauses.check({ seat: ctx.seat, subject, vote });
      if (!v.ok) return v as { reason: string; scope?: string; id?: string };
    }
    return undefined;
  }

  /** Nothing is signed: the seat or the subject is paused, or the pause state cannot be read. The decision is NOT consumed by this. */
  private withholdPaused(key: string, txHash: string, decision: string, reason: string): Promise<SigningRequest> {
    this.d.logger.warn({ tx: txHash, decision, reason }, 'signing paused; withholding signature');
    return this.d.store.update(key, { status: 'awaiting_policy', lastError: reason });
  }

  /**
   * A decision the binding check refused (DE-10): the signer made no signature, cast no vote, cancelled nothing and called no
   * `submit`. The item stays retryable (`awaiting_policy`): the Console may issue a fresh decision. The refusal is an
   * append-only receipt, not repeated while the same refusal stands (a poll every few seconds would otherwise write one per poll).
   */
  private async refuseBinding(tx: ResolvedTx, key: string, out: Extract<BindingOutcome, { ok: false }>, verb: string, seat: string): Promise<SigningRequest> {
    const reason = `binding: ${out.reason}`;
    this.d.logger.warn({ tx: tx.txHash, key, reason: out.reason, detail: out.detail, decision: verb }, 'decision refused by the binding check; signing nothing');
    // DE-97: the refusal receipt, the `binding.refused` entry of the journal: the request the signer built, the seat, the reason and, where they could be
    // read, the nonce of the refused decision and the transaction. A different decision (another nonce) refused for the same reason is a new receipt.
    const receipt = refusalReceiptOf({ requestHash: out.requestHash, seat, reason: out.reason, nonce: out.nonce, txHash: out.txHash });
    // The entry is durable before the answer, as the nonce store is. When the journal cannot be written (back-pressure, DE-47) the refusal STILL stands (nothing is
    // signed, nothing is consumed) and is recorded in the store, with the failure named on it, never skipped quietly and never turned into an allow.
    let journalled: string = 'written';
    const latest = await this.d.store.getReceipt(key);
    const le = latest?.policyEvidence;
    const lr = le?.['refusalReceipt'] as { nonce?: string } | undefined;
    const same = le?.['blockedBy'] === 'decision_binding' && le['reason'] === out.reason && (le['detail'] ?? null) === (out.detail ?? null) && (lr?.nonce ?? '') === (receipt.nonce ?? '');
    if (!same) {
      try {
        await this.d.binding!.refusals.record(receipt);
      } catch (e) {
        if (!(e instanceof JournalError)) throw e;
        journalled = `not_written: ${e.reason}${e.detail ? ' ' + e.detail : ''}`;
        this.d.logger.error({ tx: tx.txHash, reason: out.reason, journal: journalled }, 'the binding.refused receipt could not be written to the decision journal; the refusal stands (nothing was signed)');
      }
      await this.saveReceipt({
        ...this.receiptKey(tx), operationId: tx.operationId, reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: { blockedBy: 'decision_binding', reason: out.reason, ...(out.detail !== undefined ? { detail: out.detail } : {}), refusalReceipt: receipt, refusalJournal: journalled },
      });
    }
    return this.d.store.update(key, { status: 'awaiting_policy', lastError: reason });
  }

  /** Every receipt carries the signer-config version (A6). */
  private saveReceipt(r: Receipt): Promise<void> {
    return this.d.store.saveReceipt({ ...r, ...(this.d.configVersion ? { configVersion: this.d.configVersion } : {}) });
  }

  /** G-69: is `page` a human-only seat (no key here, ever)? */
  private isHumanOnly(page: string): boolean {
    return this.humanOnly.has(page.toLowerCase().replace(/\/+$/, ''));
  }

  /**
   * The RECORD KEY of a unit of work (review #1; wrapper runbook change 2): a human-only seat's own `<txHash>@<page>` record, so
   * its handling of a transaction can never pre-empt (or freeze) a keyed seat that must vote on the same transaction; a wrapper
   * path's `<txHash>:<path>`; else the tx hash, which is the key every existing record has. Works on a reference and on a
   * resolved transaction alike (a resolved one already carries its `workKey`).
   */
  private rid(r: { txHash: string; signerUrl: string; workKey?: string; delegators?: string[] }): string {
    if (this.isHumanOnly(r.signerUrl)) return humanRecordId(r.txHash, r.signerUrl);
    return r.workKey ?? workKey(r.txHash, r.delegators);
  }

  /** The receipt's key fields: `workKey` for a wrapper path, `recordId` for a human-only seat, each only when it differs from the hash. */
  private receiptKey(tx: { txHash: string; signerUrl: string; workKey?: string }): { txHash: string; workKey?: string; recordId?: string } {
    return { ...receiptKey(tx), ...(this.isHumanOnly(tx.signerUrl) ? { recordId: humanRecordId(tx.txHash, tx.signerUrl) } : {}) };
  }

  /**
   * Fire an outbound notification. Never throws and never awaited — a notification is a courtesy to the
   * operator's systems, not a step in the decision. See notify.ts for why this is the one place in the
   * codebase that does NOT fail closed.
   */
  private notify(event: NotifyEvent, tx: ResolvedTx | undefined, extra?: { reason?: string; error?: string; txHash?: string }): void {
    try {
      this.notifier.emit({
        event,
        at: new Date(this.now()).toISOString(),
        orgId: this.d.orgId ?? '',
        txHash: tx?.txHash ?? extra?.txHash,
        operationId: tx?.operationId,
        account: tx?.account,
        actionSummary: tx?.summary.action,
        chain: tx?.summary.chain,
        target: tx?.summary.target,
        values: tx?.summary.values,
        reason: extra?.reason,
        error: extra?.error,
      });
    } catch (e) {
      this.d.logger.warn({ event, err: (e as Error).message }, 'notifier threw (ignored)');
    }
  }

  /**
   * Every unit of work a pending-tx reference stands for, each handled once. What a trigger (poller,
   * push, retry) calls.
   *
   * Outside wrapper mode that is the reference itself, and this is exactly `handle`. In wrapper mode one
   * transaction can need a Trust Stamp vote on several paths — Alice's wrapper and Bob's — so the paths
   * are derived from the signatures on chain and each is handled as its own unit, in sequence (each
   * consumes our page's `lastUsedOn`, and two votes at once would race into a bad-version retry).
   */
  async handleAll(ref: PendingRef): Promise<SigningRequest[]> {
    if (!this.d.wrapper) return [await this.handle(ref)];
    const out: SigningRequest[] = [];
    for (const work of await this.wrapperWork(ref)) out.push(await this.handle(work));
    return out;
  }

  /**
   * The wrapper paths this transaction needs us on, as work items. Wrapper runbook, change 2.
   *
   * Fail closed at every step, and quietly: a transaction whose principal or signatures cannot be read
   * this cycle yields NO work, and the next poll asks again. Signing on a path guessed from partial
   * information is the one outcome that must not happen; waiting a cycle costs nothing.
   *
   * Trust Stamp's own page and book never show this work (a delegate gets no signature request, and the
   * vote is routed to the wrapper's book), so "nothing found for us" is the normal state, not a fault.
   */
  private async wrapperWork(ref: PendingRef): Promise<PendingRef[]> {
    const { accumulate, logger } = this.d;
    const w = this.d.wrapper!;
    let principal = ref.principal;
    if (!principal) {
      const p = await accumulate.getPendingTx(ref.txHash, ref.signerUrl);
      if (!p.found || !p.principal) {
        logger.debug({ tx: ref.txHash, unavailable: !!p.unavailable }, 'wrapper mode: principal unknown and not readable; nothing to do this cycle');
        return [];
      }
      principal = p.principal;
    }
    // Wrapper CREATION (change 6): the principal is a page of a wrapper the enrolment service registered,
    // and the body adds our book as a delegate. We vote as a new owner, directly on our page — there is no
    // path yet, because the entry that would make one is what this transaction creates. Everything is
    // re-checked from chain state in `run` before the engine is asked.
    const work: PendingRef[] = [];
    const owner = w.registry ? await wrapperOwning(w.registry, principal) : undefined;
    if (owner?.status === 'enrolling' && !sameUrl(principal, owner.wrapperBook)) {
      const p = await accumulate.getPendingTx(ref.txHash, principal);
      if (p.found && bodyAddsDelegate(p.body, w.ourBook)) {
        work.push({ txHash: ref.txHash, signerUrl: w.ourPage, principal, delegators: [], kind: 'wrapper_create', wrapperBook: owner.wrapperBook });
      }
    }
    if (!accumulate.getAuthoritySignatures) {
      logger.error({ tx: ref.txHash }, 'wrapper mode needs a client that reads authority signatures; signing nothing');
      return work;
    }
    // Read at each wrapper book's partition: that is where a person's book's vote through the wrapper is
    // recorded, and only after the network checked the delegation (see src/delegation/path.ts). One
    // unreadable book skips that book's paths and nothing else — each path stands on its own record.
    const books = ref.wrapperBook ? [ref.wrapperBook] : await w.wrapperBooks();
    const votes: AuthorityVote[] = [];
    for (const book of books) {
      const res = await accumulate.getAuthoritySignatures(ref.txHash, book);
      if (res.unavailable) {
        logger.warn({ tx: ref.txHash, book, err: res.unavailable }, 'wrapper mode: could not read the votes at this wrapper; leaving it for the next poll');
        continue;
      }
      if (res.delivered) {
        await this.closeDelivered(ref.txHash);
        return [];
      }
      votes.push(...res.votes);
    }
    let paths;
    try {
      paths = await resolveWrapperPaths(votes, w);
    } catch (e) {
      logger.warn({ tx: ref.txHash, err: (e as Error).message }, 'wrapper mode: enrolment could not be confirmed; signing nothing this cycle');
      return work;
    }
    if (!paths.length && !work.length) logger.debug({ tx: ref.txHash }, 'no person has approved through an enrolled wrapper yet');
    return [...work, ...paths.map((p) => ({ txHash: ref.txHash, signerUrl: w.ourPage, principal, delegators: p.path, wrapperBook: bookOf(p.wrapperPage) }))];
  }

  /**
   * Is the org page this vote travels to really holding the wrapper as a delegate? Wrapper runbook,
   * change 6, step 5.
   *
   * Read on EVERY vote, not only for an unrecorded seat: a seat the org removed would otherwise be
   * discovered only when the vote counted toward nothing. The page is `path[1]`, the hop after the
   * wrapper. A path with no such hop is not a seat at all and is refused: in this model a wrapper sits on
   * org PAGES as a delegate. A wrapper made a direct authority of an account (or added by
   * `UpdateAccountAuth`) is outside it, and is refused rather than voted through unchecked.
   *   - on chain and recorded      → go on;
   *   - on chain, not recorded     → record it (reconciled) and go on;
   *   - not on chain               → remove it if recorded, and refuse;
   *   - unreadable                 → refuse for now, retryable.
   */
  private async reconcileSeat(book: string, path: string[], txHash: string): Promise<WrapperCheck> {
    const w = this.d.wrapper!;
    const orgPage = path[1];
    if (!orgPage) return { ok: false, reason: `the path ${path.join(' > ')} names no org page for the wrapper to sit on` };
    if (!w.registry || !w.readPage) return { ok: false, reason: 'no seat registry is wired' };
    let st: PageState;
    try {
      st = await w.readPage(orgPage);
    } catch (e) {
      return { ok: false, reason: `cannot read ${orgPage}: ${(e as Error).message}`, unreadable: true };
    }
    const onChain = st.entries.some((e) => e.delegate !== null && sameUrl(e.delegate, book));
    const entry = await w.registry.get(book);
    const recorded = !!entry?.seats.some((s) => sameUrl(s.orgPage, orgPage));
    if (!onChain) {
      if (recorded) await w.registry.removeSeat(book, orgPage);
      return { ok: false, reason: `${orgPage} does not hold ${book} as a delegate` };
    }
    if (!recorded && entry) {
      await w.registry.addSeat(book, { orgPage, attachedTx: '', attachedAt: this.now() });
      this.d.logger.info({ tx: txHash, wrapper: book, orgPage }, 'seat found on chain that the registry had not recorded; reconciled');
    }
    return { ok: true };
  }

  /**
   * Bring the registry up to date with enrolment transactions we voted on. Wrapper runbook, change 6.
   *
   * ONLY after the transaction executed on chain — never on our vote alone, which is one signature of
   * several and proves nothing about the outcome. Called by the poller every cycle.
   *   wrapper_create executed → the wrapper becomes active, if the chain now shows a valid wrapper;
   *   seat_attach executed    → the seat is recorded, once the org page really holds the wrapper;
   *   expired                 → settled as failed; nothing recorded.
   */
  async settleEnrolments(): Promise<void> {
    const w = this.d.wrapper;
    if (!w?.registry) return;
    const { store, accumulate, logger } = this.d;
    const rows = (await store.listRecent(100_000, ['signed'])).map((r) => r.request)
      .filter((r) => (r.kind === 'wrapper_create' || r.kind === 'seat_attach') && !r.settled && r.principal)
      .slice(0, SETTLE_BATCH);
    for (const r of rows) {
      const key = r.workKey ?? r.txHash;
      const p = await accumulate.getPendingTx(r.txHash, r.principal!);
      if (p.unavailable) continue;
      if (!p.found) {
        const n = (r.settleAttempts ?? 0) + 1;
        await store.update(key, n >= SETTLE_MAX_MISSING ? { settled: 'failed', settleAttempts: n } : { settleAttempts: n });
        continue;
      }
      if (p.expired || p.failed) { await store.update(key, { settled: 'failed' }); continue; }
      if (!p.executed) continue;
      if (r.kind === 'wrapper_create') {
        const book = bookOf(r.principal!);
        const entry = await w.registry.get(book);
        const check = w.checkWrapper ? await w.checkWrapper(book) : { ok: false as const, reason: 'no wrapper check is wired' };
        if (!entry || !check.ok) {
          if (!check.ok && check.unreadable) continue;
          logger.error({ tx: r.txHash, wrapper: book, reason: !check.ok ? check.reason : 'not registered' }, 'wrapper creation executed but the wrapper does not pass the check; NOT activating it');
          await store.update(key, { settled: 'refused' });
          continue;
        }
        await w.registry.upsert({ ...entry, status: 'active', enrolledAt: this.now() });
        logger.info({ tx: r.txHash, wrapper: book }, 'wrapper creation executed; wrapper is now active');
      } else {
        const book = bookOf(r.delegators![0]!);
        if (!w.readPage) continue;
        let st: PageState;
        try { st = await w.readPage(r.principal!); } catch { continue; }
        if (!st.entries.some((e) => e.delegate !== null && sameUrl(e.delegate, book))) {
          logger.error({ tx: r.txHash, wrapper: book, orgPage: r.principal }, 'seat attach executed but the org page does not hold the wrapper; not recording a seat');
          await store.update(key, { settled: 'refused' });
          continue;
        }
        await w.registry.addSeat(book, { orgPage: r.principal!, attachedTx: r.txHash, attachedAt: this.now() });
        logger.info({ tx: r.txHash, wrapper: book, orgPage: r.principal }, 'seat attach executed; seat recorded');
      }
      await store.update(key, { settled: 'executed' });
    }
  }

  /**
   * The transaction executed. Any path of ours still open on it is finished — the resolver records an
   * executed transaction as `signed` the same way when it finds one gone, so these rows read alike. Left
   * open they would sit in every non-terminal list forever, since no trigger would reach them again.
   */
  private async closeDelivered(txHash: string): Promise<void> {
    for (const r of await this.d.store.listNonTerminal()) {
      if (r.txHash !== txHash) continue;
      await this.d.store.update(r.workKey ?? r.txHash, { status: 'signed', lastError: undefined });
    }
  }

  /** Handle one unit of work. Idempotent + single-flight per work key (the tx hash, or tx + path). */
  async handle(ref: PendingRef): Promise<SigningRequest> {
    // A wrapper vote's path is derived from chain state by `handleAll`, never assumed. A bare reference
    // here in wrapper mode would sign directly on our page, which counts toward nothing (or toward the
    // wrong thing), so it is refused as a programming error rather than guessed at.
    if (this.d.wrapper && !ref.delegators?.length && !(ref.kind === 'wrapper_create' && ref.delegators)) {
      throw new Error('wrapper mode: a transaction is handled per delegation path — call handleAll');
    }
    const { store, logger } = this.d;
    const key = this.rid(ref);
    const existing = await store.get(key);
    if (existing && ['signed', 'rejected', 'expired'].includes(existing.status)) {
      logger.debug({ tx: ref.txHash, key, status: existing.status }, 'idempotent skip');
      return existing;
    }
    if (!store.tryLock(key)) {
      logger.debug({ tx: ref.txHash, key }, 'already in-flight');
      return existing ?? (await this.ensure(ref, key));
    }
    try {
      return await this.run(ref, key);
    } finally {
      store.unlock(key);
    }
  }

  private async ensure(ref: PendingRef, key: string): Promise<SigningRequest> {
    const s = await this.d.store.get(key);
    if (s) return s;
    const req: SigningRequest = {
      // Only a path-keyed row carries a workKey and only a human-only seat's a recordId, so every other row keeps exactly the
      // shape it had.
      ...(this.isHumanOnly(ref.signerUrl) ? { recordId: key } : key !== ref.txHash ? { workKey: key } : {}),
      txHash: ref.txHash, signerUrl: ref.signerUrl, status: 'discovered',
      ...(ref.delegators ? { delegators: ref.delegators } : {}),
      ...(ref.principal ? { principal: ref.principal } : {}),
      ...(ref.kind ? { kind: ref.kind } : {}),
      attempts: 0, createdAt: this.now(), updatedAt: this.now(),
    };
    try {
      await this.d.store.create(req);
      return req;
    } catch {
      // lost a create race — return the row the winner created
      return (await this.d.store.get(key))!;
    }
  }

  private async run(ref: PendingRef, key: string): Promise<SigningRequest> {
    const { store, resolver, logger } = this.d;
    // Which page this work belongs to decides which engine answers for it and under which ceiling.
    const rules = this.rulesFor(ref.signerUrl);
    const priorStatus = (await store.get(key))?.status; // was this work already known? (gates the discovery log)
    await this.ensure(ref, key);

    // 1. Resolve
    const r = await resolver.resolve(ref);
    // Could not read it. Record nothing terminal about a transaction we failed to look at — leave the row
    // retryable so the next poll asks again once the node is back.
    if (r.kind === 'unavailable') {
      logger.warn({ tx: ref.txHash, err: r.error }, 'could not resolve pending tx; leaving it for the next poll');
      return store.update(key, { lastError: `resolve: ${r.error}` });
    }
    if (r.kind === 'gone') {
      const status = r.reason === 'executed' ? 'signed' : 'expired';
      logger.info({ tx: ref.txHash, reason: r.reason }, 'tx gone before signing');
      // G-64: a hold that ends because the transaction went away is still kept, with that as its outcome.
      return store.update(key, { status, ...finaliseHold(await store.get(key), `gone:${r.reason}`, this.now()) });
    }
    // The work key travels on the resolved transaction for a wrapper path; a human-only seat's record key is its `recordId` (see `rid`).
    const tx = { ...r.tx, ...(key !== r.tx.txHash && !this.isHumanOnly(ref.signerUrl) ? { workKey: key } : {}) };
    // G-69: the engine has already decided and a person owes the signature. Asking again on every poll
    // would rewrite the decision under them (and, for a seat that requires binding, would need a second decision and a second
    // nonce); the request ends when their signature lands (officer intake) or when the transaction goes away (handled just above).
    if (priorStatus === 'awaiting_human') {
      // ...but the chain is read on every poll (review #3): the people's signatures are counted against the
      // page's thresholds, so a signature that landed after officer intake stopped watching still ends it.
      logger.debug({ tx: ref.txHash }, 'awaiting a human signature through officer intake; reading the chain');
      const getTxSignatures = this.d.accumulate.getTxSignatures?.bind(this.d.accumulate);
      return (await advanceAwaitingHuman({ store, readPage: this.d.readPage, ...(getTxSignatures ? { getTxSignatures } : {}), logger, now: this.now }, ref.txHash, ref.signerUrl))
        ?? (await store.get(key))!;
    }
    await store.update(key, {
      status: 'awaiting_policy', account: tx.account, signerVersion: tx.signerVersion,
      actionSummary: tx.summary.action, operationId: tx.operationId,
    });
    // Discovery: a pending tx that names our book as a required authority. Logged once (first sighting),
    // not on every retry, so an operator can see WHAT was found and on WHICH account.
    if (!priorStatus || priorStatus === 'discovered') {
      logger.info(
        { tx: tx.txHash, account: tx.account, authority: ref.signerUrl, action: tx.summary.action },
        'discovered pending intent; our book is a required authority',
      );
      // Fired once, on first sighting, for the same reason the log line is: a notification on every poll
      // would text the operator every 20 seconds for the life of the transaction.
      this.notify('pending.discovered', tx);
    }

    // Decision 0031: never sign a transaction whose on-chain deadline has passed, nor one whose deadline
    // cannot be read. Checked before the engine is asked (there is nothing left to decide) and again
    // right before signing (the engine may have taken a while).
    const dead = this.deadlineRefusal(tx);
    if (dead) return this.refuseDeadline(tx, dead);

    // Wrapper runbook, change 5: our vote only means something while the wrapper requires it. Checked
    // here, per path, before the engine is asked — there is nothing to decide about a wrapper that can be
    // satisfied without us, and asking would prompt a person's live check for a vote that proves nothing.
    let kind: AttachmentKind | undefined;
    if (this.d.wrapper) {
      const w = this.d.wrapper;
      const creating = ref.kind === 'wrapper_create';
      const book = creating ? (ref.wrapperBook ?? bookOf(tx.account)) : bookOf(ref.delegators![0]!);
      // A seat attach is ONE hop: the wrapper is the new owner of the page the transaction changes. A longer
      // path to a page that happens to add the wrapper is an ordinary vote and gets the seat check.
      kind = creating ? 'wrapper_create'
        : !targetsWrapper(tx.account, book) && ref.delegators!.length === 1 && addsDelegate(tx, book) ? 'seat_attach' : 'vote';
      await store.update(key, { kind });
      let check: WrapperCheck;
      if (creating) {
        // Re-derived, not trusted from discovery: a registered wrapper, this page of it, a body that adds
        // our book — and the wrapper as it will be AFTER the change must pass the full check.
        const entry = w.registry ? await wrapperOwning(w.registry, tx.account) : undefined;
        check = !entry || entry.status !== 'enrolling' || !sameUrl(entry.wrapperBook, book) || !targetsWrapper(tx.account, book) || sameUrl(tx.account, book)
          ? { ok: false, reason: `${tx.account} is not a page of a wrapper being enrolled` }
          : !addsDelegate(tx, w.ourBook)
            ? { ok: false, reason: 'the transaction does not add Trust Stamp as a delegate' }
            : entry.subscriberBook && !addsDelegate(tx, entry.subscriberBook)
              ? { ok: false, reason: `the transaction does not add the registered subscriber book ${entry.subscriberBook}` }
            : w.checkWrapperChange ? await w.checkWrapperChange(book, tx) : { ok: false, reason: 'no check for changes to the wrapper is wired' };
      } else if (targetsWrapper(tx.account, book)) {
        check = w.checkWrapperChange ? await w.checkWrapperChange(book, tx) : { ok: false, reason: 'no check for changes to the wrapper is wired' };
      } else {
        check = w.checkWrapper ? await w.checkWrapper(book) : { ok: false, reason: 'no wrapper check is wired' };
        if (check.ok && kind === 'vote') check = await this.reconcileSeat(book, ref.delegators!, tx.txHash);
      }
      if (!check.ok) {
        // Could not READ the wrapper: no vote, and ask again next poll — an outage is not a verdict.
        if (check.unreadable) {
          logger.warn({ tx: tx.txHash, key, wrapper: book, err: check.reason }, 'wrapper state could not be confirmed; not signing this cycle');
          return store.update(key, { lastError: `wrapper_unreadable: ${check.reason}` });
        }
        const reason = `wrapper_invariant: ${check.reason}`;
        logger.warn({ tx: tx.txHash, key, wrapper: book, reason }, 'wrapper does not require our vote (or would not after this change); refusing to sign');
        await this.saveReceipt({
          ...this.receiptKey(tx), operationId: tx.operationId, reason,
          ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
          policyEvidence: { blockedBy: 'wrapper_invariant', wrapper: book, detail: check.reason },
        });
        this.notify('decision.denied', tx, { reason });
        return store.update(key, { status: 'rejected', lastError: reason });
      }
    }

    // 2. Decide
    // DAX-4S: a seat that requires binding tells the decision service the exact request the signer will bind (the ten members of the
    // core's request hash, the validator operation id among them, plus `legCount` and the intent's `grantRef`), so a service with no
    // chain access can build the same hash. A several-leg intent carries its `binding` too (`legCount` above 1): the decision service
    // refuses it by name (`multi_leg_unsupported`) and so does the signer's own check; neither side silently skips it. A transaction
    // the signer cannot read as an intent at all (no binding built) carries none, and its decision is refused later by name.
    const seat = this.seatOf(ref.signerUrl);
    const presentedBinding = seat.binding ? buildPresentedRequest(tx, presentOptionsOf(seat.binding)) : undefined;
    const policyReq: PolicyRequest = withDisplay({
      requestId: randomUUID(),
      txHash: tx.txHash,
      operationId: tx.operationId,
      // Which of our pages is asking. The wallet has always known -- it is how the poller found this
      // transaction -- and until F5 simply never passed it on.
      signerUrl: tx.signerUrl,
      // WHO the transaction is about, when the payload named someone. Spread rather than assigned: an
      // intent that named nobody must produce a request with NO `subject` key at all, because "absent"
      // and "unknown" are the same state and the signer has no business inventing the difference.
      ...(tx.summary.subject ? { subject: tx.summary.subject } : {}),
      account: tx.account,
      chain: tx.summary.chain,
      actionSummary: tx.summary.action,
      target: tx.summary.target,
      value: tx.summary.value,
      values: tx.summary.values,
      // Tells the engine whether `values` is the WHOLE picture. Without it, a partial list of amounts is
      // indistinguishable from a complete one, and the engine's own ceiling has the same blind spot ours had.
      unpricedLegs: tx.summary.unpricedLegs,
      calldataDecoded: tx.summary.calldataDecoded,
      // What the call GRANTS, beside what it moves. An engine gating only on `values` auto-approves an
      // unlimited spending authority, because an approve moves nothing at all. T18/T21.
      grant: tx.summary.grant,
      // The transaction's own header, read from Accumulate for every body type (task 2.5, F23): the
      // principal, the additional authorities Accumulate will enforce (the submitter chose them — a
      // required-party rule must check this list, A2), the ON-CHAIN deadline and the memo.
      header: tx.header,
      // Phase 6 seat contract §1. Spread so an absent fact is an absent key, never `undefined`.
      bodyType: tx.bodyType,
      ...(this.d.configVersion ? { configVersion: this.d.configVersion } : {}),
      ...(tx.summary.assets ? { assets: tx.summary.assets } : {}),
      // A body that provably carries no contract call (an acceptance, a governance body, or any non-WriteData body)
      // has selfCall=false and targetKnown=true. An undecoded WriteData leaves both absent, so rules stay indeterminate.
      ...(tx.summary.selfCall !== undefined ? { selfCall: tx.summary.selfCall } : noContractCall(tx) ? { selfCall: false } : {}),
      ...(tx.summary.targetKnown !== undefined ? { targetKnown: tx.summary.targetKnown } : noContractCall(tx) ? { targetKnown: true } : {}),
      ...(tx.governance ? { governance: tx.governance } : {}),
      ...(tx.acceptance ? { acceptance: tx.acceptance } : {}),
      // Wrapper mode: which person's wrapper this vote is for. Each path is its own question to the engine.
      ...(ref.delegators?.length ? { wrapper: { page: ref.delegators[0]!, path: [...ref.delegators] } } : {}),
      ...(kind === 'wrapper_create' ? { wrapper: { page: tx.account, path: [] } } : {}),
      ...(kind ? { attachmentKind: kind } : {}),
      ...(presentedBinding?.ok ? { binding: policyBindingOf(presentedBinding.value) } : {}),
      // DAX7C-F1: what actually executes, as a SIBLING of `binding` (never inside it), so a decision service can decode it instead of reading our
      // prose. Only for ONE mapped leg, already authenticated against the commitment; omitted (never null) otherwise.
      ...(presentedBinding?.ok && presentedBinding.value.execution !== null ? { execution: presentedBinding.value.execution } : {}),
      // Policy TTL for THIS request. Not the on-chain deadline, which is `header.expiresAt`.
      expiresAt: new Date(this.now() + this.opt.policyTtlSeconds * 1000).toISOString(),
    }, { labels: this.d.displayLabels });
    await store.update(key, { policyRequestId: policyReq.requestId });
    // Kept so a decision service can read back exactly what it was asked (`/relay/pending/:hash`, 6.4).
    // Under the work key: two wrapper paths on one tx are two questions, and one must not overwrite the
    // other. Outside wrapper mode the key is the hash, so the relay route reads it as before.
    await store.savePolicyRequest(policyReq, key);

    // The decision request, carried off chain to the operator's own policy engine. It holds the decoded
    // action plus every gate-relevant amount; the reply drives accept / reject / withhold.
    logger.info({ tx: tx.txHash, policyRequestId: policyReq.requestId, action: tx.summary.action }, 'requesting decision from policy engine');
    let decision;
    try {
      decision = await rules.policy.decide(policyReq);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      logger.warn({ tx: ref.txHash, err: msg }, 'policy decision failed');
      return store.update(key, {
        status: 'awaiting_policy', lastError: `policy: ${msg}`,
        attempts: (await store.get(key))!.attempts + 1,
      });
    }

    // The engine has not decided yet (out-of-band approval, step-up challenge, review queue). Withhold:
    // sign nothing, leave the tx pending on chain, ask again next poll. This is NOT an error — recording
    // it as one would bury a genuine engine fault under a stream of ordinary waiting, and would make a
    // slow human approval look identical to an outage on /healthz. Attempts are left alone for the same
    // reason: waiting is not a failed attempt.
    if (decision.decision === 'pending') {
      logger.info(
        { tx: ref.txHash, reason: decision.reason },
        'policy engine has not decided yet; withholding signature and will retry',
      );
      // G-64: keep WHY, and under which versions, on the record -- updated on every re-evaluation.
      const pending = recordHold(await store.get(key), decision, this.now());
      return store.update(key, { status: 'awaiting_policy', lastError: undefined, pending });
    }

    // G-64: the engine has decided; the hold (if there was one) ends here and is kept as history.
    {
      const fin = finaliseHold(await store.get(key), decision.decision, this.now());
      if (fin.pendingFinal) await store.update(key, fin);
    }

    // SR8 emergency pause — checked BEFORE the deny branch, because a Reject vote is still a SIGNATURE.
    // With `submit_reject_vote: true` (what every shipped config sets), leaving this check further down
    // meant a "paused" wallet went on signing and submitting rejections. Pause means sign NOTHING.
    // Now the PERSISTED pause (seat and subject scopes), read from the file each time (DAX-4S, DECISION.md section 6).
    const verb: 'approve' | 'reject' = decision.decision === 'deny' ? 'reject' : 'approve';
    const sign: SignCtx = { seat: seat.seat, subjects: [this.subjectAdi(tx.summary.subject?.adi)] };
    const stopped = this.pausedFor(sign, verb);
    if (stopped) return this.withholdPaused(key, ref.txHash, decision.decision, stopped.reason);

    // DAX-4S: the decision record is checked against the transaction ABOUT TO BE SIGNED, before ANY signature, a deny that would
    // become a reject vote included (DECISION.md section 4). A refusal is a refusal to sign and nothing else (DE-10): no vote,
    // no cancel, no `submit`. Only a seat that configures `binding` is bound; any other scope keeps the unbound legacy reply.
    let bound: BoundDecision | undefined;
    if (seat.binding) {
      const out = await verifyBinding({
        reply: decision as unknown as Record<string, unknown>, tx, rules: seat.binding, runtime: this.d.binding!,
        gate: (resolved) => {
          const adi = resolved ? this.subjectAdi(resolved.adi) : null;
          if (adi && !sign.subjects.includes(adi)) sign.subjects.push(adi);
          return this.pausedFor(sign, verb)?.reason;
        },
      });
      if (!out.ok) {
        if (out.reason === 'paused' || out.reason === 'pause_state_unreadable') return this.withholdPaused(key, ref.txHash, decision.decision, out.reason);
        return this.refuseBinding(tx, key, out, decision.decision, seat.seat);
      }
      bound = out;
      logger.info({ tx: ref.txHash, seat: bound.seat, requestHash: bound.requestHash, approver: bound.approver, policyPinned: bound.policyPinned }, 'decision bound and consumed');
    }
    const bindingInfo = bound
      ? { binding: { decisionHash: bound.decisionHash, requestHash: bound.requestHash, nonce: bound.nonce, grantHash: bound.grantHash, policyHash: bound.policyHash, policyPinned: bound.policyPinned, seat: bound.seat, approver: bound.approver } }
      : {};

    if (decision.decision === 'deny') {
      logger.info({ tx: ref.txHash, reason: decision.reason }, 'policy denied');
      await store.update(key, { status: 'denied', decision: 'deny' });
      // A reject vote that could not be submitted is a FAILURE, exactly as an approve vote is — the
      // result was being discarded here. That mattered: `rejected` is terminal, so the tx was never
      // retried, while the receipt below recorded `vote: reject` for a vote that never reached the
      // chain. The transaction stayed pending on-chain until expiry with the audit trail claiming it
      // had been actively killed. Leave it retryable and write no receipt, as the approve path does.
      let rejectVote: VoteResult | undefined;
      if (rules.submitRejectVote) {
        const lateReject = this.deadlineRefusal(tx);
        if (lateReject) return this.refuseDeadline(tx, lateReject, decision, bindingInfo);
        // G-69: a human-only seat holds no key; the reject the engine asked for is a person's to cast.
        if (this.isHumanOnly(tx.signerUrl)) return this.awaitHuman(tx, 'reject', decision, bindingInfo);
        const res = await this.signAndSubmit(tx, 'reject', undefined, signatureEvidence(decision.evidence), sign);
        if (!res.ok && res.error === PAUSED_AT_CAST) return this.withholdPaused(key, ref.txHash, decision.decision, PAUSED_AT_CAST);
        if (!res.ok) {
          logger.error({ tx: ref.txHash, err: res.error }, 'reject vote submission failed');
          this.notify('signature.failed', tx, { reason: decision.reason, error: res.error });
          return store.update(key, { status: 'error', lastError: res.error });
        }
        rejectVote = res;
      }
      const final = await store.update(key, { status: 'rejected' });
      await this.saveReceipt({
        ...this.receiptKey(tx), operationId: tx.operationId, decision: 'deny',
        vote: rules.submitRejectVote ? 'reject' : undefined,
        reason: decision.reason,
        // Whose re-authentication this was about. The receipts are the audit trail, and a year later
        // that is the question being asked of them.
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: decision.evidence,
        ...bindingInfo,
        // A reject is a signature too, and the record should say which key cast it. A deployment that
        // withholds rejects rather than casting them has nothing to attribute, and gets nothing.
        ...(rejectVote?.signedBy ? { signedBy: rejectVote.signedBy } : {}),
      });
      this.notify('decision.denied', tx, { reason: decision.reason });
      return final;
    }

    // SR4 local guard (defense-in-depth even if policy approved)
    if (rules.guard && !rules.guard({
      account: tx.account, summary: tx.summary.action,
      value: tx.summary.value, values: tx.summary.values, unpricedLegs: tx.summary.unpricedLegs,
    })) {
      logger.warn({ tx: ref.txHash, values: tx.summary.values, unpricedLegs: tx.summary.unpricedLegs }, 'local guard blocked an approved tx');
      // Keep the engine's reason and evidence on the record: the receipt must show that the engine
      // approved and WE refused, not merely that something was blocked.
      await this.saveReceipt({
        ...this.receiptKey(tx), operationId: tx.operationId, decision: 'approve',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'local_guard', values: tx.summary.values },
        ...bindingInfo,
      });
      return store.update(key, { status: 'rejected', lastError: 'local_guard_block' });
    }

    // G-65: never approve an updateKeyPage that would brick the page it changes (see keyPageRefusal).
    const brick = await this.keyPageRefusal(tx);
    if (brick) return this.refuseKeyPage(tx, brick, decision, bindingInfo);

    // Wrapper runbook, change 4: the evidence this vote commits to. With `require_signature_data` an
    // approval that brings no valid digest is not signed — a vote that cannot be tied back to the live
    // check it stands for is a claim nobody can verify. Malformed counts as absent (see
    // `signatureEvidence`), so a garbled digest refuses here rather than being signed as something else.
    const evidence = signatureEvidence(decision.evidence);
    if (this.opt.requireSignatureData && !evidence.data) {
      logger.warn({ tx: ref.txHash }, 'approved, but the decision carries no valid signatureData and it is required; not signing');
      await this.saveReceipt({
        ...this.receiptKey(tx), operationId: tx.operationId, decision: 'approve',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'signature_data_missing' },
        ...bindingInfo,
      });
      return store.update(key, { status: 'rejected', lastError: 'signature_data_missing' });
    }

    // 3. Sign + submit (approve). The deadline is re-read against the clock now: an approval that arrived
    // after the transaction died must not become a late signature (0031).
    const lateApprove = this.deadlineRefusal(tx);
    if (lateApprove) return this.refuseDeadline(tx, lateApprove, decision, bindingInfo);

    // G-69: a human-only seat holds no key. Every check above (pause, binding, SR4 ceiling, G-65 key-page guard, signature data,
    // deadline) has run exactly as for a keyed seat; the approve signature is a person's to make.
    if (this.isHumanOnly(tx.signerUrl)) return this.awaitHuman(tx, 'approve', decision, bindingInfo);

    await store.update(key, { status: 'approved', decision: 'approve', assertionRef: decision.assertion ? sha256Hex(decision.assertion) : undefined });
    // Whose key signs. T29: when the policy engine names the approver, THEIR key signs — so the
    // signature on chain is the person's rather than the organisation's cast in their name. Absent,
    // the organisation signs as itself, exactly as before.
    const res = await this.castForApprovers(tx, 'approve', approverKeyRefs(decision.evidence), evidence, sign);
    if (!res.ok && res.error === PAUSED_AT_CAST) return this.withholdPaused(key, ref.txHash, decision.decision, PAUSED_AT_CAST);
    if (res.ok) {
      await this.saveReceipt({
        ...this.receiptKey(tx), operationId: tx.operationId, decision: 'approve', vote: 'approve',
        signatureHash: res.signatureHash, submittedAt: this.now(), accumulateResult: 'ok',
        reason: decision.reason,
        ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
        policyEvidence: decision.evidence,
        ...bindingInfo,
        // What satisfied it, carried through rather than re-derived. F4.
        ...(res.signedBy ? { signedBy: res.signedBy } : {}),
      });
      this.notify('decision.approved', tx, { reason: decision.reason });
      return store.update(key, { status: 'signed', timestampMicros: res.timestamp });
    }
    // A vote we decided to cast but could not is a real failure — say so. It used to be recorded in the
    // store and nowhere else, so an operator watching the logs saw the policy decision and then silence.
    logger.error({ tx: ref.txHash, err: res.error }, 'vote submission failed');
    this.notify('signature.failed', tx, { reason: decision.reason, error: res.error });
    return store.update(key, { status: 'error', lastError: res.error });
  }

  /**
   * Why this transaction must not be signed on account of its header deadline, or undefined if it may.
   * Decision 0031, fail closed: a passed deadline and an unreadable one are both refusals.
   */
  private deadlineRefusal(tx: ResolvedTx): { lastError: string; reason: string } | undefined {
    if (tx.headerExpiryUnreadable) {
      return {
        lastError: 'header_expiry_unreadable',
        reason: `refusing to sign: the transaction header has an expiry that cannot be read (${tx.headerExpiryUnreadable})`,
      };
    }
    if (headerDeadlinePassed(tx.header, this.now())) {
      return {
        lastError: 'header_deadline_passed',
        reason: `refusing to sign: the transaction's on-chain deadline ${tx.header.expiresAt} has passed (now ${new Date(this.now()).toISOString()})`,
      };
    }
    return undefined;
  }

  /**
   * Record a deadline refusal. No signature of any kind is made. A passed deadline is terminal
   * (`expired`): Accumulate rejects any signature after it (S7), so there is nothing to retry. An
   * unreadable one is `rejected` with the reason, as a local-guard block is.
   */
  private async refuseDeadline(
    tx: ResolvedTx,
    refusal: { lastError: string; reason: string },
    decision?: { decision: string; reason?: string; evidence?: Record<string, unknown> },
    bindingInfo: Pick<Receipt, 'binding'> = {},
  ): Promise<SigningRequest> {
    this.d.logger.warn(
      { tx: tx.txHash, headerExpiresAt: tx.header.expiresAt, decision: decision?.decision, err: refusal.lastError },
      refusal.reason,
    );
    await this.saveReceipt({
      ...this.receiptKey(tx), operationId: tx.operationId,
      ...(decision && (decision.decision === 'approve' || decision.decision === 'deny') ? { decision: decision.decision } : {}),
      reason: refusal.reason,
      ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
      policyEvidence: {
        ...(decision?.evidence ?? {}),
        ...(decision?.reason ? { engineReason: decision.reason } : {}),
        blockedBy: refusal.lastError,
        ...(tx.header.expiresAt ? { headerExpiresAt: tx.header.expiresAt } : {}),
      },
      ...bindingInfo,
    });
    const status = refusal.lastError === 'header_deadline_passed' ? 'expired' : 'rejected';
    return this.d.store.update(this.rid(tx), {
      status, lastError: refusal.lastError,
      // G-64: a refusal before any decision ends the hold too (after a decision it has already ended).
      ...finaliseHold(await this.d.store.get(this.rid(tx)), refusal.lastError, this.now()),
    });
  }

  /**
   * G-69: record a decision that needs a signature this signer cannot make, because the seat's page holds
   * no key. No signature of any kind is cast. The PolicyRequest (display, summaryHash, header, facts) is
   * already stored, so a person on the page signs through officer intake against it; the receipt keeps the
   * engine's decision, reason and evidence, and says whose signature is owed and which vote. A seat that requires binding has
   * had this decision bound (and its nonce consumed) before this point, so the receipt carries the same `binding` as a signed one.
   */
  private async awaitHuman(
    tx: ResolvedTx,
    vote: 'approve' | 'reject',
    decision: { decision: string; reason?: string; evidence?: Record<string, unknown> },
    bindingInfo: Pick<Receipt, 'binding'> = {},
  ): Promise<SigningRequest> {
    this.d.logger.info({ tx: tx.txHash, page: tx.signerUrl, decision: decision.decision, vote }, 'human-only seat: decision recorded; a person on the page signs through officer intake');
    await this.saveReceipt({
      ...this.receiptKey(tx), operationId: tx.operationId,
      ...(decision.decision === 'approve' || decision.decision === 'deny' ? { decision: decision.decision } : {}),
      reason: decision.reason,
      ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
      policyEvidence: { ...(decision.evidence ?? {}), awaitingHumanSignature: { page: tx.signerUrl, vote } },
      ...bindingInfo,
    });
    return this.d.store.update(this.rid(tx), {
      status: 'awaiting_human',
      ...(decision.decision === 'approve' || decision.decision === 'deny' ? { decision: decision.decision } : {}),
      lastError: undefined,
    });
  }

  /**
   * G-65: why an approve vote on this transaction must be withheld because it would brick a key page, or
   * undefined when it may proceed.
   *
   * Only an `updateKeyPage` body changes a page's entries or thresholds, and its principal IS the page it
   * changes. The operations are the resolver's decoding of the on-chain body (`tx.governance`); the page
   * is read NOW. A body whose operations could not be decoded, and a page that cannot be read, are both
   * refusals -- never an assumed page state.
   */
  private async keyPageRefusal(tx: ResolvedTx): Promise<KeyPageRefusal | undefined> {
    if (tx.bodyType !== 'updateKeyPage') return undefined;
    const ops = tx.governance?.kind === 'updateKeyPage' ? tx.governance.operations : [{ type: 'unknown', unrecognized: true }];
    const v = await checkKeyPageChange(this.d.readPage, tx.account, ops);
    return v.ok ? undefined : v.refusal;
  }

  /**
   * Withhold the approve vote the engine asked for. No signature of any kind is cast.
   *
   * WHY WITHHOLD, NOT REJECT. Both are fail-closed (neither can carry the change towards execution). The
   * engine -- the party's own policy (P1) -- decided `approve`; this guard is the signer's safety
   * interlock, not a second policy, so it refuses to sign rather than inventing a reject vote the policy
   * never chose. That is the same posture as the SR4 local guard above. A party that wants the change
   * actively killed still has its policy's `deny` (which casts a reject when configured) and its humans.
   *
   *   - The change would brick the page: terminal `rejected`, with a receipt that records the engine's
   *     approve, `blockedBy: keypage_guard` and the structured refusal (reason, threshold, entries).
   *   - The page could not be read: NOT terminal. Nothing is known about the change, so the request stays
   *     `awaiting_policy` and is asked again next poll; still nothing is signed.
   */
  private async refuseKeyPage(
    tx: ResolvedTx,
    refusal: KeyPageRefusal,
    decision: { decision: string; reason?: string; evidence?: Record<string, unknown> },
    bindingInfo: Pick<Receipt, 'binding'> = {},
  ): Promise<SigningRequest> {
    const lastError = `keypage_guard: ${refusal.reason}`;
    if (refusal.reason === 'page_unreadable') {
      this.d.logger.warn({ tx: tx.txHash, page: tx.account, refusal }, 'key page unreadable; withholding the approve vote and will retry');
      return this.d.store.update(this.rid(tx), { status: 'awaiting_policy', lastError });
    }
    this.d.logger.warn({ tx: tx.txHash, page: tx.account, refusal }, 'REFUSING to approve an updateKeyPage that would brick the page; no signature cast');
    await this.saveReceipt({
      ...this.receiptKey(tx), operationId: tx.operationId, decision: 'approve',
      reason: decision.reason,
      ...(tx.summary.subject ? { subject: tx.summary.subject.adi } : {}),
      policyEvidence: { ...(decision.evidence ?? {}), blockedBy: 'keypage_guard', keyPageRefusal: refusal },
      ...bindingInfo,
    });
    return this.d.store.update(this.rid(tx), { status: 'rejected', lastError });
  }

  /**
   * Cast the vote through whichever backend is configured — DIRECT (we submit the envelope to Accumulate)
   * or GATEWAY (the Certen api-gateway hands us the bytes; we sign; we hand the signature back). The
   * decision above this line is identical either way: the policy engine gates both.
   */
  private async signAndSubmit(tx: ResolvedTx, vote: 'approve' | 'reject', keyRef: string | undefined, evidence: SignatureEvidence, sign: SignCtx): Promise<VoteResult> {
    // G-69 defence in depth: nothing above reaches here for a human-only seat, and if anything ever did,
    // the answer is no signature -- never a key found for the page by some other route.
    if (this.isHumanOnly(tx.signerUrl)) return { ok: false, error: 'human-only scope: this signer holds no key for this page' };
    // The pause is read again at the moment of signing: a pause set while the world was being read still applies.
    if (this.pausedFor(sign, vote)) return { ok: false, error: PAUSED_AT_CAST };
    await this.d.store.update(this.rid(tx), { status: 'signing', signerVersion: tx.signerVersion });
    return this.votes.cast(tx, vote, { ...(keyRef === undefined ? {} : { keyRef }), ...evidence, ...pathOf(tx) });
  }

  /**
   * Cast one vote per named approver. Runbook F, T29-d.
   *
   * A key page counts signatures itself, so two approvers means two signatures — one from each of
   * their keys. Votes are cast in sequence rather than together, deliberately: each consumes the
   * page's `lastUsedOn` and moves its version, and two concurrent votes would race into a
   * bad-version retry that looks like a fault.
   *
   * ── PARTIAL SUCCESS IS THE NORMAL CASE, NOT A FAULT ────────────────────────────────────────────
   *
   * A half-enrolled organisation is the ordinary state of a rollout: one approver's key is held here
   * and another's is not. The one that can sign SHOULD, and the transaction is then correctly short
   * of its threshold and left pending — the protocol's own answer, and not something to report as a
   * failure. So this succeeds if ANY vote landed, records the first that did, and says in the log
   * which refs could not be signed for and why.
   *
   * Only when nothing at all could be signed is it a failure, and then the first error is the one
   * worth reporting: it is the reason the transaction has no signature.
   */
  private async castForApprovers(
    tx: ResolvedTx,
    vote: 'approve' | 'reject',
    refs: string[],
    evidence: SignatureEvidence,
    sign: SignCtx,
  ): Promise<VoteResult> {
    if (this.isHumanOnly(tx.signerUrl)) return { ok: false, error: 'human-only scope: this signer holds no key for this page' };
    // Nobody named: one vote, the organisation's own key, exactly as before T29.
    if (refs.length === 0) return this.signAndSubmit(tx, vote, undefined, evidence, sign);

    // From one ref upward the loop below handles it, so a named approver this wallet cannot sign for
    // is RECORDED as a failed vote rather than thrown out of the pipeline. One ref and two refs
    // failing the same way is the point: a misconfigured ref is an operational fact about one
    // transaction, not an exception for the poll loop to cope with.

    await this.d.store.update(this.rid(tx), { status: 'signing', signerVersion: tx.signerVersion });
    let first: VoteResult | undefined;
    let firstError: string | undefined;

    for (const ref of refs) {
      // Before EACH signature the pause is read again: one decision may cast several keys, and a pause set between two of them
      // stops the rest.
      if (this.pausedFor(sign, vote)) {
        firstError ??= PAUSED_AT_CAST;
        break;
      }
      let res: VoteResult;
      try {
        res = await this.votes.cast(tx, vote, { keyRef: ref, ...evidence, ...pathOf(tx) });
      } catch (e) {
        // A ref this wallet holds no key for throws rather than substituting the organisation's key.
        // That is the T29 refusal working; it is not a reason to abandon the approvers it CAN sign for.
        res = { ok: false, error: (e as Error).message };
      }
      if (res.ok) {
        this.d.logger.info({ tx: tx.txHash, keyRef: ref }, 'signed as the named approver');
        first ??= res;
      } else {
        this.d.logger.warn({ tx: tx.txHash, keyRef: ref, err: res.error }, 'could not sign as the named approver');
        firstError ??= res.error;
      }
    }

    if (first) return first;
    return { ok: false, ...(firstError ? { error: firstError } : {}) };
  }
}

/**
 * The approver's key ref, as the policy engine named it. Runbook F, T29.
 *
 * `evidence` is a free-form record on the decision — part of the frozen contract, so naming the
 * approver needs no contract change (invariant F-9). What arrives here came from the policy engine
 * over the MAC channel, which authenticates it but says nothing about whether the value is one this
 * process holds a key for: that is checked in the keyring, which refuses an unknown ref rather than
 * substituting the organisation's key.
 *
 * Read strictly. A non-string, an empty string, or an over-long value is treated as ABSENT rather than
 * passed on, so a malformed decision falls back to the organisation signing as itself — the behaviour
 * every deployment had before this existed — instead of failing the vote. The one thing it must never
 * do is turn a garbled ref into a DIFFERENT valid ref, and returning undefined cannot.
 */
export function approverKeyRef(evidence: Record<string, unknown> | undefined): string | undefined {
  const raw = evidence?.['approverKeyRef'];
  if (typeof raw !== 'string') return undefined;
  const ref = raw.trim();
  if (!ref || ref.length > 256) return undefined;
  return ref;
}

/**
 * EVERY approver whose key should sign. Runbook F, T29-d.
 *
 * A key page counts signatures against its own threshold, so a 2-of-N page needs two signatures and
 * each approver makes their own with the key they control — measured on Kermit, not assumed. One vote
 * per transaction would leave such a page one signature short and the transaction pending until it
 * expired, which is what this exists to prevent.
 *
 * Reads `approverKeyRefs` (a list), falling back to the single `approverKeyRef` so a console that has
 * not been updated keeps working exactly as it did. Duplicates are collapsed: two votes with the same
 * key are one signature to the page and a wasted round trip to find that out.
 *
 * An empty result means nobody was named, and the caller signs once as the organisation — the
 * behaviour of every deployment before T29.
 */
export function approverKeyRefs(evidence: Record<string, unknown> | undefined): string[] {
  const raw = evidence?.['approverKeyRefs'];
  const list = Array.isArray(raw) ? raw : [];
  const refs: string[] = [];
  for (const item of list) {
    if (typeof item !== 'string') continue;      // a malformed entry is skipped, not fatal
    const ref = item.trim();
    if (!ref || ref.length > 256) continue;
    if (!refs.includes(ref)) refs.push(ref);
  }
  if (refs.length) return refs;
  const single = approverKeyRef(evidence);
  return single ? [single] : [];
}

/** The per-vote path, only when this work has one: absent leaves the backend's boot-time path in force. */
function pathOf(tx: ResolvedTx): { delegators?: string[] } {
  return tx.delegators ? { delegators: tx.delegators } : {};
}

/** What a signature commits to, read off the decision. Both fields absent is the ordinary case. */
export interface SignatureEvidence {
  memo?: string;
  data?: Uint8Array;
}

/**
 * The digest and memo the policy engine wants IN the signature. Wrapper runbook, change 4.
 *
 * Carried in `evidence`, the decision's free-form record, so this needs no contract change (invariant
 * F-9), the same route `approverKeyRef` takes. Read strictly, and anything malformed is ABSENT:
 *
 *   signatureData: hex (an optional 0x is tolerated), exactly 32 bytes. A digest of any other length
 *                  is not the digest of anything we agreed on, and truncating or padding one would sign
 *                  a value the engine never produced.
 *   signatureMemo: a non-empty string of at most 256 characters.
 *
 * Absent is safe by construction: the signature is then built exactly as before, and with
 * `require_signature_data` the approval is refused rather than signed without its evidence.
 */
export function signatureEvidence(evidence: Record<string, unknown> | undefined): SignatureEvidence {
  const out: SignatureEvidence = {};
  const raw = evidence?.['signatureData'];
  if (typeof raw === 'string' && /^(0x)?[0-9a-fA-F]{64}$/.test(raw)) {
    out.data = new Uint8Array(Buffer.from(raw.replace(/^0x/, ''), 'hex'));
  }
  const memo = evidence?.['signatureMemo'];
  if (typeof memo === 'string' && memo.length > 0 && memo.length <= 256) out.memo = memo;
  return out;
}

/** True when the transaction provably carries no contract call: acceptance and governance facts, or a non-WriteData body. */
function noContractCall(tx: { bodyType?: string; acceptance?: unknown; governance?: unknown }): boolean {
  return Boolean(tx.acceptance || tx.governance || (tx.bodyType && tx.bodyType !== 'writeData'));
}
