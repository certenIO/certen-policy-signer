/**
 * G-65: refuse a key-page change that would brick the page.
 *
 * A key page whose accept threshold is above the number of entries on it can never be satisfied again:
 * no set of signatures reaches the threshold, and every authority that runs through the page is stuck for
 * good. A page with no entries at all is the same failure with a smaller number. The Console cannot catch
 * this (it has no chain access, by design P2), so the signer -- the only component in a cell that talks to
 * Accumulate -- refuses to build, propose, sign or vote for such a change.
 *
 * Two parts:
 *
 *   - `simulateKeyPageOps` applies a list of `updateKeyPage` operations to a page state READ FROM
 *     ACCUMULATE and returns the resulting entries and thresholds, or the first operation the network
 *     itself would refuse. It follows the executor (accumulate v1.4.x
 *     internal/core/execute/v2/chain/update_key_page.go `executeOperation`, update_key.go `updateKey`,
 *     protocol/keys.go `SetThreshold`) operation by operation, IN ORDER:
 *       add                  duplicate entry (by key hash, else by delegate) -> refused
 *       remove               entry not on the page -> refused; afterwards the ACCEPT threshold is lowered
 *                            to the entry count, exactly as both the v1 and v2 executors do. The reject and
 *                            response thresholds are NOT lowered here even though v2 lowers them, because
 *                            v1 does not; a stale reject/response threshold then fails the final check
 *                            below. That is the conservative direction (refuse more, never less).
 *       update               old entry not on the page -> refused; new entry already elsewhere -> refused
 *       setThreshold         < 1 or > the entries on the page AT THAT POINT -> refused (SetThreshold)
 *       setRejectThreshold   > the entries at that point -> refused
 *       setResponseThreshold > the entries at that point -> refused
 *       updateAllowed        changes no entry and no threshold
 *     A delegate entry is an entry: it holds a seat and counts toward the threshold like a key does.
 *
 *   - `validateKeyPageChange` runs the simulation and then checks the RESULT: no entries, an accept
 *     threshold below one or above the entries, or a set (non-zero) reject/response threshold above the
 *     entries is refused. The accept threshold is judged as the protocol enforces it: a stored 0 (which a
 *     remove can leave behind by lowering the threshold to an entry count of 0 before a later add) is
 *     read as ONE by protocol/authority.go `GetSignatureThreshold`, exactly as PageState.threshold does.
 *     An explicit `setThreshold 0` is still refused at the operation (SetThreshold refuses it too).
 *
 * Anything the simulator cannot read (an operation marked `unrecognized` by the decoder, an unknown type,
 * an entry with neither a key hash nor a delegate) is refused: a change whose effect cannot be computed is
 * a change whose safety cannot be shown.
 *
 * `checkKeyPageChange` is what the wired call sites use: it reads the page NOW (decision time, never a
 * cached copy) and refuses with the distinct reason `page_unreadable` when the page cannot be read. It
 * never assumes a page state.
 */
import type { PageState } from './rotate.js';
import type { KeyPageOp } from './keypage.js';

/** Why a key-page change is refused. Stable strings: callers and evidence key on them. */
export type KeyPageRefusalReason =
  | 'no_entries'
  | 'threshold_below_one'
  | 'threshold_exceeds_entries'
  | 'reject_threshold_exceeds_entries'
  | 'response_threshold_exceeds_entries'
  | 'entry_not_on_page'
  | 'duplicate_entry'
  | 'unrecognized_operation'
  | 'page_unreadable';

export interface KeyPageRefusal {
  reason: KeyPageRefusalReason;
  /** One line for a log or an operator; the structured fields below are what a program reads. */
  message: string;
  page?: string;
  /** Index of the operation that was refused, when one operation (rather than the end state) is at fault. */
  opIndex?: number;
  /** The threshold that was refused, with the entry count it was measured against. */
  threshold?: number;
  entries?: number;
  /** The entry an add/remove/update named, when that is what was refused. */
  entry?: { keyHash?: string; delegate?: string };
}

/**
 * One `updateKeyPage` operation, in the shape `extractGovernance` (src/decode/facts.ts) produces for a
 * decoded body: hex key hashes, delegate URLs, numeric thresholds.
 */
export interface KeyPageOperation {
  type: string;
  keyHash?: unknown;
  delegate?: unknown;
  oldKeyHash?: unknown;
  oldDelegate?: unknown;
  newKeyHash?: unknown;
  newDelegate?: unknown;
  threshold?: unknown;
  unrecognized?: unknown;
  [k: string]: unknown;
}

export interface SimEntry { keyHash: string | null; delegate: string | null }

/** The page as the simulation sees it. Raw thresholds: 0 means "not set" for reject/response. */
export interface SimPage {
  entries: SimEntry[];
  acceptThreshold: number;
  rejectThreshold: number;
  responseThreshold: number;
}

export interface SimResult extends SimPage {
  /** The accept threshold the network enforces: a stored 0 means one (GetSignatureThreshold). */
  effectiveAcceptThreshold: number;
  /** Entry count after the change: keys and delegates alike. */
  entryCount: number;
  /** True when a remove lowered the accept threshold to the entry count (the executor does this). */
  acceptThresholdLowered: boolean;
}

export type SimOutcome = { ok: true; result: SimResult } | { ok: false; refusal: KeyPageRefusal };

const HEX64 = /^[0-9a-f]{64}$/;
const normHash = (v: unknown): string | undefined => {
  if (typeof v !== 'string') return undefined;
  const h = v.toLowerCase().replace(/^0x/, '');
  return HEX64.test(h) ? h : undefined;
};
const normUrl = (v: unknown): string | undefined => {
  if (typeof v !== 'string' || !v.trim()) return undefined;
  return v.trim().toLowerCase().replace(/\/+$/, '');
};
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

/** The page state readPage returned, as the simulator's input. */
export function simPageFrom(st: PageState): SimPage {
  return {
    entries: st.entries.map((e) => ({ keyHash: e.keyHash ? e.keyHash.toLowerCase() : null, delegate: e.delegate ?? null })),
    acceptThreshold: st.threshold,
    rejectThreshold: st.rejectThreshold ?? 0,
    responseThreshold: st.responseThreshold ?? 0,
  };
}

/**
 * findKeyPageEntry: by key hash when the search names one, else (or when that misses) by delegate.
 * Returns the index or -1.
 */
function findEntry(entries: SimEntry[], keyHash: string | undefined, delegate: string | undefined): number {
  if (keyHash) {
    const i = entries.findIndex((e) => e.keyHash === keyHash);
    if (i >= 0) return i;
  }
  if (delegate) return entries.findIndex((e) => e.delegate !== null && normUrl(e.delegate) === delegate);
  return -1;
}

function entryOf(o: KeyPageOperation, prefix: '' | 'old' | 'new'): { keyHash?: string; delegate?: string; raw: { keyHash?: string; delegate?: string } } | undefined {
  const khRaw = prefix ? o[`${prefix}KeyHash`] : o.keyHash;
  const dgRaw = prefix ? o[`${prefix}Delegate`] : o.delegate;
  const keyHash = normHash(khRaw);
  const delegate = normUrl(dgRaw);
  // A key hash that is present but not 64 hex is unreadable, not absent.
  if (khRaw !== undefined && !keyHash) return undefined;
  if (dgRaw !== undefined && !delegate) return undefined;
  if (!keyHash && !delegate) return undefined;
  return {
    ...(keyHash ? { keyHash } : {}), ...(delegate ? { delegate } : {}),
    raw: { ...(keyHash ? { keyHash } : {}), ...(typeof dgRaw === 'string' && delegate ? { delegate: dgRaw.trim() } : {}) },
  };
}

/** Apply `ops` to `page` in order, as the executor would. Pure. */
export function simulateKeyPageOps(page: SimPage, ops: KeyPageOperation[]): SimOutcome {
  const entries: SimEntry[] = page.entries.map((e) => ({ ...e }));
  let accept = page.acceptThreshold;
  let reject = page.rejectThreshold;
  let response = page.responseThreshold;
  let lowered = false;

  const refuse = (r: KeyPageRefusal): SimOutcome => ({ ok: false, refusal: r });

  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    if (!o || typeof o !== 'object' || o.unrecognized) {
      return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} (${String(o?.type)}) could not be read; refusing a change whose effect cannot be computed` });
    }
    switch (o.type) {
      case 'add': {
        const e = entryOf(o, '');
        if (!e) return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} (add) names no readable entry` });
        if (findEntry(entries, e.keyHash, e.delegate) >= 0) {
          return refuse({ reason: 'duplicate_entry', opIndex: i, entry: e.raw, message: `operation ${i} adds an entry that is already on the page` });
        }
        entries.push({ keyHash: e.keyHash ?? null, delegate: e.raw.delegate ?? null });
        break;
      }
      case 'remove': {
        const e = entryOf(o, '');
        if (!e) return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} (remove) names no readable entry` });
        const at = findEntry(entries, e.keyHash, e.delegate);
        if (at < 0) return refuse({ reason: 'entry_not_on_page', opIndex: i, entry: e.raw, message: `operation ${i} removes an entry that is not on the page` });
        entries.splice(at, 1);
        if (accept > entries.length) { accept = entries.length; lowered = true; }
        break;
      }
      case 'update': {
        const oldE = entryOf(o, 'old');
        const newE = entryOf(o, 'new');
        if (!oldE || !newE) return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} (update) names no readable old or new entry` });
        const at = findEntry(entries, oldE.keyHash, oldE.delegate);
        if (at < 0) return refuse({ reason: 'entry_not_on_page', opIndex: i, entry: oldE.raw, message: `operation ${i} updates an entry that is not on the page` });
        const dup = findEntry(entries, newE.keyHash, newE.delegate);
        if (dup >= 0 && dup !== at) return refuse({ reason: 'duplicate_entry', opIndex: i, entry: newE.raw, message: `operation ${i} updates an entry into one that is already on the page` });
        entries[at] = { keyHash: newE.keyHash ?? null, delegate: newE.raw.delegate ?? null };
        break;
      }
      case 'setThreshold': {
        if (!isCount(o.threshold)) return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} (setThreshold) has no readable threshold` });
        if (o.threshold < 1) return refuse({ reason: 'threshold_below_one', opIndex: i, threshold: o.threshold, entries: entries.length, message: `operation ${i} sets the accept threshold to ${o.threshold}; a page must require at least one signature` });
        if (o.threshold > entries.length) {
          return refuse({ reason: 'threshold_exceeds_entries', opIndex: i, threshold: o.threshold, entries: entries.length, message: `operation ${i} sets the accept threshold to ${o.threshold} on a page with ${entries.length} entries; it could never be met` });
        }
        accept = o.threshold;
        break;
      }
      case 'setRejectThreshold':
      case 'setResponseThreshold': {
        if (!isCount(o.threshold)) return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} (${o.type}) has no readable threshold` });
        if (o.threshold > entries.length) {
          const reason = o.type === 'setRejectThreshold' ? 'reject_threshold_exceeds_entries' : 'response_threshold_exceeds_entries';
          return refuse({ reason, opIndex: i, threshold: o.threshold, entries: entries.length, message: `operation ${i} sets the ${o.type === 'setRejectThreshold' ? 'reject' : 'response'} threshold to ${o.threshold} on a page with ${entries.length} entries; it could never be met` });
        }
        if (o.type === 'setRejectThreshold') reject = o.threshold; else response = o.threshold;
        break;
      }
      case 'updateAllowed':
        break;
      default:
        return refuse({ reason: 'unrecognized_operation', opIndex: i, message: `operation ${i} has unknown type ${JSON.stringify(o.type)}` });
    }
  }
  return {
    ok: true,
    result: { entries, entryCount: entries.length, acceptThreshold: accept, effectiveAcceptThreshold: accept === 0 ? 1 : accept, rejectThreshold: reject, responseThreshold: response, acceptThresholdLowered: lowered },
  };
}

export type KeyPageCheck = { ok: true; before: SimPage; after: SimResult } | { ok: false; refusal: KeyPageRefusal };

/** Simulate, then refuse an end state that can never be satisfied. Pure. */
export function validateKeyPageChange(page: SimPage, ops: KeyPageOperation[]): KeyPageCheck {
  const sim = simulateKeyPageOps(page, ops);
  if (!sim.ok) return sim;
  const r = sim.result;
  const n = r.entryCount;
  if (n === 0) return { ok: false, refusal: { reason: 'no_entries', entries: 0, message: 'the change leaves the page with no entries; nothing could ever sign for it again' } };
  const accept = r.effectiveAcceptThreshold;
  if (!Number.isSafeInteger(accept) || accept < 1) return { ok: false, refusal: { reason: 'threshold_below_one', threshold: accept, entries: n, message: `the change leaves an accept threshold of ${accept}` } };
  if (accept > n) {
    return { ok: false, refusal: { reason: 'threshold_exceeds_entries', threshold: accept, entries: n, message: `the change leaves an accept threshold of ${accept} over ${n} entries; it could never be met` } };
  }
  if (r.rejectThreshold > n) {
    return { ok: false, refusal: { reason: 'reject_threshold_exceeds_entries', threshold: r.rejectThreshold, entries: n, message: `the change leaves a reject threshold of ${r.rejectThreshold} over ${n} entries` } };
  }
  if (r.responseThreshold > n) {
    return { ok: false, refusal: { reason: 'response_threshold_exceeds_entries', threshold: r.responseThreshold, entries: n, message: `the change leaves a response threshold of ${r.responseThreshold} over ${n} entries` } };
  }
  return { ok: true, before: page, after: r };
}

/**
 * The typed governance operations (keypage.ts) as `updateKeyPage` operations.
 *
 * `rotate-key` replaces our own key in place (`updateKey`, or `update` / add-then-remove); its effect on the
 * entry count is nil, so it is modelled as an `update` of `ourKeyHash`. Without our key hash it cannot be
 * modelled and is returned as unrecognized (refused).
 */
export function operationsFromKeyPageOps(ops: KeyPageOp[], ourKeyHash?: string): KeyPageOperation[] {
  return ops.map((o): KeyPageOperation => {
    switch (o.op) {
      case 'add-key': return { type: 'add', keyHash: o.keyHash };
      case 'remove-key': return { type: 'remove', keyHash: o.keyHash };
      case 'add-delegate': return { type: 'add', delegate: o.delegate };
      case 'remove-delegate': return { type: 'remove', delegate: o.delegate };
      case 'set-threshold': return { type: 'setThreshold', threshold: o.threshold };
      case 'rotate-key':
        return ourKeyHash ? { type: 'update', oldKeyHash: ourKeyHash, newKeyHash: o.newKeyHash } : { type: 'rotate-key', unrecognized: true };
      default: return { type: String((o as { op?: unknown }).op), unrecognized: true };
    }
  });
}

/** Thrown by the governance paths when the guard refuses; carries the structured refusal. */
export class KeyPageGuardError extends Error {
  constructor(readonly refusal: KeyPageRefusal) {
    super(`key-page guard refused: ${refusal.reason}: ${refusal.message}`);
    this.name = 'KeyPageGuardError';
  }
}

/**
 * Read `page` NOW and validate `ops` against it. Fails closed: an unreadable page is a refusal with reason
 * `page_unreadable`, never an assumed state.
 */
export async function checkKeyPageChange(
  readPage: ((page: string) => Promise<PageState>) | undefined,
  page: string,
  ops: KeyPageOperation[],
): Promise<KeyPageCheck> {
  if (!readPage) {
    return { ok: false, refusal: { reason: 'page_unreadable', page, message: `no page reader is configured, so ${page} cannot be read; refusing rather than assuming its state` } };
  }
  let st: PageState;
  try {
    st = await readPage(page);
  } catch (e) {
    return { ok: false, refusal: { reason: 'page_unreadable', page, message: `${page} could not be read (${(e as Error).message}); refusing rather than assuming its state` } };
  }
  if (!st || !Array.isArray(st.entries) || !isCount(st.threshold)) {
    return { ok: false, refusal: { reason: 'page_unreadable', page, message: `${page} returned no readable page state; refusing rather than assuming its state` } };
  }
  const out = validateKeyPageChange(simPageFrom(st), ops);
  return out.ok ? out : { ok: false, refusal: { ...out.refusal, page } };
}
