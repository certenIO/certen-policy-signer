/**
 * The Grant decisions of the core: parse (with hash), checkAction (GRANT.md section 6, GR-15 to GR-21, GR-39) and the
 * lineage of versions (section 7, GR-22 to GR-27, GR-40). Pure functions of their arguments: time, usage and the
 * resolved subject are inputs, never read from the environment. The library decides; it never signs for anyone.
 */
import { ADDRESS_RE, isAmount, isPlainObject } from './bytes.js';
import {
  ACTION_KINDS,
  SUBJECT_TYPES,
  parseGrantTextUnhashed,
  validateGrant,
  type Condition,
  type Grant,
  type ParseGrantResult,
  type RequiredBook,
} from './grant-profile.js';
import { hashGrant } from './hashes.js';

export function parseGrantText(text: string): ParseGrantResult {
  const p = parseGrantTextUnhashed(text);
  if (!p.ok) return p;
  return { ok: true, grant: p.grant, canonical: p.canonical, grantHash: hashGrant(p.grant) };
}

// ---- checkAction ---------------------------------------------------------------------------------------------

export interface CheckActionInput {
  grant: unknown;
  action: unknown;
  /** the subject resolved from the registry, `{adi, type}`; never the producer's claim */
  subject: unknown;
  /** Unix seconds, supplied by the caller (the library has no clock) */
  now: unknown;
  /** usage of the CURRENT window computed by the ledger: decimal cumulative amount and a count */
  usage: unknown;
  /** an accepted exception lifts the per-transaction limit and nothing else */
  liftPerTransaction?: unknown;
}

export type CheckActionResult =
  | { ok: true; tier: number; required: RequiredBook[] }
  | { ok: false; reason: string; detail?: string };

interface Action {
  kind: string;
  chainId: number;
  source: string;
  beneficiary: string;
  asset: string;
  amount: string;
}

const denied = (reason: string, detail?: string): CheckActionResult => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });

function readAction(v: unknown): Action | null {
  if (!isPlainObject(v)) return null;
  const keys = Object.keys(v);
  const want = ['kind', 'chainId', 'source', 'beneficiary', 'asset', 'amount'];
  if (keys.length !== want.length || !want.every((k) => keys.includes(k))) return null;
  const { kind, chainId, source, beneficiary, asset, amount } = v;
  if (typeof kind !== 'string' || !(ACTION_KINDS as readonly string[]).includes(kind)) return null;
  if (typeof chainId !== 'number' || !Number.isSafeInteger(chainId) || chainId < 1) return null;
  if (typeof source !== 'string' || !ADDRESS_RE.test(source)) return null;
  if (typeof beneficiary !== 'string' || !ADDRESS_RE.test(beneficiary)) return null;
  if (typeof asset !== 'string' || !(asset === 'native' || ADDRESS_RE.test(asset))) return null;
  if (!isAmount(amount)) return null;
  return { kind, chainId, source, beneficiary, asset, amount };
}

function readUsage(v: unknown): { cumulative: bigint; count: number } | null {
  if (!isPlainObject(v)) return null;
  const keys = Object.keys(v);
  if (keys.length !== 2 || !keys.includes('cumulative') || !keys.includes('count')) return null;
  if (!isAmount(v['cumulative'])) return null;
  const c = v['count'];
  if (typeof c !== 'number' || !Number.isSafeInteger(c) || c < 0) return null;
  return { cumulative: BigInt(v['cumulative']), count: c };
}

function leftValue(field: string, a: Action, now: number): string | number {
  switch (field) {
    case 'action.kind': return a.kind;
    case 'action.chainId': return a.chainId;
    case 'action.amount': return a.amount;
    case 'action.beneficiary': return a.beneficiary;
    case 'action.source': return a.source;
    case 'action.asset': return a.asset;
    case 'time.hourUtc': return Math.floor(now / 3600) % 24;
    // 1970-01-01 was a Thursday; 0 is Sunday
    default: return (Math.floor(now / 86400) + 4) % 7;
  }
}

function compare(l: string | number, r: unknown, op: string, field: string): boolean {
  if (op === 'in') return (r as unknown[]).some((x) => x === l);
  if (op === 'nin') return !(r as unknown[]).some((x) => x === l);
  if (field === 'action.amount') {
    const a = BigInt(l as string);
    const b = BigInt(r as string);
    switch (op) {
      case 'eq': return a === b;
      case 'ne': return a !== b;
      case 'gt': return a > b;
      case 'gte': return a >= b;
      case 'lt': return a < b;
      default: return a <= b;
    }
  }
  switch (op) {
    case 'eq': return l === r;
    case 'ne': return l !== r;
    case 'gt': return (l as number) > (r as number);
    case 'gte': return (l as number) >= (r as number);
    case 'lt': return (l as number) < (r as number);
    default: return (l as number) <= (r as number);
  }
}

function holds(c: Condition, a: Action, now: number): boolean {
  if ('all' in c) return c.all.every((k) => holds(k, a, now));
  if ('any' in c) return c.any.some((k) => holds(k, a, now));
  if ('not' in c) return !holds(c.not, a, now);
  return compare(leftValue(c.field, a, now), c.value, c.op, c.field);
}

/**
 * Is this action inside the current Grant? The refusals are evaluated in the order of GRANT.md section 6 so that two
 * implementations name the same reason: malformed Grant, malformed action, malformed time or usage, subject
 * (unproven, then mismatch), validity, scope (action, source, beneficiary, asset), per-transaction, cumulative, count,
 * conditions; otherwise a permit with the first tier whose ceiling covers the amount and that tier's required books.
 */
export function checkAction(input: CheckActionInput): CheckActionResult {
  const g = validateGrant(input.grant);
  if (!g.ok) return denied('grant_malformed', g.reason + (g.detail ? ' ' + g.detail : ''));
  const grant = g.grant;
  const action = readAction(input.action);
  if (action === null) return denied('action_malformed');
  const now = input.now;
  if (typeof now !== 'number' || !Number.isSafeInteger(now) || now < 0) return denied('check_input_malformed', 'now');
  const usage = readUsage(input.usage);
  if (usage === null) return denied('check_input_malformed', 'usage');
  if (input.liftPerTransaction !== undefined && typeof input.liftPerTransaction !== 'boolean') return denied('check_input_malformed', 'liftPerTransaction');

  const s = input.subject;
  if (!isPlainObject(s) || Object.keys(s).length !== 2 || typeof s['adi'] !== 'string' || typeof s['type'] !== 'string' || !(SUBJECT_TYPES as readonly string[]).includes(s['type'])) return denied('subject_unproven');
  if (s['adi'] !== grant.subject.adi || s['type'] !== grant.subject.type) return denied('grant_subject_mismatch');

  const { notBefore, notAfter } = grant.validity;
  if (notAfter <= notBefore) return denied('grant_expired');
  if (now < notBefore) return denied('grant_not_yet_valid');
  if (now >= notAfter) return denied('grant_expired');

  if (!(grant.scope.actions as string[]).includes(action.kind)) return denied('action_not_in_scope');
  if (!grant.scope.accounts.some((x) => x.chainId === action.chainId && x.address === action.source)) return denied('source_not_in_scope');
  if (!grant.scope.beneficiaries.some((x) => x.chainId === action.chainId && x.address === action.beneficiary)) return denied('beneficiary_not_in_scope');
  if (!grant.scope.assets.some((x) => x.chainId === action.chainId && x.token === action.asset)) return denied('asset_not_in_scope');

  const limit = grant.limits.find((l) => l.asset.chainId === action.chainId && l.asset.token === action.asset);
  if (limit === undefined) return denied('asset_not_in_scope');
  const amount = BigInt(action.amount);
  if (input.liftPerTransaction !== true && amount > BigInt(limit.perTransaction)) return denied('limit_per_transaction_exceeded');
  if (usage.cumulative + amount > BigInt(limit.cumulative.amount)) return denied('limit_cumulative_exceeded');
  if (usage.count + 1 > limit.count.max) return denied('limit_count_exceeded');

  if (!holds(grant.conditions, action, now)) return denied('condition_failed');

  const approval = grant.approvals.find((a) => a.asset.chainId === action.chainId && a.asset.token === action.asset);
  if (approval === undefined) return denied('asset_not_in_scope');
  const tier = approval.tiers.findIndex((t) => t.upTo === null || amount <= BigInt(t.upTo));
  if (tier < 0) return denied('grant_malformed', 'no_open_tier');
  return { ok: true, tier, required: approval.tiers[tier]!.required.map((r) => ({ book: r.book, threshold: r.threshold })) };
}

// ---- lineage -------------------------------------------------------------------------------------------------

export interface LineageEntryInput {
  grant: unknown;
  /** `ok` or the reason the envelope check gave; anything else is a version that did not verify */
  envelopeVerdict: unknown;
}

export type GrantStatus = 'in_force' | 'ended' | 'not_yet_valid';
export type LineageResult =
  | { ok: true; head: { version: number; hash: string }; status: GrantStatus }
  | { ok: false; reason: string; detail?: string };

const lineageDenied = (reason: string, detail?: string): LineageResult => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });

/**
 * The versions of one grantId in data-entry order. Fail closed: an empty lineage, a fork, a gap, a broken prior hash,
 * a changed subject or grantor, a regressing issuedAt, a moved notBefore anchor, a malformed Grant or a version whose
 * envelope did not verify refuses the WHOLE lineage; no entry is ever skipped to use an earlier one.
 */
export function evaluateLineage(input: { entries: unknown; now: unknown }): LineageResult {
  const now = input.now;
  if (typeof now !== 'number' || !Number.isSafeInteger(now) || now < 0) return lineageDenied('lineage_input_malformed', 'now');
  const raw = input.entries;
  if (!Array.isArray(raw) || raw.length === 0) return lineageDenied('lineage_empty');

  const grants: Grant[] = [];
  const verdicts: unknown[] = [];
  for (let i = 0; i < raw.length; i++) {
    const e = raw[i];
    if (!isPlainObject(e) || !('grant' in e)) return lineageDenied('lineage_entry_malformed', 'entry ' + i);
    const g = validateGrant(e['grant']);
    if (!g.ok) return lineageDenied('lineage_entry_malformed', 'entry ' + i + ' ' + g.reason);
    grants.push(g.grant);
    verdicts.push(e['envelopeVerdict']);
  }
  const versions = new Set<number>();
  for (const g of grants) {
    if (versions.has(g.version)) return lineageDenied('lineage_fork', 'version ' + g.version);
    versions.add(g.version);
  }

  const first = grants[0]!;
  let prevHash = '';
  for (let i = 0; i < grants.length; i++) {
    const g = grants[i]!;
    const verdict = verdicts[i];
    if (typeof verdict !== 'string' || verdict !== 'ok') return lineageDenied('lineage_unverified_version', 'version ' + g.version + (typeof verdict === 'string' && verdict ? ' ' + verdict : ''));
    if (g.version !== i + 1) return lineageDenied('lineage_version_gap', 'entry ' + i + ' has version ' + g.version);
    if (i > 0) {
      const p = grants[i - 1]!;
      if (g.priorHash !== prevHash) return lineageDenied('lineage_prior_mismatch', 'version ' + g.version);
      if (g.subject.adi !== first.subject.adi || g.subject.type !== first.subject.type) return lineageDenied('lineage_subject_changed', 'version ' + g.version);
      if (g.grantor.adi !== first.grantor.adi || g.grantor.keyBook !== first.grantor.keyBook) return lineageDenied('lineage_grantor_changed', 'version ' + g.version);
      if (g.issuedAt < p.issuedAt) return lineageDenied('lineage_time_regress', 'version ' + g.version);
      if (g.validity.notBefore !== first.validity.notBefore) return lineageDenied('lineage_anchor_moved', 'version ' + g.version);
    }
    prevHash = hashGrant(g);
  }

  const head = grants[grants.length - 1]!;
  const { notBefore, notAfter } = head.validity;
  let status: GrantStatus = 'in_force';
  if (notAfter <= notBefore || now >= notAfter) status = 'ended';
  else if (now < notBefore) status = 'not_yet_valid';
  return { ok: true, head: { version: head.version, hash: prevHash }, status };
}
