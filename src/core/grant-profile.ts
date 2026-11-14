/**
 * The Grant profile (GRANT.md sections 2 and 3): the closed object certen.grant/v1, its strict validation and its
 * canonical text. Every refusal is a named reason; nothing is partially evaluated.
 */
import { CoreError, ADDRESS_RE, HASH_RE, MAX_UINT256, isAmount, isPlainObject, utf8Length, type Json } from './bytes.js';
import { canonicalize, parseJson } from './jcs.js';

export const GRANT_SCHEMA = 'certen.grant/v1';
/** the closed action set (GR-84): three typed kinds and `raw`, the kind of a single call that no typed kind describes (GRANT.md section 6a); a decoder never answers raw */
export const ACTION_KINDS = ['erc20.transfer', 'erc20.approve', 'native.transfer', 'raw'] as const;
export type ActionKind = (typeof ACTION_KINDS)[number];
export const SUBJECT_TYPES = ['agent', 'merchant', 'client'] as const;
export type SubjectType = (typeof SUBJECT_TYPES)[number];

export interface ChainAddress { chainId: number; address: string }
export interface AssetRef { chainId: number; token: string }
export interface RequiredBook { book: string; threshold: number }
export interface Tier { upTo: string | null; required: RequiredBook[] }
export type Condition =
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | { field: string; op: string; value: Json };

export interface Grant {
  schema: 'certen.grant/v1';
  grantId: string;
  version: number;
  priorHash: string | null;
  issuedAt: number;
  subject: { type: SubjectType; adi: string };
  grantor: { adi: string; keyBook: string };
  scope: { actions: ActionKind[]; accounts: ChainAddress[]; beneficiaries: ChainAddress[]; assets: AssetRef[] };
  limits: Array<{ asset: AssetRef; perTransaction: string; cumulative: { amount: string; periodSeconds: number }; count: { max: number; periodSeconds: number } }>;
  validity: { notBefore: number; notAfter: number };
  approvals: Array<{ asset: AssetRef; tiers: Tier[] }>;
  conditions: Condition;
}

export type GrantValidation = { ok: true; grant: Grant } | { ok: false; reason: string; detail?: string };

/** GR-46: the profile size limits are part of the specification. conditionDepth and conditionNodes are GR-21; inList is this library's bound on one in/nin list (inside the 64-node budget). */
export const LIMITS = { textBytes: 65536, scopeEntries: 64, tiers: 16, required: 16, conditionDepth: 8, conditionNodes: 64, inList: 64 };

const GRANT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const URL_SEGMENT_RE = /^[a-z0-9][a-z0-9._-]*$/;

class Refusal extends Error {
  constructor(readonly reason: string, readonly detail?: string) {
    super(reason);
  }
}
const fail = (reason: string, path: string): never => {
  throw new Refusal(reason, path);
};

/** acc:// URL: lowercase, non-empty segments of [a-z0-9._-], no query, no fragment, no trailing slash. */
export function isAccUrl(v: unknown): v is string {
  if (typeof v !== 'string' || v.length > 512 || !v.startsWith('acc://')) return false;
  const segs = v.slice(6).split('/');
  return segs.length >= 1 && segs.every((s) => URL_SEGMENT_RE.test(s));
}
/** an ADI URL has exactly one segment */
export function isAdiUrl(v: unknown): v is string {
  return isAccUrl(v) && !v.slice(6).includes('/');
}
export function hostOf(url: string): string {
  return url.slice(6).split('/')[0]!;
}
/**
 * True when `url` is the subject ADI, lies under it, or belongs to a sub-ADI of it (a sub-ADI host is
 * `<name>.<subject host>`, a text prefix is NOT the relation: acc://agent-7.x.acme-extra is another ADI).
 */
export function isUnderAdi(url: string, adi: string): boolean {
  const h = hostOf(url);
  const s = hostOf(adi);
  return h === s || h.endsWith('.' + s);
}

function obj(v: unknown, path: string, keys: readonly string[]): Record<string, unknown> {
  if (!isPlainObject(v)) return fail('grant_field_invalid', path);
  const have = Object.keys(v);
  for (const k of have) if (!keys.includes(k)) fail('grant_unknown_field', path + '.' + k);
  for (const k of keys) if (!have.includes(k)) fail('grant_missing_field', path + '.' + k);
  return v;
}
function arr(v: unknown, path: string, max: number, min = 0): unknown[] {
  if (!Array.isArray(v) || v.length < min) return fail('grant_field_invalid', path);
  if (v.length > max) return fail('grant_too_large', path);
  return v;
}
function int(v: unknown, path: string, min: number): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || Object.is(v, -0)) return fail('grant_field_invalid', path);
  return v;
}
function str(v: unknown, path: string, re: RegExp): string {
  if (typeof v !== 'string' || !re.test(v)) return fail('grant_field_invalid', path);
  return v;
}
function amount(v: unknown, path: string): string {
  if (!isAmount(v)) return fail('grant_field_invalid', path);
  return v;
}
function adi(v: unknown, path: string): string {
  if (!isAdiUrl(v)) return fail('grant_field_invalid', path);
  return v;
}
function bookUrl(v: unknown, path: string): string {
  if (!isAccUrl(v) || !v.slice(6).includes('/')) return fail('grant_field_invalid', path);
  return v;
}
function chainAddress(v: unknown, path: string): ChainAddress {
  const o = obj(v, path, ['chainId', 'address']);
  return { chainId: int(o['chainId'], path + '.chainId', 1), address: str(o['address'], path + '.address', ADDRESS_RE) };
}
function assetRef(v: unknown, path: string): AssetRef {
  const o = obj(v, path, ['chainId', 'token']);
  const token = o['token'];
  if (token !== 'native') str(token, path + '.token', ADDRESS_RE);
  return { chainId: int(o['chainId'], path + '.chainId', 1), token: token as string };
}
const assetKey = (a: AssetRef): string => a.chainId + ':' + a.token;

// ---- conditions ----------------------------------------------------------------------------------------------

type FieldKind = 'kind' | 'int' | 'amount' | 'address' | 'asset' | 'hour' | 'weekday';
const FIELD_KINDS: Record<string, FieldKind> = {
  'action.kind': 'kind',
  'action.chainId': 'int',
  'action.amount': 'amount',
  'action.beneficiary': 'address',
  'action.source': 'address',
  'action.asset': 'asset',
  'time.hourUtc': 'hour',
  'time.weekdayUtc': 'weekday',
};
const OPS_ALL = ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'nin'];
const OPS_EQ = ['eq', 'ne', 'in', 'nin'];
export const CONDITION_FIELDS = Object.keys(FIELD_KINDS);
const OPS_FOR: Record<FieldKind, string[]> = { kind: OPS_EQ, int: OPS_ALL, amount: OPS_ALL, address: OPS_EQ, asset: OPS_EQ, hour: OPS_ALL, weekday: OPS_ALL };

function conditionScalar(kind: FieldKind, v: unknown): boolean {
  switch (kind) {
    case 'kind': return typeof v === 'string' && (ACTION_KINDS as readonly string[]).includes(v);
    case 'int': return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
    case 'amount': return isAmount(v);
    case 'address': return typeof v === 'string' && ADDRESS_RE.test(v);
    case 'asset': return v === 'native' || (typeof v === 'string' && ADDRESS_RE.test(v));
    case 'hour': return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= 23;
    case 'weekday': return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= 6;
  }
}

function validateCondition(node: unknown, depth: number, count: { n: number }, path: string): Condition {
  if (depth > LIMITS.conditionDepth) return fail('condition_too_large', path);
  count.n++;
  if (count.n > LIMITS.conditionNodes) return fail('condition_too_large', path);
  if (!isPlainObject(node)) return fail('grant_conditions_invalid', path);
  const keys = Object.keys(node);
  const comb = keys.filter((k) => k === 'all' || k === 'any' || k === 'not');
  if (comb.length > 0) {
    if (keys.length !== 1) return fail('grant_conditions_invalid', path);
    const k = comb[0]!;
    const child = node[k];
    if (k === 'not') return { not: validateCondition(child, depth + 1, count, path + '.not') };
    if (!Array.isArray(child) || (k === 'any' && child.length === 0)) return fail('grant_conditions_invalid', path + '.' + k);
    const kids = child.map((c, i) => validateCondition(c, depth + 1, count, path + '.' + k + '[' + i + ']'));
    return k === 'all' ? { all: kids } : { any: kids };
  }
  if (keys.length !== 3 || !keys.includes('field') || !keys.includes('op') || !keys.includes('value')) return fail('grant_conditions_invalid', path);
  const field = node['field'];
  if (typeof field !== 'string' || !(field in FIELD_KINDS) || !Object.prototype.hasOwnProperty.call(FIELD_KINDS, field)) return fail('condition_unknown_field', path + '.field');
  const kind = FIELD_KINDS[field]!;
  const op = node['op'];
  if (typeof op !== 'string' || !OPS_ALL.includes(op) || !OPS_FOR[kind].includes(op)) return fail('condition_unknown_operator', path + '.op');
  const value = node['value'];
  if (op === 'in' || op === 'nin') {
    if (!Array.isArray(value) || value.length === 0 || value.length > LIMITS.inList || !value.every((x) => conditionScalar(kind, x))) return fail('condition_value_invalid', path + '.value');
    if (new Set(value.map((x) => String(x))).size !== value.length) return fail('condition_value_invalid', path + '.value');
  } else if (!conditionScalar(kind, value)) return fail('condition_value_invalid', path + '.value');
  return { field, op, value: value as Json };
}

// ---- the Grant -----------------------------------------------------------------------------------------------

function validate(v: unknown): void {
  const g = obj(v, '$', ['schema', 'grantId', 'version', 'priorHash', 'issuedAt', 'subject', 'grantor', 'scope', 'limits', 'validity', 'approvals', 'conditions']);
  if (g['schema'] !== GRANT_SCHEMA) fail('grant_field_invalid', '$.schema');
  str(g['grantId'], '$.grantId', GRANT_ID_RE);
  const version = int(g['version'], '$.version', 1);
  const prior = g['priorHash'];
  if (prior !== null) str(prior, '$.priorHash', HASH_RE);
  int(g['issuedAt'], '$.issuedAt', 0);

  const subject = obj(g['subject'], '$.subject', ['type', 'adi']);
  if (typeof subject['type'] !== 'string' || !(SUBJECT_TYPES as readonly string[]).includes(subject['type'])) fail('grant_field_invalid', '$.subject.type');
  const subjectAdi = adi(subject['adi'], '$.subject.adi');
  const grantor = obj(g['grantor'], '$.grantor', ['adi', 'keyBook']);
  const grantorAdi = adi(grantor['adi'], '$.grantor.adi');
  const keyBook = bookUrl(grantor['keyBook'], '$.grantor.keyBook');
  if (!keyBook.startsWith(grantorAdi + '/')) fail('grant_field_invalid', '$.grantor.keyBook');
  if (isUnderAdi(grantorAdi, subjectAdi)) fail('grantor_is_subject', '$.grantor.adi');

  if ((version === 1) !== (prior === null)) fail('grant_lineage_invalid', '$.priorHash');

  const scope = obj(g['scope'], '$.scope', ['actions', 'accounts', 'beneficiaries', 'assets']);
  const actions = arr(scope['actions'], '$.scope.actions', ACTION_KINDS.length);
  for (const a of actions) if (typeof a !== 'string' || !(ACTION_KINDS as readonly string[]).includes(a)) fail('grant_field_invalid', '$.scope.actions');
  // GR-84: each kind at most once
  if (new Set(actions).size !== actions.length) fail('grant_field_invalid', '$.scope.actions');
  arr(scope['accounts'], '$.scope.accounts', LIMITS.scopeEntries).forEach((a, i) => chainAddress(a, '$.scope.accounts[' + i + ']'));
  arr(scope['beneficiaries'], '$.scope.beneficiaries', LIMITS.scopeEntries).forEach((a, i) => chainAddress(a, '$.scope.beneficiaries[' + i + ']'));
  const assets = arr(scope['assets'], '$.scope.assets', LIMITS.scopeEntries, 1).map((a, i) => assetRef(a, '$.scope.assets[' + i + ']'));
  const assetKeys = assets.map(assetKey);
  if (new Set(assetKeys).size !== assetKeys.length) fail('grant_field_invalid', '$.scope.assets');

  const limits = arr(g['limits'], '$.limits', LIMITS.scopeEntries);
  const limitKeys: string[] = [];
  limits.forEach((l, i) => {
    const p = '$.limits[' + i + ']';
    const o = obj(l, p, ['asset', 'perTransaction', 'cumulative', 'count']);
    limitKeys.push(assetKey(assetRef(o['asset'], p + '.asset')));
    const per = BigInt(amount(o['perTransaction'], p + '.perTransaction'));
    const cum = obj(o['cumulative'], p + '.cumulative', ['amount', 'periodSeconds']);
    const cumAmount = BigInt(amount(cum['amount'], p + '.cumulative.amount'));
    int(cum['periodSeconds'], p + '.cumulative.periodSeconds', 60);
    const cnt = obj(o['count'], p + '.count', ['max', 'periodSeconds']);
    int(cnt['max'], p + '.count.max', 1);
    int(cnt['periodSeconds'], p + '.count.periodSeconds', 60);
    if (cumAmount < per || cumAmount > MAX_UINT256) fail('grant_limits_inconsistent', p);
  });
  if (limitKeys.length !== assetKeys.length || new Set(limitKeys).size !== limitKeys.length || !assetKeys.every((k) => limitKeys.includes(k))) fail('grant_limits_coverage', '$.limits');

  const validity = obj(g['validity'], '$.validity', ['notBefore', 'notAfter']);
  const notBefore = int(validity['notBefore'], '$.validity.notBefore', 0);
  const notAfter = int(validity['notAfter'], '$.validity.notAfter', 0);
  if (notAfter < notBefore || (version === 1 && notAfter === notBefore)) fail('grant_validity_invalid', '$.validity');

  const approvals = arr(g['approvals'], '$.approvals', LIMITS.scopeEntries);
  const approvalKeys: string[] = [];
  approvals.forEach((a, i) => {
    const p = '$.approvals[' + i + ']';
    const o = obj(a, p, ['asset', 'tiers']);
    approvalKeys.push(assetKey(assetRef(o['asset'], p + '.asset')));
    const tiers = arr(o['tiers'], p + '.tiers', LIMITS.tiers);
    if (tiers.length === 0) fail('grant_tiers_invalid', p + '.tiers');
    let prev: bigint | null = null;
    tiers.forEach((t, j) => {
      const tp = p + '.tiers[' + j + ']';
      const to = obj(t, tp, ['upTo', 'required']);
      const last = j === tiers.length - 1;
      if (last) {
        if (to['upTo'] !== null) fail('grant_tiers_invalid', tp + '.upTo');
      } else {
        if (to['upTo'] === null) fail('grant_tiers_invalid', tp + '.upTo');
        const up = BigInt(amount(to['upTo'], tp + '.upTo'));
        if (prev !== null && up <= prev) fail('grant_tiers_invalid', tp + '.upTo');
        prev = up;
      }
      const req = arr(to['required'], tp + '.required', LIMITS.required);
      if (req.length === 0) fail('grant_tiers_invalid', tp + '.required');
      const books = new Set<string>();
      req.forEach((r, k) => {
        const rp = tp + '.required[' + k + ']';
        const ro = obj(r, rp, ['book', 'threshold']);
        const bookValue = ro['book'];
        if (isAccUrl(bookValue) && isUnderAdi(bookValue, subjectAdi)) fail('grant_approver_is_subject', rp + '.book');
        const book = bookUrl(bookValue, rp + '.book');
        int(ro['threshold'], rp + '.threshold', 1);
        if (books.has(book)) fail('grant_tiers_invalid', rp + '.book');
        books.add(book);
      });
    });
  });
  if (approvalKeys.length !== assetKeys.length || new Set(approvalKeys).size !== approvalKeys.length || !assetKeys.every((k) => approvalKeys.includes(k))) fail('grant_approvals_coverage', '$.approvals');

  validateCondition(g['conditions'], 1, { n: 0 }, '$.conditions');
}

/** Validates an already-parsed value as a Grant and returns a clean deep copy (later mutation of the input cannot affect it). */
export function validateGrant(value: unknown): GrantValidation {
  try {
    validate(value);
    const canonicalText = canonicalize(value);
    if (utf8Length(canonicalText) > LIMITS.textBytes) fail('grant_too_large', '$');
    return { ok: true, grant: parseJson(canonicalText, { integersOnly: true }) as unknown as Grant };
  } catch (e) {
    if (e instanceof Refusal) return e.detail === undefined ? { ok: false, reason: e.reason } : { ok: false, reason: e.reason, detail: e.detail };
    if (e instanceof CoreError) return { ok: false, reason: 'grant_field_invalid', detail: e.code };
    throw e;
  }
}

export function canonicalGrant(grant: unknown): string {
  const v = validateGrant(grant);
  if (!v.ok) throw new CoreError(v.reason, v.detail);
  return canonicalize(v.grant);
}

export type ParseGrantResult =
  | { ok: true; grant: Grant; canonical: string; grantHash: string }
  | { ok: false; reason: string; detail?: string };

/** Strict parse of Grant text: duplicates, lone surrogates and non-integer numbers refuse; then the profile. */
export function parseGrantTextUnhashed(text: string): { ok: true; grant: Grant; canonical: string } | { ok: false; reason: string; detail?: string } {
  if (utf8Length(text) > LIMITS.textBytes) return { ok: false, reason: 'grant_too_large' };
  let value: Json;
  try {
    value = parseJson(text, { integersOnly: true });
  } catch (e) {
    if (e instanceof CoreError) return { ok: false, reason: 'grant_' + e.code };
    throw e;
  }
  const v = validateGrant(value);
  if (!v.ok) return v;
  return { ok: true, grant: v.grant, canonical: canonicalize(v.grant) };
}
