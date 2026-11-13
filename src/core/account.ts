/**
 * The ACCOUNT AUTHORITY RULE (GRANT.md section 4a, GR-58): the one online gate of the core.
 *
 * Accumulate itself enforced who may write every data entry at execution time, and an entry is immutable. So what an
 * online reader must establish is not which keys signed an envelope but that the account's authority set WAS and IS the
 * intended one: exactly the owner's key book, never a book of the subject, with no change of authority since the account
 * was created. A routine key rotation does not change any of these facts, so it can never brick a Grant or a registration
 * (GR-59): no online verdict reads a key page, at any time.
 *
 * Inputs are facts the caller's reader obtained: the authority set NOW, and the transaction types of the account's own
 * main chain from its creation (with an `incomplete` signal when the chain could not be read back that far). The
 * SAFE_AFTER list is the reader's constant: the transaction types that may follow the creation without changing the
 * authority. Anything outside it refuses by name; the list is confirmed against real chain types by DAX-3-A15.
 */
import { isPlainObject } from './bytes.js';
import { isAccUrl, isUnderAdi } from './grant-profile.js';

/** The transaction types that may follow the creation of a data account without changing who may write to it. */
export const SAFE_AFTER: readonly string[] = ['writeData', 'writeDataTo'];
/** The transaction type that creates a data account; the main chain must start with it, else the history is incomplete. */
export const CREATION_TYPES: readonly string[] = ['createDataAccount'];

export interface AccountFacts {
  /** the key book that owns the account (the grantor's book for certen-grants, the subject's for certen-acceptances) */
  ownerBook: string;
  /** the authority set now, or null when it could not be read */
  authorities: string[] | null;
  /** main-chain transaction types from the creation, in order, or null when unreadable; `incomplete` when the creation was not reached */
  history: Array<{ type: string }> | null;
  /** an explicit incomplete signal from the reader (the chain could not be read back to the creation) */
  incomplete?: boolean;
}

export type AccountAuthorityResult =
  | { ok: true }
  | { ok: false; reason: AccountRefusal; index?: number };

export type AccountRefusal =
  | 'account_authority_unreadable'
  | 'account_history_unreadable'
  | 'account_history_incomplete'
  | 'account_authority_includes_subject'
  | 'account_authority_not_owner_only'
  | 'account_authority_changed';

const refuse = (reason: AccountRefusal, index?: number): AccountAuthorityResult => (index === undefined ? { ok: false, reason } : { ok: false, reason, index });

/**
 * Order of refusals: account_authority_unreadable, account_history_unreadable, account_authority_includes_subject (a book
 * of the subject next to the owner), account_authority_not_owner_only (anything but exactly the owner book),
 * account_history_incomplete (the main chain does not start at the creation), account_authority_changed (a transaction
 * type outside the safe-after list, with the index of the first one).
 */
export function checkAccountAuthority(input: { ownerBook: unknown; forbiddenBooks?: unknown; subjectAdi?: unknown; authorities: unknown; history: unknown; incomplete?: unknown; safeAfter: unknown }): AccountAuthorityResult {
  const owner = input.ownerBook;
  if (!isAccUrl(owner)) return refuse('account_authority_unreadable');
  const forbidden = input.forbiddenBooks === undefined ? [] : input.forbiddenBooks;
  const safe = input.safeAfter;
  if (!Array.isArray(forbidden) || !forbidden.every((b) => typeof b === 'string') || !Array.isArray(safe) || !safe.every((t) => typeof t === 'string')) return refuse('account_authority_unreadable');
  if (!Array.isArray(input.authorities) || !input.authorities.every((a) => isAccUrl(a))) return refuse('account_authority_unreadable');
  const history = input.history;
  if (!Array.isArray(history) || !history.every((h) => isPlainObject(h) && typeof h['type'] === 'string')) return refuse('account_history_unreadable');

  const authorities = input.authorities as string[];
  const subjectAdi = typeof input.subjectAdi === 'string' ? input.subjectAdi : undefined;
  if (authorities.some((a) => (forbidden as string[]).includes(a) || (subjectAdi !== undefined && isUnderAdi(a, subjectAdi)))) return refuse('account_authority_includes_subject');
  if (authorities.length !== 1 || authorities[0] !== owner) return refuse('account_authority_not_owner_only');
  const types = (history as Array<{ type: string }>).map((h) => h.type);
  if (input.incomplete === true || types.length === 0 || !CREATION_TYPES.includes(types[0]!)) return refuse('account_history_incomplete');
  for (let i = 1; i < types.length; i++) if (!(safe as string[]).includes(types[i]!)) return refuse('account_authority_changed', i);
  return { ok: true };
}
