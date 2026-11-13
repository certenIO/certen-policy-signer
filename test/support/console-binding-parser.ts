/**
 * THE CONSOLE'S REQUEST PARSER, COPIED AS A FIXTURE (no import across repos). Source: src/binding/wire.ts of branch pl/dax-4c-decision-binding
 * of the Console (transaction-controls) at commit 5e71d178db15efff3e79c568bcaf0c93ed8def9c; sha256 of that file with LF line endings 3db9b7a589f024d07465475173edd62b591fcff0939313a04ccd77765b224c6f.
 * Everything from `export interface BindingFields` to the end of `bindingOf` below is that file's text, unchanged; only the three import
 * lines differ (the signer's own copies of the core and of the PolicyRequest type). The file's header comment is not copied.
 * `bindingOf(request)` is what the Console does with the `PolicyRequest` the signer sends: a member that is not in the shape, an unknown member
 * or a missing member makes the request unbindable (`binding_malformed`), and a held request is never approved. test/binding-console-request-contract.test.ts
 * runs the REAL orchestrator's request through it. When the Console changes this file, re-copy it and the test says what the signer must now send.
 */
import { CoreError } from '../../src/core/bytes.js';
import { hashRequest } from '../../src/core/hashes.js';
import type { PolicyRequest } from '../../src/types.js';

export interface BindingFields {
  chainId: number;
  kind: string;
  source: string;
  target: string;
  beneficiary: string;
  asset: string;
  amount: string;
  executionCommitment: string;
  /** the validator's operation id (never the intent UUID, never the blob-3 hash) */
  validatorOperationId: string;
  txHash: string;
  /** how many legs the transaction has: the request hash binds ONE action, so anything but 1 is refused `multi_leg_unsupported` (DE-76) */
  legCount: number;
}

export interface GrantRefClaim { grantId: string; version: number; grantHash: string }

export type BindingRead =
  | { ok: true; fields: BindingFields; requestHash: string; grantRef: GrantRefClaim | null; leafExpiry: number | null; coreRequest: Record<string, unknown> }
  | { ok: false; reason: 'binding_absent' | 'binding_malformed' | 'binding_field_invalid'; detail?: string };

/** the members of a `binding` the Console requires (test/contract-drift.test.ts compares them with the signer's `PolicyBinding`) */
export const BINDING_WIRE_KEYS = ['chainId', 'kind', 'source', 'target', 'beneficiary', 'asset', 'amount', 'executionCommitment', 'validatorOperationId', 'txHash', 'legCount'] as const;
const KEYS = BINDING_WIRE_KEYS;
const HASH = /^0x[0-9a-f]{64}$/;

const refuse = (reason: 'binding_absent' | 'binding_malformed' | 'binding_field_invalid', detail?: string): BindingRead =>
  detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };

function isPlain(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/** The 0x form of an Accumulate transaction hash (the request carries 64 hex without the prefix). */
export const withHexPrefix = (h: string): string => (h.startsWith('0x') ? h : '0x' + h);

export function bindingOf(request: PolicyRequest): BindingRead {
  const raw = (request as unknown as { binding?: unknown }).binding;
  if (raw === undefined) return refuse('binding_absent');
  if (!isPlain(raw)) return refuse('binding_malformed', 'not an object');
  const allowed = new Set<string>([...KEYS, 'grantRef', 'leafExpiry']);
  for (const k of Object.keys(raw)) if (!allowed.has(k)) return refuse('binding_malformed', 'unknown member ' + k);
  for (const k of KEYS) if (!(k in raw)) return refuse('binding_malformed', 'missing member ' + k);

  let grantRef: GrantRefClaim | null = null;
  if ('grantRef' in raw && raw['grantRef'] !== null) {
    const g = raw['grantRef'];
    if (!isPlain(g) || Object.keys(g).sort().join(',') !== 'grantHash,grantId,version') return refuse('binding_malformed', 'grantRef');
    if (typeof g['grantId'] !== 'string' || typeof g['version'] !== 'number' || !Number.isSafeInteger(g['version']) || typeof g['grantHash'] !== 'string' || !HASH.test(g['grantHash'])) {
      return refuse('binding_field_invalid', 'grantRef');
    }
    grantRef = { grantId: g['grantId'], version: g['version'], grantHash: g['grantHash'] };
  }

  // the on-chain leaf expiry (the leaf's notAfter, Unix seconds): optional; the exposure window ends at the later of it and the decision's expiry
  let leafExpiry: number | null = null;
  if ('leafExpiry' in raw && raw['leafExpiry'] !== null) {
    const l = raw['leafExpiry'];
    if (typeof l !== 'number' || !Number.isSafeInteger(l) || l < 0) return refuse('binding_field_invalid', 'leafExpiry');
    leafExpiry = l;
  }

  // the transaction the binding names must be the transaction the request is about
  if (typeof raw['txHash'] !== 'string' || withHexPrefix(request.txHash).toLowerCase() !== raw['txHash']) return refuse('binding_field_invalid', 'txHash differs from the request');
  // the validator id must be a plain 32-byte hash: a UUID (the intent_id) is refused here, by name, before any hash is built
  if (typeof raw['validatorOperationId'] !== 'string' || !HASH.test(raw['validatorOperationId'])) return refuse('binding_field_invalid', 'validatorOperationId is not a 0x 32-byte hash');

  // the signer always supplies the leg count it derived from the transaction (DE-76): a binding without one, or a non-positive one, is malformed
  if (typeof raw['legCount'] !== 'number' || !Number.isSafeInteger(raw['legCount']) || raw['legCount'] < 1) return refuse('binding_field_invalid', 'legCount');
  const fields = Object.fromEntries(KEYS.map((k) => [k, raw[k]])) as unknown as BindingFields;
  const coreRequest: Record<string, unknown> = {
    chainId: fields.chainId,
    kind: fields.kind,
    source: fields.source,
    target: fields.target,
    beneficiary: fields.beneficiary,
    asset: fields.asset,
    amount: fields.amount,
    executionCommitment: fields.executionCommitment,
    operationId: fields.validatorOperationId,
    txHash: fields.txHash,
  };
  try {
    return { ok: true, fields, requestHash: hashRequest(coreRequest), grantRef, leafExpiry, coreRequest };
  } catch (e) {
    if (e instanceof CoreError) return refuse('binding_field_invalid', e.code + (e.detail ? ' ' + e.detail : ''));
    throw e;
  }
}
