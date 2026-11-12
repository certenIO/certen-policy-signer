/**
 * Test support for the DAX-4S decision binding: FICTIONAL pending intents, decision records and a fake world. Every party,
 * key label, address and amount is invented. Nothing here reads a secret, a file outside the repository or the network.
 */
import { createHash } from 'node:crypto';
import type { BindingWorld } from '../../src/binding/world.js';

export const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
export const H = (label: string): string => '0x' + sha(label);
export const KEY = (label: string): string => 'key:' + sha('pubkey:' + label);

export const ADDR = {
  treasury: '0x' + '11'.repeat(20),
  token: '0x' + '22'.repeat(20),
  vendorA: '0x' + '33'.repeat(20),
  vendorB: '0x' + '44'.repeat(20),
  other: '0x' + '55'.repeat(20),
};
export const SEAT = 'seat:fic-treasury';
export const SUBJECT = { adi: 'acc://agent-one.fic-grantor.acme', type: 'agent' as const };
export const GRANTOR = 'acc://fic-grantor.acme';
export const PRINCIPAL = 'acc://fic-principal.acme';
export const POLICY = H('policy-v1');
export const GRANT_HASH = H('grant-v1');
export const APPROVER = KEY('officer-a');

const hex = (o: unknown): string => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
const word = (v: string): string => v.replace(/^0x/, '').padStart(64, '0');

export interface LegOpts {
  kind?: 'native' | 'erc20.transfer' | 'erc20.approve' | 'erc20.transferFrom';
  chainId?: number;
  from?: string;
  token?: string;
  to?: string;
  amount?: string;
  commitment?: string;
  /** replaces the whole executionPayload members (e.g. to break one) */
  payloadOverride?: Record<string, unknown>;
  legOverride?: Record<string, unknown>;
}

export function leg(o: LegOpts = {}): Record<string, unknown> {
  const kind = o.kind ?? 'erc20.transfer';
  const from = o.from ?? ADDR.treasury;
  const amount = o.amount ?? '300';
  const chainId = o.chainId ?? 84532;
  let target: string;
  let callData: string;
  let value: string;
  if (kind === 'native') {
    target = o.to ?? ADDR.vendorA;
    callData = '0x';
    value = amount;
  } else {
    target = o.token ?? ADDR.token;
    value = '0';
    const sel = kind === 'erc20.transfer' ? 'a9059cbb' : kind === 'erc20.approve' ? '095ea7b3' : '23b872dd';
    const args = kind === 'erc20.transferFrom' ? word(from) + word(o.to ?? ADDR.vendorA) + word(BigInt(amount).toString(16)) : word(o.to ?? ADDR.vendorA) + word(BigInt(amount).toString(16));
    callData = '0x' + sel + args;
  }
  return {
    legId: 'leg-1', chain: 'base-sepolia', chainId, from, to: target, amountWei: value, asset: { symbol: 'FICUSD' },
    executionPayload: { target, value, callData, chainId, executionCommitment: o.commitment ?? H('commit-1'), ...(o.payloadOverride ?? {}) },
    ...(o.legOverride ?? {}),
  };
}

export interface IntentOpts {
  legs?: Array<Record<string, unknown>>;
  grantRef?: unknown;
  subject?: unknown;
  extra0?: Record<string, unknown>;
  blob3?: Record<string, unknown>;
}

/** A CERTEN writeData body whose four blobs follow the published shape; returns the body and the raw blobs. */
export function intentBody(o: IntentOpts = {}): { type: 'writeData'; entry: { type: string; data: string[] } } {
  const blob0 = {
    kind: 'CERTEN_INTENT', version: '2.0', intentType: 'single_leg_cross_chain_transfer', description: 'FICTIONAL payment',
    organizationAdi: PRINCIPAL, intent_id: '5b0c6e0a-3c1e-4d57-9c1a-0d3a3c7b9e11', created_by: PRINCIPAL,
    ...(o.grantRef !== undefined ? { grantRef: o.grantRef } : {}),
    ...(o.subject !== undefined ? { subject: o.subject } : {}),
    ...(o.extra0 ?? {}),
  };
  const blob1 = { protocol: 'CERTEN', version: '2.0', legs: o.legs ?? [leg()] };
  const blob2 = { organizationAdi: PRINCIPAL, authorization: { signature_threshold: 1 } };
  const blob3 = { nonce: 'n-1', intent_hash: H('bridge-intent-hash'), ...(o.blob3 ?? {}) };
  return { type: 'writeData', entry: { type: 'doubleHash', data: [blob0, blob1, blob2, blob3].map(hex) } };
}

export const subjectClaim = (adi = SUBJECT.adi, assertedBy = PRINCIPAL): Record<string, string> => ({ adi, assertedBy });

/** the decision record the Console would issue (certen.decision/v1), the hash fields filled by the caller */
export interface RecordOpts {
  requestHash: string;
  decision?: 'approve' | 'deny';
  grantHash?: string | null;
  policyHash?: string;
  seat?: string;
  approver?: string;
  nonce?: string;
  issuedAt: number;
  expiresAt?: number;
  reason?: string;
}
export function record(o: RecordOpts): Record<string, unknown> {
  return {
    schema: 'certen.decision/v1',
    decision: o.decision ?? 'approve',
    requestHash: o.requestHash,
    grantHash: o.grantHash === undefined ? null : o.grantHash,
    policyHash: o.policyHash ?? POLICY,
    seat: o.seat ?? SEAT,
    approver: o.approver ?? APPROVER,
    nonce: o.nonce ?? H('nonce-' + Math.random()),
    issuedAt: o.issuedAt,
    expiresAt: o.expiresAt ?? o.issuedAt + 3600,
    reason: o.reason ?? 'FICTIONAL approval by the treasury officers',
  };
}

export interface FakeWorld extends BindingWorld {
  head: { hash: string; subject: { adi: string; type: 'agent' | 'merchant' | 'client' } } | null;
  resolved: { adi: string; type: 'agent' | 'merchant' | 'client' } | null;
  calls: string[];
}
export function fakeWorld(over: Partial<Pick<FakeWorld, 'head' | 'resolved'>> = {}): FakeWorld {
  const w: FakeWorld = {
    head: over.head === undefined ? { hash: GRANT_HASH, subject: { ...SUBJECT } } : over.head,
    resolved: over.resolved === undefined ? { ...SUBJECT } : over.resolved,
    calls: [],
    async grantHead() { w.calls.push('grantHead'); return w.head === null ? { ok: false, detail: 'unreadable' } : { ok: true, value: w.head }; },
    async resolveSubject() { w.calls.push('resolveSubject'); return w.resolved === null ? { ok: false, detail: 'not_registered' } : { ok: true, value: w.resolved }; },
  };
  return w;
}
