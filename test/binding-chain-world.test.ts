/**
 * The production BindingWorld (src/binding/chain-world.ts) over the node source and the read cache, against a FAKE API v3 node,
 * under the ONLINE reader model of READER-MODEL-V2: the gate is the account authority rule and the account's own main chain from
 * its creation; NO key page is read; a Grant's subject resolves only through the GRANTOR's registry and the subject's own
 * acceptance account. Real Ed25519 keys sign real envelopes (generated in memory, never written, never printed): the envelope is
 * OFFLINE evidence, so a rotated key changes nothing here (DAX2-L9).
 */
import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createChainWorld } from '../src/binding/chain-world.js';
import { ReadCache } from '../src/binding/read-cache.js';
import { buildEnvelope, encodeGrantEntry, encodeRegistrationEntry } from '../src/core/envelope.js';
import { encodeAcceptanceEntry } from '../src/core/acceptance.js';
import { hashGrant, hashRegistration, envelopeDigest } from '../src/core/hashes.js';
import type { Grant } from '../src/core/grant-profile.js';
import { ADDR } from './support/binding-fixtures.js';
import { FakeNode } from './support/fake-node.js';

const GRANTOR = 'acc://fic-grantor.acme';
const BOOK = `${GRANTOR}/book`;
const SUBJECT = 'acc://agent-one.fic-grantor.acme';
const GRANTS = `${GRANTOR}/certen-grants`;
const REGISTRY = `${GRANTOR}/certen-subjects`;
const ACCEPT = `${SUBJECT}/certen-acceptances`;
const NOW = 1_800_000_500;
const T_REG = 1_800_000_100;

function key() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from((publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url');
  return { pubHex: raw.toString('hex'), sign: (d: Uint8Array) => sign(null, d, privateKey).toString('hex'), hash: createHash('sha256').update(raw).digest('hex') };
}
const oldKey = key(); // the key the entries were signed with: it is on NO key page of the fake node (a rotation happened)

function grant(over: Partial<Grant> = {}): Grant {
  const asset = { chainId: 84532, token: ADDR.token };
  return {
    schema: 'certen.grant/v1', grantId: 'fic-agent-pay', version: 1, priorHash: null, issuedAt: 1_800_000_000,
    subject: { type: 'agent', adi: SUBJECT }, grantor: { adi: GRANTOR, keyBook: BOOK },
    scope: { actions: ['erc20.transfer'], accounts: [{ chainId: 84532, address: ADDR.treasury }], beneficiaries: [{ chainId: 84532, address: ADDR.vendorA }], assets: [asset] },
    limits: [{ asset, perTransaction: '1000', cumulative: { amount: '5000', periodSeconds: 86400 }, count: { max: 3, periodSeconds: 86400 } }],
    validity: { notBefore: 1_800_000_000, notAfter: 1_810_000_000 },
    approvals: [{ asset, tiers: [{ upTo: null, required: [{ book: `${GRANTOR}/treasury`, threshold: 1 }] }] }],
    conditions: { all: [] },
    ...over,
  };
}
function grantElements(g: Grant): Uint8Array[] {
  const h = hashGrant(g);
  const page = `${BOOK}/1`;
  return encodeGrantEntry(g, buildEnvelope('certen:grant:v1', h, [{ alg: 'ed25519', page, publicKey: oldKey.pubHex, signature: oldKey.sign(envelopeDigest('certen:grant:v1', h, page)) }]));
}
function registration(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { schema: 'certen.subject/v2', adi: SUBJECT, version: 1, priorHash: null, type: 'agent', principal: { adi: GRANTOR, keyBook: BOOK }, responsibleSeat: 'seat:fic-treasury', submitters: [], status: 'active', registeredAt: T_REG, ...over };
}
function registrationElements(r: Record<string, unknown>): Uint8Array[] {
  const h = hashRegistration(r);
  const page = `${(r['principal'] as { keyBook: string }).keyBook}/1`;
  return encodeRegistrationEntry(r, buildEnvelope('certen:subject:v2', h, [{ alg: 'ed25519', page, publicKey: oldKey.pubHex, signature: oldKey.sign(envelopeDigest('certen:subject:v2', h, page)) }]));
}
const acceptance = (action: 'accept' | 'revoke', over: Record<string, unknown> = {}) => encodeAcceptanceEntry({ schema: 'certen.acceptance/v1', subject: SUBJECT, principal: GRANTOR, registry: REGISTRY, action, ...over });

/** the whole scene: the grantor's grants account and registry (owned by the grantor's book), the subject ADI and its acceptance account */
function scene(o: { grants?: Grant[]; registrations?: Array<{ r: Record<string, unknown>; time?: number }>; acceptances?: Array<{ action: 'accept' | 'revoke'; time: number }> | null } = {}) {
  const node = new FakeNode();
  node.dataAccount(GRANTS, [BOOK]);
  for (const g of o.grants ?? [grant()]) node.write(GRANTS, grantElements(g));
  node.dataAccount(REGISTRY, [BOOK]);
  for (const x of o.registrations ?? [{ r: registration(), time: T_REG }]) node.write(REGISTRY, registrationElements(x.r), x.time);
  node.identity(SUBJECT, [`${SUBJECT}/book`]);
  if (o.acceptances !== null) {
    node.dataAccount(ACCEPT, [`${SUBJECT}/book`]);
    for (const a of o.acceptances ?? [{ action: 'accept' as const, time: T_REG - 10 }]) node.write(ACCEPT, acceptance(a.action), a.time);
  }
  const cache = new ReadCache(node.query, { now: () => Date.now() });
  const world = createChainWorld({ evaluation: () => cache.evaluation(), nowSeconds: () => NOW });
  const ask = (asserted: { adi: string; assertedBy: string } | null = { adi: SUBJECT, assertedBy: GRANTOR }, now = NOW) =>
    createChainWorld({ evaluation: () => cache.evaluation(), nowSeconds: () => now }).establish({ grantorAdi: GRANTOR, grantorBook: BOOK, grantId: 'fic-agent-pay', asserted });
  return { node, cache, world, ask };
}

describe('the Grant head (online model: no key page is read)', () => {
  it('is the verified head with its Grant, decoded from the very bytes the lineage verified', async () => {
    const g1 = grant();
    const r = await scene({ grants: [g1] }).ask(null);
    expect(r.head).toMatchObject({ ok: true, value: { hash: hashGrant(g1), subject: { adi: SUBJECT, type: 'agent' }, grant: g1 } });
    expect(r.subject).toBeNull();
  });

  it('survives a key rotation: the envelope key is on no key page of the node, the Grant is still the head, and no key page is asked for', async () => {
    const s = scene();
    const r = await s.ask();
    expect(r.head.ok).toBe(true);
    expect(r.subject).toEqual({ ok: true, value: { adi: SUBJECT, type: 'agent' } });
    // the model's central property: an online verdict reads no key page (no `/book/1`, no book record)
    expect(s.node.calls.filter((c) => /\/book(\/\d+)?( |$)/.test(c))).toEqual([]);
  });

  it('is the NEWEST version after a supersede', async () => {
    const g1 = grant();
    const g2 = grant({ version: 2, priorHash: hashGrant(g1), issuedAt: 1_800_000_100 });
    const r = await scene({ grants: [g1, g2] }).ask(null);
    expect(r.head).toMatchObject({ ok: true, value: { hash: hashGrant(g2) } });
  });

  it('reads past the first page of entries (230 entries of other lineages, then the real one)', async () => {
    const noise = Array.from({ length: 230 }, (_, i) => grant({ grantId: `noise-${i}` }));
    const g1 = grant();
    const s = scene({ grants: [...noise, g1] });
    const r = await s.ask(null);
    expect(r.head).toMatchObject({ ok: true, value: { hash: hashGrant(g1) } });
    expect(s.node.calls.filter((c) => c === `${GRANTS} data`)).toHaveLength(3);
  });

  it('is refused by the account authority rule, never allowed', async () => {
    const detail = async (mut: (n: FakeNode) => void, now = NOW): Promise<string> => {
      const s = scene();
      mut(s.node);
      const r = await s.ask(null, now);
      return r.head.ok ? 'OK' : r.head.detail;
    };
    // another book next to the owner, or instead of it
    expect(await detail((n) => n.accounts.get(GRANTS)!.authorities.push('acc://other.acme/book'))).toContain('account_authority_not_owner_only');
    expect(await detail((n) => { n.accounts.get(GRANTS)!.authorities = ['acc://other.acme/book']; })).toContain('account_authority_not_owner_only');
    // the subject's own book among the authorities
    expect(await detail((n) => n.accounts.get(GRANTS)!.authorities.push(`${SUBJECT}/book`))).toContain('account_authority_includes_subject');
    // an authority change after the creation, even one that restored the same set
    expect(await detail((n) => n.updateAuth(GRANTS, [BOOK]))).toContain('account_authority_changed');
    // a main chain that does not start at the creation
    expect(await detail((n) => { n.accounts.get(GRANTS)!.chain.shift(); })).toContain('account_history_incomplete');
    // unreadable
    expect(await detail((n) => n.down.add(GRANTS))).toContain('unreadable');
    expect(await detail((n) => n.accounts.delete(GRANTS))).toContain('unreadable');
    // the interval is half open: ended at notAfter, not yet valid before notBefore
    expect(await detail(() => undefined, 1_810_000_000)).toBe('grant_ended');
    expect(await detail(() => undefined, 1_799_999_999)).toBe('grant_not_yet_valid');
  });

  it('an unknown grantId or a Grant whose grantor book is not the account owner is refused', async () => {
    const s = scene();
    const r = await createChainWorld({ evaluation: () => s.cache.evaluation(), nowSeconds: () => NOW }).establish({ grantorAdi: GRANTOR, grantorBook: BOOK, grantId: 'unknown-grant', asserted: null });
    expect(r.head.ok).toBe(false);
    const other = await createChainWorld({ evaluation: () => s.cache.evaluation(), nowSeconds: () => NOW }).establish({ grantorAdi: GRANTOR, grantorBook: `${GRANTOR}/other-book`, grantId: 'fic-agent-pay', asserted: null });
    expect(other.head.ok).toBe(false);
  });
});

describe('the subject (the GRANTOR registry and the subject acceptance only)', () => {
  const subject = async (s: ReturnType<typeof scene>, assertedBy = GRANTOR) => (await s.ask({ adi: SUBJECT, assertedBy })).subject;

  it('resolves a registered subject that accepted, asserted by the grantor', async () => {
    expect(await subject(scene())).toEqual({ ok: true, value: { adi: SUBJECT, type: 'agent' } });
  });

  it('is unproven without an acceptance, after a revoke, and when the acceptance came after the registration', async () => {
    expect(await subject(scene({ acceptances: null }))).toMatchObject({ ok: false, detail: expect.stringContaining('subject_unproven') });
    expect(await subject(scene({ acceptances: [{ action: 'accept', time: T_REG - 10 }, { action: 'revoke', time: T_REG + 5 }] }))).toMatchObject({ ok: false });
    expect(await subject(scene({ acceptances: [{ action: 'accept', time: T_REG + 5 }] }))).toMatchObject({ ok: false });
  });

  it('follows the lineage: a suspension needs no acceptance, a reactivation needs a consent in force', async () => {
    const v1 = registration();
    const v2 = registration({ version: 2, priorHash: hashRegistration(v1), status: 'suspended', registeredAt: T_REG + 100 });
    const v3 = registration({ version: 3, priorHash: hashRegistration(v2), status: 'active', registeredAt: T_REG + 200 });
    const regs = (...rs: Array<[Record<string, unknown>, number]>) => rs.map(([r, time]) => ({ r, time }));
    expect(await subject(scene({ registrations: regs([v1, T_REG], [v2, T_REG + 100]) }))).toMatchObject({ ok: false, detail: expect.stringContaining('subject_suspended') });
    // the consent stays in force until it is revoked: a reactivation needs a consent IN FORCE at its entry time (GR-56)
    expect(await subject(scene({ registrations: regs([v1, T_REG], [v2, T_REG + 100], [v3, T_REG + 200]) }))).toMatchObject({ ok: true });
    const revoked = [{ action: 'accept' as const, time: T_REG - 10 }, { action: 'revoke' as const, time: T_REG + 150 }];
    expect(await subject(scene({ registrations: regs([v1, T_REG], [v2, T_REG + 100], [v3, T_REG + 200]), acceptances: revoked }))).toMatchObject({ ok: false });
    expect(await subject(scene({ registrations: regs([v1, T_REG], [v2, T_REG + 100], [v3, T_REG + 200]), acceptances: [...revoked, { action: 'accept' as const, time: T_REG + 180 }] }))).toMatchObject({ ok: true });
  });

  it('a registration by ANOTHER ADI in the grantor registry is invisible to the Grant; an entry without a chain time cannot be placed', async () => {
    const stranger = registration({ principal: { adi: 'acc://stranger.acme', keyBook: 'acc://stranger.acme/book' } });
    expect(await subject(scene({ registrations: [{ r: stranger, time: T_REG }] }))).toMatchObject({ ok: false, detail: expect.stringContaining('registration_principal_mismatch') });
    expect(await subject(scene({ registrations: [{ r: registration() }] }))).toMatchObject({ ok: false, detail: expect.stringContaining('account_entry_undecodable entry_time_missing') });
  });

  it('is unproven when the asserter is neither the grantor nor a submitter, and when the registry fails the authority rule', async () => {
    expect(await subject(scene(), 'acc://stranger.acme')).toMatchObject({ ok: false, detail: expect.stringContaining('submitter_not_authorized') });
    const s = scene();
    s.node.accounts.get(REGISTRY)!.authorities.push('acc://other.acme/book');
    expect(await subject(s)).toMatchObject({ ok: false, detail: expect.stringContaining('account_authority_not_owner_only') });
    // the registry is the GRANTOR's: a subject type other than the Grant's is `subject_type_mismatch`
    expect(await subject(scene({ registrations: [{ r: registration({ type: 'merchant' }), time: T_REG }] }))).toMatchObject({ ok: false, detail: expect.stringContaining('subject_type_mismatch') });
  });
});
