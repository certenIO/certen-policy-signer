/**
 * The production BindingWorld (src/binding/chain-world.ts) over the Kermit-shaped reader (src/binding/chain-reader.ts) and the
 * core's own lineage and registry code, against a FAKE API v3 whose answers have the shapes the DAX-3A live spike read.
 * Real Ed25519 keys signing real envelopes (generated in memory, never written, never printed). This proves the glue and its
 * fail-closed paths; it does NOT prove the shapes against Kermit (no chain contact in DAX-4S): the live smoke does.
 */
import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createChainReader, type ChainQuery } from '../src/binding/chain-reader.js';
import { createChainWorld } from '../src/binding/chain-world.js';
import { buildEnvelope, encodeGrantEntry, encodeRegistrationEntry } from '../src/core/envelope.js';
import { hashGrant, hashRegistration, envelopeDigest } from '../src/core/hashes.js';
import type { Grant } from '../src/core/grant-profile.js';
import { ADDR } from './support/binding-fixtures.js';

const GRANTOR = 'acc://fic-grantor.acme';
const SUBJECT = 'acc://agent-one.fic-grantor.acme';
const PRINCIPAL = 'acc://fic-principal.acme';
const NOW = 1_800_000_500;

function key() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const x = (publicKey.export({ format: 'jwk' }) as { x: string }).x;
  const raw = Buffer.from(x, 'base64url');
  return { pubHex: raw.toString('hex'), hash: createHash('sha256').update(raw).digest('hex'), sign: (d: Uint8Array) => sign(null, d, privateKey).toString('hex') };
}
const grantorKey = key();
const principalKey = key();
const subjectKey = key();

function grant(over: Partial<Grant> = {}): Grant {
  const asset = { chainId: 84532, token: ADDR.token };
  return {
    schema: 'certen.grant/v1', grantId: 'fic-agent-pay', version: 1, priorHash: null, issuedAt: 1_800_000_000,
    subject: { type: 'agent', adi: SUBJECT }, grantor: { adi: GRANTOR, keyBook: `${GRANTOR}/book` },
    scope: { actions: ['erc20.transfer'], accounts: [{ chainId: 84532, address: ADDR.treasury }], beneficiaries: [{ chainId: 84532, address: ADDR.vendorA }], assets: [asset] },
    limits: [{ asset, perTransaction: '1000', cumulative: { amount: '5000', periodSeconds: 86400 }, count: { max: 3, periodSeconds: 86400 } }],
    validity: { notBefore: 1_800_000_000, notAfter: 1_810_000_000 },
    approvals: [{ asset, tiers: [{ upTo: null, required: [{ book: `${GRANTOR}/treasury`, threshold: 1 }] }] }],
    conditions: { all: [] },
    ...over,
  };
}
const hex = (els: Uint8Array[]): string[] => els.map((e) => Buffer.from(e).toString('hex'));

function grantEntry(g: Grant, signer = grantorKey, page = `${GRANTOR}/book/1`): string[] {
  const h = hashGrant(g);
  return hex(encodeGrantEntry(g, buildEnvelope('certen:grant:v1', h, [{ alg: 'ed25519', page, publicKey: signer.pubHex, signature: signer.sign(envelopeDigest('certen:grant:v1', h, page)) }])));
}
function registration(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { schema: 'certen.subject/v2', adi: SUBJECT, version: 1, priorHash: null, type: 'agent', principal: { adi: PRINCIPAL, keyBook: `${PRINCIPAL}/book` }, responsibleSeat: 'seat:fic-treasury', submitters: [], status: 'active', registeredAt: 1_800_000_000, ...over };
}
function registrationEntry(r: Record<string, unknown>): string[] {
  const h = hashRegistration(r);
  const page = `${PRINCIPAL}/book/1`;
  return hex(encodeRegistrationEntry(r, buildEnvelope('certen:subject:v2', h, [{ alg: 'ed25519', page, publicKey: principalKey.pubHex, signature: principalKey.sign(envelopeDigest('certen:subject:v2', h, page)) }])));
}

/** a fake API v3: accounts by URL; a data account answers the `data` range query with records and a total */
function chain(data: Record<string, string[][]>, opts: { shortRead?: boolean; fail?: string } = {}): { query: ChainQuery; calls: string[] } {
  const calls: string[] = [];
  const accounts: Record<string, unknown> = {
    [`${GRANTOR}/certen-grants`]: { account: { type: 'dataAccount', authorities: [{ url: `${GRANTOR}/book` }] } },
    [`${PRINCIPAL}/certen-subjects`]: { account: { type: 'dataAccount', authorities: [{ url: `${PRINCIPAL}/book` }] } },
    [SUBJECT]: { account: { type: 'identity', authorities: [{ url: `${SUBJECT}/book` }] } },
    [`${GRANTOR}/book`]: { account: { type: 'keyBook', pageCount: 1 } },
    [`${GRANTOR}/book/1`]: { account: { keys: [{ publicKeyHash: grantorKey.hash }], acceptThreshold: 1 } },
    [`${PRINCIPAL}/book`]: { account: { type: 'keyBook', pageCount: 1 } },
    [`${PRINCIPAL}/book/1`]: { account: { keys: [{ publicKeyHash: principalKey.hash }], acceptThreshold: 1 } },
    [`${SUBJECT}/book`]: { account: { type: 'keyBook', pageCount: 1 } },
    [`${SUBJECT}/book/1`]: { account: { keys: [{ publicKeyHash: subjectKey.hash }], acceptThreshold: 1 } },
  };
  const query: ChainQuery = async (scope, q) => {
    calls.push(scope + (q ? ' ' + JSON.stringify(q) : ''));
    if (opts.fail === scope) throw new Error('node unreachable');
    const qq = q as { queryType?: string; range?: { start: number; count: number } } | undefined;
    if (qq?.queryType === 'data') {
      const all = data[scope];
      if (all === undefined) throw new Error('not found');
      const slice = all.slice(qq.range!.start, qq.range!.start + qq.range!.count);
      return { records: slice.map((els, i) => ({ value: { id: `acc://${String(qq.range!.start + i).padStart(64, '0')}@${scope.replace('acc://', '')}`, message: { transaction: { body: { entry: { data: els } } } } } })), total: opts.shortRead ? all.length + 1 : all.length };
    }
    const a = accounts[scope];
    if (a === undefined) throw new Error('not found');
    return a;
  };
  return { query, calls };
}
const worldOf = (c: { query: ChainQuery }, now = NOW) => createChainWorld({ reader: createChainReader(c.query), nowSeconds: () => now });
const GRANTS = `${GRANTOR}/certen-grants`;
const SUBJECTS = `${PRINCIPAL}/certen-subjects`;

describe('the Grant head', () => {
  it('is the verified head with its subject, read from the very bytes that were verified', async () => {
    const g1 = grant();
    const r = await worldOf(chain({ [GRANTS]: [grantEntry(g1)] })).grantHead({ grantorAdi: GRANTOR, grantId: 'fic-agent-pay' });
    expect(r).toEqual({ ok: true, value: { hash: hashGrant(g1), subject: { adi: SUBJECT, type: 'agent' } } });
  });

  it('is the NEWEST version after a supersede (the old hash is no longer the head)', async () => {
    const g1 = grant();
    const g2 = grant({ version: 2, priorHash: hashGrant(g1), issuedAt: 1_800_000_100 });
    const r = await worldOf(chain({ [GRANTS]: [grantEntry(g1), grantEntry(g2)] })).grantHead({ grantorAdi: GRANTOR, grantId: 'fic-agent-pay' });
    expect(r).toMatchObject({ ok: true, value: { hash: hashGrant(g2) } });
    expect(hashGrant(g1)).not.toBe(hashGrant(g2));
  });

  it('reads past the first page of data entries (230 entries of other lineages, then the real one) and checks the count', async () => {
    const noise = Array.from({ length: 230 }, (_, i) => grantEntry(grant({ grantId: `noise-${i}` })));
    const g1 = grant();
    const c = chain({ [GRANTS]: [...noise, grantEntry(g1)] });
    const r = await worldOf(c).grantHead({ grantorAdi: GRANTOR, grantId: 'fic-agent-pay' });
    expect(r).toMatchObject({ ok: true, value: { hash: hashGrant(g1) } });
    expect(c.calls.filter((x) => x.includes('"queryType":"data"')).length).toBe(3);
    const short = await worldOf(chain({ [GRANTS]: [grantEntry(g1)] }, { shortRead: true })).grantHead({ grantorAdi: GRANTOR, grantId: 'fic-agent-pay' });
    expect(short.ok).toBe(false); // the node's total does not add up: not the whole account
  });

  it('is refused, never allowed, when anything is unreadable, unverifiable or not in force', async () => {
    const g1 = grant();
    const ask = (c: { query: ChainQuery }, now = NOW) => worldOf(c, now).grantHead({ grantorAdi: GRANTOR, grantId: 'fic-agent-pay' });
    expect(await ask(chain({ [GRANTS]: [grantEntry(g1)] }, { fail: GRANTS }))).toMatchObject({ ok: false });
    expect(await ask(chain({}))).toMatchObject({ ok: false, detail: expect.stringContaining('lineage_unreadable') });
    expect(await ask(chain({ [GRANTS]: [] }))).toMatchObject({ ok: false });
    // signed by a key that is NOT on the grantor's page: the whole lineage is refused
    expect(await ask(chain({ [GRANTS]: [grantEntry(g1, subjectKey)] }))).toMatchObject({ ok: false });
    // a key page that cannot be read
    expect(await ask(chain({ [GRANTS]: [grantEntry(g1)] }, { fail: `${GRANTOR}/book/1` }))).toMatchObject({ ok: false });
    // ended (the interval is half open) and not yet valid
    expect(await ask(chain({ [GRANTS]: [grantEntry(g1)] }), 1_810_000_000)).toEqual({ ok: false, detail: 'grant_ended' });
    expect(await ask(chain({ [GRANTS]: [grantEntry(g1)] }), 1_799_999_999)).toEqual({ ok: false, detail: 'grant_not_yet_valid' });
    // another grantor's lineage under the same account is a different lineage: the id is not found
    expect(await worldOf(chain({ [GRANTS]: [grantEntry(g1)] })).grantHead({ grantorAdi: GRANTOR, grantId: 'unknown-grant' })).toMatchObject({ ok: false });
  });
});

describe('the resolved subject', () => {
  const ask = (c: { query: ChainQuery }, assertedBy = PRINCIPAL, principals = [PRINCIPAL]) => worldOf(c).resolveSubject({ principals, asserted: { adi: SUBJECT, assertedBy } });

  it('resolves a registered, active subject asserted by its principal', async () => {
    expect(await ask(chain({ [SUBJECTS]: [registrationEntry(registration())] }))).toEqual({ ok: true, value: { adi: SUBJECT, type: 'agent' } });
  });
  it('follows the lineage: a suspension is the head, a reactivation lifts it', async () => {
    const v1 = registration();
    const v2 = registration({ version: 2, priorHash: hashRegistration(v1), status: 'suspended', registeredAt: 1_800_000_100 });
    const v3 = registration({ version: 3, priorHash: hashRegistration(v2), status: 'active', registeredAt: 1_800_000_200 });
    expect(await ask(chain({ [SUBJECTS]: [registrationEntry(v1), registrationEntry(v2)] }))).toEqual({ ok: false, detail: 'subject_unproven:subject_suspended' });
    expect(await ask(chain({ [SUBJECTS]: [registrationEntry(v1), registrationEntry(v2), registrationEntry(v3)] }))).toMatchObject({ ok: true });
  });
  it('is unproven when not registered, when the asserter is not the principal or a submitter, when no registry is configured or readable', async () => {
    expect(await ask(chain({ [SUBJECTS]: [] }))).toEqual({ ok: false, detail: 'subject_unproven:not_registered' });
    expect(await ask(chain({ [SUBJECTS]: [registrationEntry(registration())] }), 'acc://stranger.acme')).toEqual({ ok: false, detail: 'subject_unproven:submitter_not_authorized' });
    expect(await ask(chain({ [SUBJECTS]: [registrationEntry(registration({ submitters: ['acc://stranger.acme'] }))] }), 'acc://stranger.acme')).toMatchObject({ ok: true });
    expect(await ask(chain({}), PRINCIPAL, [])).toEqual({ ok: false, detail: 'no_registry_principals_configured' });
    expect(await ask(chain({}))).toMatchObject({ ok: false, detail: expect.stringContaining('registry_unreadable') });
  });
  it('returns the registry TYPE so that a Grant of another type is a subject MISMATCH (the core compares), not a hidden unproven', async () => {
    const merchant = registration({ type: 'merchant' });
    expect(await ask(chain({ [SUBJECTS]: [registrationEntry(merchant)] }))).toEqual({ ok: true, value: { adi: SUBJECT, type: 'merchant' } });
  });
  it('is unproven when the registration was signed by a key that is not the principal\'s', async () => {
    const r = registration();
    const h = hashRegistration(r);
    const page = `${PRINCIPAL}/book/1`;
    const forged = hex(encodeRegistrationEntry(r, buildEnvelope('certen:subject:v2', h, [{ alg: 'ed25519', page, publicKey: subjectKey.pubHex, signature: subjectKey.sign(envelopeDigest('certen:subject:v2', h, page)) }])));
    expect(await ask(chain({ [SUBJECTS]: [forged] }))).toMatchObject({ ok: false, detail: expect.stringContaining('registration_unverified') });
  });
});
