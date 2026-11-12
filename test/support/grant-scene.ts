/**
 * A FICTIONAL grantor scene on a fake v3 node: the grantor's grants account, the grantor's registry, the subject ADI and its
 * acceptance account, a read cache over it and the production chain world. Real Ed25519 keys sign the envelopes (generated in
 * memory, never written, never printed); the online model never verifies them.
 */
import { generateKeyPairSync, sign } from 'node:crypto';
import { createChainWorld } from '../../src/binding/chain-world.js';
import { ReadCache, type ReadCacheOptions } from '../../src/binding/read-cache.js';
import { encodeAcceptanceEntry } from '../../src/core/acceptance.js';
import { buildEnvelope, encodeGrantEntry, encodeRegistrationEntry } from '../../src/core/envelope.js';
import type { Grant } from '../../src/core/grant-profile.js';
import { envelopeDigest, hashGrant, hashRegistration } from '../../src/core/hashes.js';
import { ADDR } from './binding-fixtures.js';
import { FakeNode } from './fake-node.js';

export const S_GRANTOR = 'acc://fic-grantor.acme';
export const S_BOOK = `${S_GRANTOR}/book`;
export const S_SUBJECT = 'acc://agent-one.fic-grantor.acme';
export const S_GRANTS = `${S_GRANTOR}/certen-grants`;
export const S_REGISTRY = `${S_GRANTOR}/certen-subjects`;
export const S_ACCEPT = `${S_SUBJECT}/certen-acceptances`;
export const S_NOW = 1_800_000_500;

const k = generateKeyPairSync('ed25519');
const pubHex = Buffer.from((k.publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url').toString('hex');

export const sceneGrant = (over: Partial<Grant> = {}): Grant => {
  const asset = { chainId: 84532, token: ADDR.token };
  return {
    schema: 'certen.grant/v1', grantId: 'fic-agent-pay', version: 1, priorHash: null, issuedAt: 1_800_000_000, subject: { type: 'agent', adi: S_SUBJECT }, grantor: { adi: S_GRANTOR, keyBook: S_BOOK },
    scope: { actions: ['erc20.transfer'], accounts: [{ chainId: 84532, address: ADDR.treasury }], beneficiaries: [{ chainId: 84532, address: ADDR.vendorA }], assets: [asset] },
    limits: [{ asset, perTransaction: '1000', cumulative: { amount: '5000', periodSeconds: 86400 }, count: { max: 3, periodSeconds: 86400 } }],
    validity: { notBefore: 1_800_000_000, notAfter: 1_810_000_000 }, approvals: [{ asset, tiers: [{ upTo: null, required: [{ book: `${S_GRANTOR}/treasury`, threshold: 1 }] }] }], conditions: { all: [] }, ...over,
  };
};
const envFor = (tag: string, hash: string, page: string) => buildEnvelope(tag, hash, [{ alg: 'ed25519', page, publicKey: pubHex, signature: sign(null, envelopeDigest(tag, hash, page), k.privateKey).toString('hex') }]);
export const grantElements = (g: Grant) => encodeGrantEntry(g, envFor('certen:grant:v1', hashGrant(g), `${S_BOOK}/1`));
export const sceneRegistration = { schema: 'certen.subject/v2', adi: S_SUBJECT, version: 1, priorHash: null, type: 'agent', principal: { adi: S_GRANTOR, keyBook: S_BOOK }, responsibleSeat: 'seat:fic-treasury', submitters: [], status: 'active', registeredAt: 1_800_000_100 };
const regElements = (r: Record<string, unknown>) => encodeRegistrationEntry(r, envFor('certen:subject:v2', hashRegistration(r), `${S_BOOK}/1`));

export function grantScene(opts: ReadCacheOptions = {}) {
  const node = new FakeNode();
  node.dataAccount(S_GRANTS, [S_BOOK]);
  node.write(S_GRANTS, grantElements(sceneGrant()));
  node.dataAccount(S_REGISTRY, [S_BOOK]);
  node.write(S_REGISTRY, regElements(sceneRegistration), 1_800_000_100);
  node.identity(S_SUBJECT, [`${S_SUBJECT}/book`]);
  node.dataAccount(S_ACCEPT, [`${S_SUBJECT}/book`]);
  node.write(S_ACCEPT, encodeAcceptanceEntry({ schema: 'certen.acceptance/v1', subject: S_SUBJECT, principal: S_GRANTOR, registry: S_REGISTRY, action: 'accept' }), 1_800_000_090);
  const clock = { ms: 1_000_000 };
  const cache = new ReadCache(node.query, { now: () => clock.ms, ...opts });
  const world = createChainWorld({ evaluation: () => cache.evaluation(), nowSeconds: () => S_NOW });
  const evaluate = () => world.establish({ grantorAdi: S_GRANTOR, grantorBook: S_BOOK, grantId: 'fic-agent-pay', asserted: { adi: S_SUBJECT, assertedBy: S_GRANTOR } });
  return { node, cache, clock, world, evaluate };
}
