/**
 * EWA-F48 (lead): the signer's copy of the shared core carries the EWA-2 errata (transaction-controls pl/ewa-2-core-errata, merged to main): the service.access Grant
 * action kind with its service asset (GRANT.md section 6b, SA-01..SA-11), the serviceId golden of `dashboard-api` (core gh-18), the eighteen decision-log kinds
 * (DE-103, DE-116) and the grantor-keyed subject resolver (GR-98). A seat whose core lags would refuse a merchant Grant that lists service.access, or a log entry of an
 * EWA kind, that every other CERTEN component accepts (R8: checkers agree).
 */
import { describe, expect, it } from 'vitest';
import { validateGrant } from '../src/core/grant-profile.js';
import { serviceId } from '../src/core/hashes.js';
import { LOG_KINDS } from '../src/core/log.js';
import * as registryOnline from '../src/core/registry-online.js';

const SVC = '0x00000000000000000000000000000000653f194f';
const TOK = '0x' + '33'.repeat(20);
const G = 'acc://fic-grantor.acme';
const merchantGrant = () => ({
  schema: 'certen.grant/v1', grantId: 'fic-merchant-pay', version: 1, priorHash: null, issuedAt: 1800000000,
  subject: { type: 'merchant', adi: 'acc://fic-merchant.acme' }, grantor: { adi: G, keyBook: `${G}/book` },
  scope: {
    actions: ['erc20.transfer', 'service.access'],
    accounts: [{ chainId: 84532, address: '0x' + '11'.repeat(20) }], beneficiaries: [{ chainId: 84532, address: '0x' + '22'.repeat(20) }],
    assets: [{ chainId: 84532, token: TOK }, { chainId: 84532, token: SVC }],
  },
  limits: [
    { asset: { chainId: 84532, token: TOK }, perTransaction: '100', cumulative: { amount: '500', periodSeconds: 86400 }, count: { max: 3, periodSeconds: 86400 } },
    { asset: { chainId: 84532, token: SVC }, perTransaction: '0', cumulative: { amount: '0', periodSeconds: 86400 }, count: { max: 100, periodSeconds: 86400 } },
  ],
  validity: { notBefore: 1800000000, notAfter: 1810000000 },
  approvals: [
    { asset: { chainId: 84532, token: TOK }, tiers: [{ upTo: null, required: [{ book: `${G}/treasury`, threshold: 1 }] }] },
    { asset: { chainId: 84532, token: SVC }, tiers: [{ upTo: null, required: [{ book: `${G}/treasury`, threshold: 1 }] }] },
  ],
  conditions: { all: [] },
});

describe('EWA-F48: the signer core copy carries the EWA-2 errata', () => {
  it('a merchant Grant that lists service.access with its service asset is valid; without the asset it is refused by the core reason', () => {
    expect(validateGrant(merchantGrant()).ok).toBe(true);
    const g = merchantGrant();
    g.scope.assets.pop(); g.limits.pop(); g.approvals.pop();
    const v = validateGrant(g);
    expect(v.ok).toBe(false);
    expect(v.ok ? '' : v.reason).toBe('grant_service_asset_missing');
  });
  it('serviceId("dashboard-api") is the core golden', () => {
    expect(serviceId('dashboard-api')).toBe(SVC);
  });
  it('the decision log has the eighteen kinds, the three EWA kinds appended', () => {
    expect(LOG_KINDS).toHaveLength(18);
    expect(LOG_KINDS.slice(-3)).toEqual(['assessment.intake', 'epoch.published', 'platform.checked']);
  });
  it('the grantor-keyed subject resolver exists', () => {
    expect(typeof (registryOnline as Record<string, unknown>)['resolveSubjectByGrantor']).toBe('function');
  });
});
