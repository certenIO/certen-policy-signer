/**
 * The contract with the Console's REQUEST parser (DAX-4C round 3, DAX4C-F16 and F17). The Console reads `PolicyRequest.binding` with a strict
 * parser: an unknown member or a missing member makes the request unbindable and nothing is approved. The relay contract test copies the
 * Console's relay parsers; this one copies its request parser (test/support/console-binding-parser.ts, pinned to its commit) and runs the
 * request the REAL orchestrator sends through it, for a single-leg and a several-leg intent, with and without a Grant.
 */
import { describe, expect, it } from 'vitest';
import { hashGrant, hashRequest } from '../src/core/hashes.js';
import type { Decision, PolicyRequest } from '../src/types.js';
import { ADDR, H, intentBody, leg, subjectClaim } from './support/binding-fixtures.js';
import { rig, requestHashOf, TX, type Body } from './support/binding-rig.js';
import { BINDING_WIRE_KEYS, bindingOf } from './support/console-binding-parser.js';
import { S_GRANTOR, S_SUBJECT, sceneGrant } from './support/grant-scene.js';

/** the members the Console accepts but does not require */
const CONSOLE_OPTIONAL = ['grantRef', 'leafExpiry'] as const;
const claim = { grantId: 'fic-agent-pay', version: 1, grantHash: hashGrant(sceneGrant()) };

/** the request the real orchestrator hands to the decision service for a pending transaction on a seat that requires binding */
async function sentFor(body: Body): Promise<PolicyRequest> {
  let seen: PolicyRequest | undefined;
  const r = rig({ body, reply: (req) => { seen = req; return { decision: 'pending', reason: 'FICTIONAL: waiting for officers' } as Decision; } });
  await r.handle();
  if (seen === undefined) throw new Error('the orchestrator never asked the decision service');
  return seen;
}
const missingOptional = (req: PolicyRequest): string[] => CONSOLE_OPTIONAL.filter((k) => !(k in (req.binding as object)));

describe('a single-leg request, Grant-less (the lab smoke seat): the Console parser accepts what the real orchestrator sends', () => {
  it('every required member is present and nothing else is: bindable, one leg, no Grant claim, no leaf expiry', async () => {
    const body = intentBody();
    const req = await sentFor(body);
    expect(Object.keys(req.binding as object).sort()).toEqual([...BINDING_WIRE_KEYS].sort());
    const parsed = bindingOf(req);
    expect(parsed).toMatchObject({ ok: true, grantRef: null, leafExpiry: null, fields: { legCount: 1, chainId: 84532, kind: 'erc20.transfer', amount: '300', txHash: '0x' + TX } });
    // the request hash the Console builds is the hash the signer recomputes from the transaction it is about to sign
    expect(parsed.ok && parsed.requestHash).toBe(requestHashOf(body));
  });
});

describe('a single-leg request that names a Grant: grantRef is forwarded with the members the Console expects', () => {
  const body = intentBody({ grantRef: claim, subject: subjectClaim(S_SUBJECT, S_GRANTOR) });

  it('blob 0 grantRef reaches the Console as {grantId, version, grantHash} and nothing else', async () => {
    const req = await sentFor(body);
    expect(req.binding?.grantRef).toEqual(claim);
    expect(Object.keys(req.binding!.grantRef!).sort()).toEqual(['grantHash', 'grantId', 'version']);
    const parsed = bindingOf(req);
    expect(parsed).toMatchObject({ ok: true, grantRef: claim, leafExpiry: null, fields: { legCount: 1 } });
    expect(parsed.ok && parsed.requestHash).toBe(requestHashOf(body));
  });

  it('GAP PINNED: no field of the pending transaction carries the on-chain leaf expiry, so the members the Console accepts and the signer does not send are exactly [leafExpiry] (and [grantRef, leafExpiry] for an intent with no Grant)', async () => {
    expect(missingOptional(await sentFor(body))).toEqual(['leafExpiry']);
    expect(missingOptional(await sentFor(intentBody()))).toEqual(['grantRef', 'leafExpiry']);
  });

  it('the intent expiry (blob 3 `expires_at`) and the Accumulate header deadline are NOT taken for the leaf expiry: a fixture that carries them still sends no leafExpiry', async () => {
    const withExpiry = intentBody({ grantRef: claim, blob3: { created_at: 1_800_000_000, expires_at: 1_800_003_600 } });
    const req = await sentFor(withExpiry);
    expect(req.binding).not.toHaveProperty('leafExpiry');
    expect(bindingOf(req)).toMatchObject({ ok: true, leafExpiry: null });
  });

  it('a grantRef the Console would refuse is never sent: a malformed claim in blob 0 builds no binding at all (the decision is refused by name later)', async () => {
    const req = await sentFor(intentBody({ grantRef: { grantId: 'fic-agent-pay', version: 0, grantHash: claim.grantHash } }));
    expect(req.binding).toBeUndefined();
    expect(bindingOf(req)).toEqual({ ok: false, reason: 'binding_absent' });
  });
});

describe('a several-leg intent carries its binding too, so the Console refuses it by name and the signer never skips it', () => {
  it('two mappable legs: a binding with legCount 2 that the Console parses (it then answers multi_leg_unsupported for a count other than 1)', async () => {
    const body = intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })] });
    const req = await sentFor(body);
    expect(Object.keys(req.binding as object).sort()).toEqual([...BINDING_WIRE_KEYS].sort());
    const parsed = bindingOf(req);
    expect(parsed).toMatchObject({ ok: true, fields: { legCount: 2 } });
    expect(parsed.ok && parsed.fields.legCount !== 1).toBe(true); // the Console's refusal rule: legCount !== 1 -> multi_leg_unsupported
  });

  it('a first leg that cannot be mapped still gives a binding the Console parses (a hashable stand-in, never compared: the count is refused first)', async () => {
    const body = intentBody({ legs: [leg({ kind: 'erc20.transferFrom' }), leg()] });
    const req = await sentFor(body);
    const parsed = bindingOf(req);
    expect(parsed).toMatchObject({ ok: true, fields: { legCount: 2 } });
    expect(parsed.ok && parsed.requestHash).toBe(hashRequest(parsed.ok ? parsed.coreRequest : {}));
  });

  it('a several-leg intent with a Grant forwards the claim too', async () => {
    const req = await sentFor(intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })], grantRef: claim }));
    expect(bindingOf(req)).toMatchObject({ ok: true, grantRef: claim, fields: { legCount: 2 } });
  });
});

describe('the fixture parser is the Console strict parser (it would have held every real request before this round)', () => {
  it('a binding without legCount (what the signer sent until f6af4fa) is binding_malformed: missing member legCount', async () => {
    const req = await sentFor(intentBody());
    const { legCount: _dropped, ...tenMembers } = req.binding!;
    expect(bindingOf({ ...req, binding: tenMembers } as unknown as PolicyRequest)).toEqual({ ok: false, reason: 'binding_malformed', detail: 'missing member legCount' });
  });

  it('an unknown member, a legCount that is not a positive integer and a txHash that is not the request\'s are refused', async () => {
    const req = await sentFor(intentBody());
    const mutate = (over: Record<string, unknown>) => bindingOf({ ...req, binding: { ...req.binding!, ...over } } as unknown as PolicyRequest);
    expect(mutate({ extra: 1 })).toMatchObject({ ok: false, reason: 'binding_malformed' });
    expect(mutate({ legCount: 0 })).toMatchObject({ ok: false, reason: 'binding_field_invalid' });
    expect(mutate({ legCount: '1' })).toMatchObject({ ok: false, reason: 'binding_field_invalid' });
    expect(mutate({ txHash: H('other') })).toMatchObject({ ok: false, reason: 'binding_field_invalid' });
    expect(mutate({ leafExpiry: -1 })).toMatchObject({ ok: false, reason: 'binding_field_invalid' });
    expect(mutate({ grantRef: { grantId: 'x', version: 1 } })).toMatchObject({ ok: false, reason: 'binding_malformed' });
  });
});
