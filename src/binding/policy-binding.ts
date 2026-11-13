/**
 * The `binding` member of a policy request: the request the signer will bind, named as the Console's wire contract names it
 * (src/binding/wire.ts of the Console, pinned by test/binding-console-request-contract.test.ts).
 *
 *   - the ten members of the core's request hash (`validatorOperationId` is the core's `operationId`),
 *   - `legCount`, ALWAYS: the number of legs of the intent (DE-76); the request hash binds one action, so the decision service refuses
 *     a count other than 1 by name and the signer does not leave the binding out,
 *   - `grantRef` ({grantId, version, grantHash}) ONLY when blob 0 of the intent carries one: the producer's claim, compared with the
 *     head by the decision service and by the signer's own world. It is omitted, never `null`, when the intent names no Grant.
 * There is no `leafExpiry`: no field of the pending transaction carries it (DAX-4S round 4).
 */
import type { PolicyBinding } from '../types.js';
import type { PresentedRequest } from './request.js';

export function policyBindingOf(p: Pick<PresentedRequest, 'request' | 'legCount' | 'grantRef'>): PolicyBinding {
  const request = p.request;
  return {
    chainId: request['chainId'] as number,
    kind: request['kind'] as PolicyBinding['kind'],
    source: request['source'] as string,
    target: request['target'] as string,
    beneficiary: request['beneficiary'] as string,
    asset: request['asset'] as string,
    amount: request['amount'] as string,
    executionCommitment: request['executionCommitment'] as string,
    validatorOperationId: request['operationId'] as string,
    txHash: request['txHash'] as string,
    legCount: p.legCount,
    ...(p.grantRef === null ? {} : { grantRef: { grantId: p.grantRef.grantId, version: p.grantRef.version, grantHash: p.grantRef.grantHash } }),
  };
}
