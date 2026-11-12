/** The `binding` member of a policy request: the request the signer will bind, named as the Console's wire contract names it. */
import type { PolicyBinding } from '../types.js';

export function policyBindingOf(request: Record<string, string | number>): PolicyBinding {
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
  };
}
