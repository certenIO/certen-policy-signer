import { describe, it, expect } from 'vitest';
import pino from 'pino';
import nacl from 'tweetnacl';
import { buildPreimage, buildDelegatedSignatureObject, bytesToHex } from '../src/accumulate/signing.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const ORG_PAGE = 'acc://ts.acme/book/1';
const USER_PAGE = 'acc://alice.acme/book/1';

describe('delegate signing', () => {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(3));
  const txHash = new Uint8Array(32).fill(0xab);
  const base = { publicKey: kp.publicKey, signerUrl: ORG_PAGE, signerVersion: 2, timestamp: 1751630000000000, vote: 'approve' as const };

  it('delegated preimage is a valid signature and differs from the non-delegated one', () => {
    const plain = buildPreimage(txHash, base);
    const deleg = buildPreimage(txHash, { ...base, delegators: [USER_PAGE] });
    expect(bytesToHex(deleg.dataForSignature)).not.toBe(bytesToHex(plain.dataForSignature));
    const sig = nacl.sign.detached(deleg.dataForSignature, kp.secretKey);
    expect(nacl.sign.detached.verify(deleg.dataForSignature, sig, kp.publicKey)).toBe(true);
  });

  it('buildDelegatedSignatureObject produces a nested delegated wire object', () => {
    const pre = buildPreimage(txHash, { ...base, delegators: [USER_PAGE] });
    const sig = nacl.sign.detached(pre.dataForSignature, kp.secretKey);
    const obj = buildDelegatedSignatureObject(pre, sig, bytesToHex(txHash)) as any;
    // wire shape: { type:'delegated', signature:{...ed25519...}, delegator:'acc://...' }
    expect(obj.type).toBe('delegated');
    expect(obj.delegator).toBeDefined();
    expect(obj.signature).toBeDefined();
  });

  it('orchestrator in delegate mode submits a delegated signature', async () => {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount: '1' }] }, principal: 'acc://alice.acme/tokens' });
    const o = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(4))),
      policy: new MockPolicyClient({ decision: 'approve' }), store: new MemoryStore(),
      resolver: new Resolver(acc), logger: silent, options: { delegators: [USER_PAGE] },
    });
    const r = await o.handle({ txHash: TX, signerUrl: ORG_PAGE });
    expect(r.status).toBe('signed');
    const sigObj = (acc.submissions[0] as any).signatures[0];
    expect(sigObj.type).toBe('delegated');
    expect(sigObj.delegator).toBeDefined();
  });
});
