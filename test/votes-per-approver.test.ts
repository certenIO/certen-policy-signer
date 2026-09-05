/**
 * One vote per approver. Runbook F, T29-d.
 *
 * A key page counts signatures against its own threshold — measured on Kermit, not assumed: a 2-of-2
 * page held a transaction pending on one certificate's signature and executed it on the second. So a
 * decision naming two approvers has to produce TWO signatures, each made with the key that approver
 * controls. One vote per transaction would leave such a page a signature short and the transaction
 * pending until it expired.
 *
 * ── THE CASE THAT MATTERS IS THE HALF-ENROLLED ONE ────────────────────────────────────────────────
 *
 * A rollout seats certificates one employee at a time, so "one approver we hold a key for and one we
 * do not" is the ordinary state for months. The one that can sign must, and the transaction is then
 * correctly short of its threshold — the protocol's own answer, not a failure of ours to report.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { MapKeyring, bookOf, type SigningScope } from '../src/signer/keyring.js';
import { Orchestrator } from '../src/orchestrator.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const PAGE = 'acc://bank.acme/roles/treasury/1';
const ALICE = 'alice@bank.example';
const BOB = 'bob@bank.example';

const ORG_KEY = new LocalSigner(new Uint8Array(32).fill(1));
const ALICE_KEY = new LocalSigner(new Uint8Array(32).fill(2));
const BOB_KEY = new LocalSigner(new Uint8Array(32).fill(3));

function setup(seats: Record<string, LocalSigner>) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, {
    body: { type: 'sendTokens', to: [{ url: 'acc://alice.acme/tokens', amount: '5000' }] },
    principal: 'acc://alice.acme/tokens',
  });
  const scope: SigningScope = { page: PAGE, book: bookOf(PAGE), signer: ORG_KEY, keys: seats };
  const store = new MemoryStore();
  return { acc, store, keyring: new MapKeyring([scope]), resolver: new Resolver(acc) };
}

/** Run one transaction through the pipeline with a decision naming `refs`. */
async function run(seats: Record<string, LocalSigner>, refs: string[] | undefined, single?: string) {
  const d = setup(seats);
  const evidence: Record<string, unknown> = {};
  if (refs) evidence['approverKeyRefs'] = refs;
  if (single) evidence['approverKeyRef'] = single;

  const o = new Orchestrator({
    accumulate: d.acc, keyring: d.keyring, store: d.store, resolver: d.resolver, logger: silent,
    policy: new MockPolicyClient({ decision: 'approve', reason: 'ok', evidence }),
  });
  const result = await o.handle({ txHash: TX, signerUrl: PAGE });
  const signedBy = (d.acc.submissions as { signatures: { publicKey: string }[] }[])
    .map((e) => e.signatures[0]!.publicKey);
  return { result, signedBy, store: d.store };
}

const hex = async (s: LocalSigner) => Buffer.from(await s.publicKey()).toString('hex');

describe('one vote per approver', () => {
  it('casts TWO votes, one with each approver key, when two are named', async () => {
    const { result, signedBy } = await run({ [ALICE]: ALICE_KEY, [BOB]: BOB_KEY }, [ALICE, BOB]);

    expect(result.status).toBe('signed');
    expect(signedBy).toHaveLength(2);
    expect(signedBy).toEqual([await hex(ALICE_KEY), await hex(BOB_KEY)]);
    // The organisation's key is nowhere in it. Two people approved; two people's keys signed.
    expect(signedBy).not.toContain(await hex(ORG_KEY));
  });

  it('signs once, as the organisation, when nobody is named', async () => {
    const { result, signedBy } = await run({ [ALICE]: ALICE_KEY }, undefined);
    expect(result.status).toBe('signed');
    expect(signedBy).toEqual([await hex(ORG_KEY)]);
  });

  it('signs for the approver it CAN, and does not fail because of the one it cannot', async () => {
    // The half-enrolled organisation. Alice's key is held; Bob's is not. Her signature is real and
    // the page is then one short of its threshold — which the chain resolves by holding the
    // transaction pending, not something for this process to call an error.
    const { result, signedBy } = await run({ [ALICE]: ALICE_KEY }, [ALICE, BOB]);

    expect(result.status).toBe('signed');
    expect(signedBy).toEqual([await hex(ALICE_KEY)]);
  });

  it('fails only when it could sign for NOBODY who was named', async () => {
    // Every named approver is unknown here. Falling back to the organisation would be the
    // substitution T29 exists to prevent, so nothing is signed and the failure is recorded.
    const { result, signedBy } = await run({ [ALICE]: ALICE_KEY }, ['mallory@bank.example']);

    expect(signedBy).toHaveLength(0);
    expect(result.status).toBe('error');
    expect(result.lastError).toMatch(/no key "mallory@bank.example" configured/);
  });

  it('honours a lone `approverKeyRef` from a console predating T29-d', async () => {
    const { result, signedBy } = await run({ [ALICE]: ALICE_KEY }, undefined, ALICE);
    expect(result.status).toBe('signed');
    expect(signedBy).toEqual([await hex(ALICE_KEY)]);
  });

  it('records a receipt naming a key that actually signed', async () => {
    const { store } = await run({ [ALICE]: ALICE_KEY, [BOB]: BOB_KEY }, [ALICE, BOB]);
    const receipt = await store.getReceipt(TX);

    expect(receipt?.vote).toBe('approve');
    // The Receipt contract carries ONE attribution and is frozen, so it names the first signature
    // rather than inventing a list. It must be a key that signed -- never the organisation's, which
    // signed nothing here.
    expect(receipt?.signedBy?.publicKeyHash).toBeDefined();
    expect(receipt?.signedBy?.publicKeyHash).not.toBe(
      Buffer.from(await ORG_KEY.publicKey()).toString('hex'),
    );
  });
});
