/**
 * WHO the transaction is about, carried to the policy engine.
 *
 * A policy engine holding a per-user binding — Trust Stamp's biometric re-auth is the case this exists
 * for — must know which enrolled user a pending transaction concerns. Nothing on the request named one:
 * `account` is the submitter's data account, one per deployment, and `operationId` is per operation.
 * Neither names a person. The intent has always been able to say; the signer simply never passed it on.
 *
 * ── WHAT THESE TESTS ARE REALLY PINNING ───────────────────────────────────────────────────────────
 *
 * Absence is a wire fact, not a JavaScript one. An intent that named nobody must produce a request with
 * NO `subject` key — not `subject: undefined`, not `subject: null`. The approval console fingerprints
 * the request by serializing it, so a key that is present-but-empty is a different request from one
 * where the key is absent, and every review item in flight during an upgrade would supersede itself.
 * That is why the absence case asserts `'subject' in req` and not `toBeUndefined()`.
 *
 * And a malformed claim is no claim. The signer never invents a subject the producer did not assert.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import type { PolicyClient } from '../src/policy/policy.js';
import type { Decision, PolicyRequest, Receipt } from '../src/types.js';

const silent = pino({ level: 'silent' });
const TX = 'a1'.repeat(32);
const PAGE = 'acc://bank.acme/book/1';
const ALICE = 'acc://alice.acme';

/** A policy engine that records what it was asked, and answers however the test told it to. */
function recordingEngine(answer: Decision): { seen: PolicyRequest[]; client: PolicyClient } {
  const seen: PolicyRequest[] = [];
  return {
    seen,
    client: {
      decide: async (req: PolicyRequest) => {
        seen.push(req);
        return answer;
      },
    } as unknown as PolicyClient,
  };
}

/** A writeData body in the reference 4-blob intent format, with whatever blob 0 carries as `subject`. */
function intentBody(subject?: unknown) {
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const blobs = [
    {
      kind: 'CERTEN_INTENT',
      version: '2.0',
      intent_id: 'intent-subject-1',
      description: 'Reauth-gated transfer',
      ...(subject !== undefined ? { subject } : {}),
    },
    { protocol: 'CERTEN', version: '2.0', legs: [{ legId: 'leg-1', chain: 'ethereum-sepolia', asset: { symbol: 'ETH' }, to: '0xBe0043', amountWei: '4000' }] },
    { organizationAdi: 'acc://bank.acme', authorization: { signature_threshold: 1 } },
    { nonce: 'certen_1' },
  ];
  return { type: 'writeData', entry: { type: 'doubleHash', data: blobs.map(toHex) } };
}

/** Run one transaction end to end and hand back what the engine saw and what was written down. */
async function askAbout(subject?: unknown, answer: Decision = { decision: 'approve', reason: 'recorded' }) {
  const acc = new MockAccumulateClient();
  acc.addPending(TX, { body: intentBody(subject), principal: 'acc://bank.acme/data' });
  const engine = recordingEngine(answer);
  const store = new MemoryStore();
  const orchestrator = new Orchestrator({
    accumulate: acc,
    keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(3)), PAGE),
    policy: engine.client,
    store,
    resolver: new Resolver(acc),
    logger: silent,
  });
  await orchestrator.handle({ txHash: TX, signerUrl: PAGE });
  const req = engine.seen[0];
  if (!req) throw new Error('the policy engine was never asked');
  // Receipts are keyed by txHash — one per transaction — so this run wrote at most one.
  const receipt = await store.getReceipt(TX);
  return { req, receipt: receipt as Receipt | undefined };
}

describe('the decision request says who the transaction is about', () => {
  it('carries the subject when the intent names one', async () => {
    const { req } = await askAbout({ adi: ALICE, keyBook: `${ALICE}/book`, id: 'cust-99213', assertedBy: 'acc://bank.acme' });
    expect(req.subject).toEqual({ adi: ALICE, keyBook: `${ALICE}/book`, id: 'cust-99213', assertedBy: 'acc://bank.acme' });
  });

  it('carries a subject that is only an ADI, with no empty companions', async () => {
    const { req } = await askAbout({ adi: ALICE });
    expect(req.subject).toEqual({ adi: ALICE });
    expect('keyBook' in req.subject!).toBe(false);
  });

  /**
   * The backward-compatibility case, and the reason the field is spread rather than assigned. The KEY
   * must be gone, not merely undefined — the console fingerprints the serialized request.
   */
  it('omits the field entirely when the intent has no subject', async () => {
    const { req } = await askAbout(undefined);
    expect('subject' in req).toBe(false);
    expect(JSON.parse(JSON.stringify(req))).not.toHaveProperty('subject');
  });

  it('ignores a malformed subject rather than half-populating one', async () => {
    // A bare string. It is the shape someone reaches for first, and it names no field we can key on.
    expect('subject' in (await askAbout(ALICE)).req).toBe(false);
    // An object with no identity in it. The companions are worthless without the ADI.
    expect('subject' in (await askAbout({ keyBook: `${ALICE}/book`, id: 'cust-1' })).req).toBe(false);
    // An empty ADI is not an ADI.
    expect('subject' in (await askAbout({ adi: '' })).req).toBe(false);
    // Non-string companions are dropped; the claim itself survives.
    const { req } = await askAbout({ adi: ALICE, keyBook: 42, id: null });
    expect(req.subject).toEqual({ adi: ALICE });
  });

  it('leaves every other field exactly as it was', async () => {
    const withSubject = await askAbout({ adi: ALICE });
    const without = await askAbout(undefined);
    const strip = (r: PolicyRequest) => {
      const { requestId, expiresAt, subject, ...rest } = r;
      return rest;
    };
    expect(strip(withSubject.req)).toEqual(strip(without.req));
    expect(without.req.account).toBe('acc://bank.acme/data');
    expect(without.req.operationId).toBe('intent-subject-1');
    expect(without.req.signerUrl).toBe(PAGE);
  });
});

describe('the receipt records whose re-authentication it was', () => {
  it('writes the subject ADI onto the approve receipt', async () => {
    const { receipt } = await askAbout({ adi: ALICE, keyBook: `${ALICE}/book` });
    expect(receipt?.decision).toBe('approve');
    // The ADI alone, not the whole object: the receipt answers "who", and the hint is not the identity.
    expect(receipt?.subject).toBe(ALICE);
  });

  it('writes the subject ADI onto the deny receipt', async () => {
    const { receipt } = await askAbout({ adi: ALICE }, { decision: 'deny', reason: 'no enrolled biometric' });
    expect(receipt?.decision).toBe('deny');
    expect(receipt?.subject).toBe(ALICE);
    expect(receipt?.reason).toBe('no enrolled biometric');
  });

  it('leaves the field off a receipt for an intent that named nobody', async () => {
    const { receipt } = await askAbout(undefined);
    expect(receipt).toBeDefined();
    expect('subject' in receipt!).toBe(false);
  });
});
