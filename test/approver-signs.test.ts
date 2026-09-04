/**
 * T29 — the approver's own key casts their vote.
 *
 * Before this, one key signed every transaction on a page however many people approved: the record
 * said "the organisation signed", and which person approved lived only in the console's database.
 * Now the decision can name the approver and THAT key signs, so the signature on chain is theirs.
 *
 * The load-bearing property is the REFUSAL. If the decision names an approver this process holds no
 * key for, it must fail the vote — not sign with the organisation's key. Silently substituting would
 * produce exactly the record T29 exists to stop: a person's approval attributed to a key they never
 * touched, and no way to tell afterwards.
 */
import { describe, it, expect, vi } from 'vitest';
import pino from 'pino';
import { MapKeyring, bookOf, SigningScope } from '../src/signer/keyring.js';
import { LocalSigner } from '../src/signer/signer.js';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { approverKeyRef } from '../src/orchestrator.js';

const silent = pino({ level: 'silent' });
const PAGE = 'acc://bank.acme/roles/treasury/1';

const ORG = new LocalSigner(new Uint8Array(32).fill(1));
const ALICE = new LocalSigner(new Uint8Array(32).fill(2));
const BOB = new LocalSigner(new Uint8Array(32).fill(3));

function keyring(): MapKeyring {
  const scope: SigningScope = {
    page: PAGE, book: bookOf(PAGE), signer: ORG,
    keys: { 'alice@bank.example': ALICE, 'bob@bank.example': BOB },
  };
  return new MapKeyring([scope]);
}

/** An Accumulate client that accepts everything, so the test observes WHICH key signed. */
function acceptingClient() {
  return {
    submit: vi.fn(async () => ({ ok: true, code: 'ok' })),
  } as never;
}

const tx = {
  txHash: 'ab'.repeat(32),
  signerUrl: PAGE,
  signerVersion: 1,
  rawTransaction: { header: { principal: PAGE }, body: { type: 'sendTokens' } },
  lastUsedOn: 0,
  account: 'acc://bank.acme/tokens',
};

/** The public key the vote was actually signed with, read back off the submitted envelope. */
async function signedWith(client: { submit: ReturnType<typeof vi.fn> }): Promise<string> {
  const envelope = client.submit.mock.calls[0]![0] as { signatures: { publicKey: string }[] };
  return envelope.signatures[0]!.publicKey;
}

const hex = async (s: LocalSigner) => Buffer.from(await s.publicKey()).toString('hex');

describe('whose key casts the vote', () => {
  it('signs as the organisation when nobody is named — the behaviour every deployment had', async () => {
    const client = acceptingClient();
    const backend = new DirectVoteBackend(client, keyring(), silent);
    const res = await backend.cast(tx, 'approve');
    expect(res.ok).toBe(true);
    expect(await signedWith(client)).toBe(await hex(ORG));
  });

  it("signs with the APPROVER's key when the decision names them", async () => {
    const client = acceptingClient();
    const backend = new DirectVoteBackend(client, keyring(), silent);
    const res = await backend.cast(tx, 'approve', { keyRef: 'alice@bank.example' });
    expect(res.ok).toBe(true);
    expect(await signedWith(client)).toBe(await hex(ALICE));
    // And the attribution names the key that actually signed, not the scope's.
    expect(res.signedBy?.publicKeyHash).toBeDefined();
  });

  it('distinguishes two approvers on the same page', async () => {
    const a = acceptingClient();
    const b = acceptingClient();
    await new DirectVoteBackend(a, keyring(), silent).cast(tx, 'approve', { keyRef: 'alice@bank.example' });
    await new DirectVoteBackend(b, keyring(), silent).cast(tx, 'approve', { keyRef: 'bob@bank.example' });
    expect(await signedWith(a)).not.toBe(await signedWith(b));
  });

  it('REFUSES an approver it holds no key for, and does not fall back to the organisation', async () => {
    const client = acceptingClient();
    const backend = new DirectVoteBackend(client, keyring(), silent);
    await expect(backend.cast(tx, 'approve', { keyRef: 'mallory@bank.example' }))
      .rejects.toThrow(/no key "mallory@bank.example" configured/);
    // Nothing was submitted. A refusal that still signed would be worse than no feature at all.
    expect(client.submit).not.toHaveBeenCalled();
  });
});

describe('reading the approver off the decision', () => {
  it('takes a well-formed ref', () => {
    expect(approverKeyRef({ approverKeyRef: 'alice@bank.example' })).toBe('alice@bank.example');
    expect(approverKeyRef({ approverKeyRef: '  alice@bank.example  ' })).toBe('alice@bank.example');
  });

  it('treats anything malformed as absent, so the organisation signs as itself', () => {
    // Absent is safe: it is the pre-T29 behaviour. What must never happen is a garbled value
    // resolving to a DIFFERENT valid ref, and returning undefined cannot.
    expect(approverKeyRef(undefined)).toBeUndefined();
    expect(approverKeyRef({})).toBeUndefined();
    expect(approverKeyRef({ approverKeyRef: '' })).toBeUndefined();
    expect(approverKeyRef({ approverKeyRef: '   ' })).toBeUndefined();
    expect(approverKeyRef({ approverKeyRef: 42 })).toBeUndefined();
    expect(approverKeyRef({ approverKeyRef: null })).toBeUndefined();
    expect(approverKeyRef({ approverKeyRef: ['alice'] })).toBeUndefined();
    expect(approverKeyRef({ approverKeyRef: 'x'.repeat(257) })).toBeUndefined();
  });

  it('ignores other evidence the engine sends', () => {
    expect(approverKeyRef({ rule: 'under-10k', approverKeyRef: 'alice@bank.example' })).toBe('alice@bank.example');
    expect(approverKeyRef({ rule: 'under-10k' })).toBeUndefined();
  });
});
