/**
 * What actually satisfied the vote, on the record rather than inferred from it.
 *
 * Runbook F Phase F4, task 1: "The receipt carries what satisfied the vote — signer page URL,
 * signature type, public key. A DelegatedSignature preserves all three for the inner signer; pass them
 * through rather than flattening to a boolean."
 *
 * ── WHY A BOOLEAN WOULD BE THE WRONG SHAPE ────────────────────────────────────────────────────────
 *
 * The question F4 exists to answer is whether a PERSON approved something or whether the organisation
 * approved it in their name. Every honest answer to that rests on three facts — which page signed,
 * with which algorithm, and which key — and any one of them alone is a guess:
 *
 *   the page alone      says where the signature came from, not what kind of key it was
 *   the algorithm alone looks decisive and is not: an organisation may hold an ECDSA key, which F2
 *                       made configurable, so "ecdsaSha256 means a certificate" is a heuristic that
 *                       will be wrong in a deployment nobody has built yet
 *   the key hash alone  identifies the key and says nothing about whose it is
 *
 * So the receipt carries all three and classifies nothing. A boolean computed here would be this
 * process's opinion, frozen at the moment of signing, unreadable afterwards and impossible to check
 * against the chain.
 *
 * ── AND THE DELEGATED CASE IS THE ONE THAT MATTERS ────────────────────────────────────────────────
 *
 * When a seat is exercised, the signature on the chain is a DelegatedSignature: an outer wrapper
 * naming the role page and an inner signature made on the employee's own page. The INNER one is the
 * interesting one -- it is the one that says which key belonged to whom -- and flattening the pair to
 * the outer page would record every seated approval as the role having approved itself.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { LocalSigner, LocalEcdsaP256Signer } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';

const silent = pino({ level: 'silent' });
const TX = 'ab'.repeat(32);
const PAGE = 'acc://bank.acme/roles/treasury/1';
const HER_PAGE = 'acc://bank.acme/alice/book/1';
const ROLE_PAGE = 'acc://bank.acme/roles/treasury/1';

function p256Signer(): LocalEcdsaP256Signer {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return new LocalEcdsaP256Signer(new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' })));
}

/** An Accumulate that accepts everything and remembers the envelope. */
function acc() {
  const submitted: unknown[] = [];
  return {
    submitted,
    getSignerInfo: async () => ({ version: 1, lastUsedOn: 0, creditBalance: 100 }),
    submit: async (env: unknown) => { submitted.push(env); return { ok: true }; },
  } as never;
}

const votable = (signerUrl: string) => ({
  txHash: TX, signerUrl, signerVersion: 1, rawTransaction: { header: { principal: 'acc://x.acme/data' } },
  lastUsedOn: 0, account: 'acc://x.acme',
});

describe('what the vote result reports', () => {
  it('names the page it signed on, the algorithm, and the key', async () => {
    const key = new LocalSigner(new Uint8Array(32).fill(4));
    const backend = new DirectVoteBackend(acc(), singleKeyring(key, PAGE), silent);
    const res = await backend.cast(votable(PAGE), 'approve');

    expect(res.ok).toBe(true);
    expect(res.signedBy?.page).toBe(PAGE);
    expect(res.signedBy?.signatureType).toBe('ed25519');
    // The hash, not the key: it is what a key page entry IS, so it is the form that can be compared
    // against one. The key itself is on the chain in the signature and does not need repeating here.
    expect(res.signedBy?.publicKeyHash).toBe(
      createHash('sha256').update(await key.publicKey()).digest('hex'),
    );
  });

  it('reports a certificate as the certificate it is, not as Ed25519', async () => {
    const key = p256Signer();
    const backend = new DirectVoteBackend(acc(), singleKeyring(key, HER_PAGE), silent);
    const res = await backend.cast(votable(HER_PAGE), 'approve');

    expect(res.signedBy?.signatureType).toBe('ecdsaSha256');
    expect(res.signedBy?.page).toBe(HER_PAGE);
    // 91 bytes of PKIX DER hashed to 32, exactly as the page entry for it would be.
    expect(res.signedBy?.publicKeyHash).toHaveLength(64);
  });

  /**
   * The delegated case. The vote is cast on HER page and wrapped in a delegation naming the role page,
   * and the record has to keep both: the inner one says whose key it was, and the outer says which
   * seat it satisfied. Reporting only the outer would record a seated approval as the role approving
   * itself, and reporting only the inner would lose which authority it counted towards.
   */
  it('keeps the inner signer AND the seat it satisfied, rather than flattening them', async () => {
    const key = p256Signer();
    const backend = new DirectVoteBackend(acc(), singleKeyring(key, HER_PAGE), silent, { delegators: [ROLE_PAGE] });
    const res = await backend.cast(votable(HER_PAGE), 'approve');

    expect(res.signedBy?.page).toBe(HER_PAGE);
    expect(res.signedBy?.signatureType).toBe('ecdsaSha256');
    expect(res.signedBy?.delegators).toEqual([ROLE_PAGE]);
  });

  it('says nothing about who the key belongs to, because this process cannot know', async () => {
    const backend = new DirectVoteBackend(acc(), singleKeyring(p256Signer(), HER_PAGE), silent);
    const res = await backend.cast(votable(HER_PAGE), 'approve');

    // No verdict, no boolean, no rank. Three facts and nothing computed from them: a classification
    // frozen here would be this process's opinion, and unreadable against the chain afterwards.
    expect(Object.keys(res.signedBy ?? {}).sort()).toEqual(['delegators', 'page', 'publicKeyHash', 'signatureType']);
  });

  it('reports nothing at all when the vote was not cast', async () => {
    const failing = {
      getSignerInfo: async () => ({ version: 1, lastUsedOn: 0, creditBalance: 100 }),
      submit: async () => ({ ok: false, error: 'network refused' }),
    } as never;
    const backend = new DirectVoteBackend(failing, singleKeyring(new LocalSigner(new Uint8Array(32).fill(5)), PAGE), silent);
    const res = await backend.cast(votable(PAGE), 'approve');

    expect(res.ok).toBe(false);
    // A signature that was never accepted did not satisfy anything, and a record saying which key
    // "signed" a transaction that has no signature on it is worse than a record saying nothing.
    expect(res.signedBy).toBeUndefined();
  });
});
