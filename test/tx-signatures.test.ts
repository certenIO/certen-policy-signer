/**
 * Reading the signatures off a transaction. Runbook F Phase F4, T32.
 *
 * ── THE GAP THIS CLOSES ───────────────────────────────────────────────────────────────────────────
 *
 * The approval console could say *the organisation signed in her name* — our own signer made that
 * signature and knew which of its keys it used — and could NOT say *she signed*, because her
 * certificate signs on chain and nothing read it back. One direction had an alarm and the other had
 * silence, and somebody was eventually going to read the silence as proof.
 *
 * The console cannot read this itself: invariant F-1 keeps chain work in the signer, and its
 * `check-no-chain-code` lint specifically refuses a computed `sha256` in the authority module, because
 * hashing a key to compare it with a page is exactly the two-line change nobody notices making.
 *
 * ── THE SHAPES ARE FROM A REAL RESPONSE ──────────────────────────────────────────────────────────
 *
 * Verified against Kermit on 2026-09-06 using the two-approver transaction of the day before —
 * `acc://5770d714…@twoa1788601803711.acme/data`, whose two ecdsaSha256 key hashes are the two entries
 * on its team page. The reader returned exactly those, plus the submitter's ed25519. The nesting below
 * is that response's shape.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';

const silent = { debug() {}, info() {}, warn() {}, error() {} } as never;

/** A public key and the page entry it hashes to — the pairing the whole feature turns on. */
const key = (seed: string) => {
  const publicKey = Buffer.from(seed.padEnd(64, '0'), 'utf8').toString('hex');
  return { publicKey, hash: createHash('sha256').update(Buffer.from(publicKey, 'hex')).digest('hex') };
};

const ALICE = key('alice-certificate');
const BOB = key('bob-certificate');
const SUBMITTER = key('submitter-ed25519');

/** The record a v3 node returns: signature sets, each holding its own paginated signature records. */
function record(status: string, sigs: unknown[]) {
  return {
    status,
    signatures: { records: [{ signatures: { records: sigs.map((signature) => ({ message: { signature } })) } }] },
  };
}

/** A client whose only real behaviour is the response it is handed. */
function clientReturning(payload: unknown | Error) {
  const c = new RawAccumulateClient('http://node.test/v3', silent);
  (c as unknown as { query: (s: string) => Promise<unknown> }).query = async () => {
    if (payload instanceof Error) throw payload;
    return payload;
  };
  return c;
}

describe('reading the signatures on a transaction', () => {
  it('reports the key hash a page entry would hold, per signature', async () => {
    const out = await clientReturning(record('delivered', [
      { type: 'ecdsaSha256', publicKey: ALICE.publicKey, signer: 'acc://bank.acme/book/1' },
      { type: 'ecdsaSha256', publicKey: BOB.publicKey, signer: 'acc://bank.acme/book/1' },
    ])).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.status).toBe('delivered');
    expect(out.delivered).toBe(true);
    expect(out.signatures.map((s) => s.publicKeyHash)).toEqual([ALICE.hash, BOB.hash]);
    expect(out.signatures[0]!.type).toBe('ecdsaSha256');
    expect(out.signatures[0]!.signer).toBe('acc://bank.acme/book/1');
  });

  it('counts the submitter too, because it really is a signature on the transaction', async () => {
    // Observed on the live run: three signatures, of which one is the ed25519 that created the intent.
    // Filtering it here would be this reader forming an opinion about which signatures count, and the
    // caller — which knows what it is matching against — is where that belongs.
    const out = await clientReturning(record('delivered', [
      { type: 'ed25519', publicKey: SUBMITTER.publicKey },
      { type: 'ecdsaSha256', publicKey: ALICE.publicKey },
    ])).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.signatures).toHaveLength(2);
    expect(out.signatures.map((s) => s.type)).toEqual(['ed25519', 'ecdsaSha256']);
  });

  it('unwraps a delegated signature to the key that signed, and keeps the path', async () => {
    // The shape an employee's seat produces: the signature is made by her key, THROUGH her book. The
    // delegators are what ties it to a roster seat, and the inner key hash is what a page entry holds.
    const out = await clientReturning(record('delivered', [{
      type: 'delegated',
      delegator: 'acc://bank.acme/alice/book',
      signature: { type: 'ecdsaSha256', publicKey: ALICE.publicKey },
    }])).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.signatures).toHaveLength(1);
    expect(out.signatures[0]).toMatchObject({
      type: 'ecdsaSha256',
      publicKeyHash: ALICE.hash,
      delegators: ['acc://bank.acme/alice/book'],
    });
  });

  it('handles delegation several levels deep, outermost first', async () => {
    const out = await clientReturning(record('delivered', [{
      type: 'delegated',
      delegator: 'acc://bank.acme/roles/treasury',
      signature: {
        type: 'delegated',
        delegator: 'acc://bank.acme/alice/book',
        signature: { type: 'ecdsaSha256', publicKey: ALICE.publicKey },
      },
    }])).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.signatures[0]!.delegators).toEqual([
      'acc://bank.acme/roles/treasury',
      'acc://bank.acme/alice/book',
    ]);
    expect(out.signatures[0]!.publicKeyHash).toBe(ALICE.hash);
  });

  it('ignores an entry with no public key, which is an authority rather than somebody signing', async () => {
    // Counting one would inflate "how many people signed this" — the number a reader trusts most.
    const out = await clientReturning(record('delivered', [
      { type: 'authority', authority: 'acc://bank.acme/book' },
      { type: 'ecdsaSha256', publicKey: ALICE.publicKey },
    ])).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.signatures).toHaveLength(1);
    expect(out.signatures[0]!.publicKeyHash).toBe(ALICE.hash);
  });

  it('says PENDING is pending, not delivered', async () => {
    const out = await clientReturning(record('pending', [
      { type: 'ecdsaSha256', publicKey: ALICE.publicKey },
    ])).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.delivered).toBe(false);
    expect(out.status).toBe('pending');
    // One of the two a 2-of-2 page needs. The count is the fact; whether it is enough is the page's
    // business, and this reader does not pretend to know a threshold it did not ask for.
    expect(out.signatures).toHaveLength(1);
  });

  it('reports being unable to ASK as unavailable, never as "nobody signed"', async () => {
    // The distinction `getPendingTx` already draws, for the same reason: a caller that read a timeout
    // as "no signatures" would report an outage as an unsigned transaction.
    const out = await clientReturning(new Error('connect ETIMEDOUT')).getTxSignatures('ab'.repeat(32), 'bank.acme/data');

    expect(out.unavailable).toMatch(/ETIMEDOUT/);
    expect(out.signatures).toEqual([]);
    expect(out.delivered).toBe(false);
  });

  it('finds signatures however the node nests them', async () => {
    // The live response wraps signature records two levels deep and may not expand them the same way
    // twice. A reader that indexed a fixed path would return nothing the day that changed — and
    // "nothing" is the one answer that must never be produced by accident.
    const flat = { status: 'delivered', signatures: [{ message: { signature: { type: 'ed25519', publicKey: ALICE.publicKey } } }] };
    const out = await clientReturning(flat).getTxSignatures('ab'.repeat(32), 'bank.acme/data');
    expect(out.signatures.map((s) => s.publicKeyHash)).toEqual([ALICE.hash]);
  });
});
