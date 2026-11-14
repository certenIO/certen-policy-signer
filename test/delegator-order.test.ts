/**
 * Delegator order: one convention, hop order. Wrapper runbook, change 3 (Phase 1).
 *
 * ── THE BUG THIS PINS ─────────────────────────────────────────────────────────────────────────────
 *
 * Reading and signing used opposite orders. `unwrapDelegation` walks the wire form from the outside in,
 * so it returns the OUTERMOST delegator first: for Alice's two-hop signature (her key → her wrapper
 * `P/id/1` → the org page `O/book/1`) that is `[O, W]`. `buildPreimage` wraps its FIRST element
 * innermost, so it needs `[W, O]`. Fed straight through, the signer would nest a two-hop vote backwards.
 * Single-hop never showed it: a one-element list reads the same either way round.
 *
 * The network's own order is hop order — `unwrapDelegated` collects outermost first and then reverses
 * (accumulate-core `block/sig_user.go:158-184`), and routes the vote to `Delegator[0]`
 * (`protocol/signature.go:1027-1032`). So `hops` is what signs, and `delegators` stays what it was for
 * the readers that already depend on it.
 */
import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { buildPreimage, buildDelegatedSignatureObject, toHopOrder, bytesToHex } from '../src/accumulate/signing.js';

const silent = { debug() {}, info() {}, warn() {}, error() {} } as never;

const ALICE_PAGE = 'acc://p.acme/book/1';
const W = 'acc://p.acme/id/1';       // Alice's wrapper page: the first hop
const O = 'acc://o.acme/book/1';     // the org page the wrapper sits on: the second hop
const TX = 'cd'.repeat(32);

const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));

/** Sign a vote through `hops` exactly as the vote backend does, and return the wire object. */
function signThrough(hops: string[]) {
  const pre = buildPreimage(Buffer.from(TX, 'hex'), {
    publicKey: kp.publicKey, signerUrl: ALICE_PAGE, signerVersion: 1, timestamp: 1_790_000_000_000_000, vote: 'approve',
    ...(hops.length ? { delegators: hops } : {}),
  });
  const sig = nacl.sign.detached(pre.dataForSignature, kp.secretKey);
  return { pre, sig, wire: buildDelegatedSignatureObject(pre, sig, TX) as Record<string, unknown> };
}

/** Read the wire object back through the same unwrap `getTxSignatures` uses, from a node's record shape. */
async function readBack(wire: unknown) {
  const c = new RawAccumulateClient('http://node.test/v3', silent);
  (c as unknown as { query: () => Promise<unknown> }).query = async () => ({
    status: 'pending',
    signatures: { records: [{ signatures: { records: [{ message: { signature: wire } }] } }] },
  });
  const out = await c.getTxSignatures(TX, 'o.acme/tokens');
  expect(out.signatures).toHaveLength(1);
  return out.signatures[0]!;
}

describe('delegator order', () => {
  it('a two-hop signature built from hops [W, O] nests W innermost, so the outermost wrapper names O', () => {
    const { wire } = signThrough([W, O]);
    // The outermost DelegatedSignature is the LAST hop. The network unwraps it first and then reverses.
    expect(wire['type']).toBe('delegated');
    expect(String(wire['delegator'])).toBe(O);
    const next = wire['signature'] as Record<string, unknown>;
    expect(String(next['delegator'])).toBe(W);
    expect((next['signature'] as Record<string, unknown>)['signer']).toBe(ALICE_PAGE);
  });

  it('reading it back gives delegators outermost first [O, W] and hops in hop order [W, O]', async () => {
    const read = await readBack(signThrough([W, O]).wire);
    expect(read.delegators).toEqual([O, W]);
    expect(read.hops).toEqual([W, O]);
  });

  it('round trips: hops -> sign -> wire -> unwrap -> hops is the input, and the signature still verifies', async () => {
    for (const hops of [[W, O], ['acc://a.acme/book/1', W, O], [W]]) {
      const { pre, sig, wire } = signThrough(hops);
      const read = await readBack(wire);
      expect(read.hops).toEqual(hops);
      expect(toHopOrder(read.delegators)).toEqual(hops);
      // Re-sign from what was read: the preimage must be the one originally signed, or the network would
      // compute a different metadata hash and refuse the vote.
      const again = buildPreimage(Buffer.from(TX, 'hex'), {
        publicKey: kp.publicKey, signerUrl: ALICE_PAGE, signerVersion: 1, timestamp: 1_790_000_000_000_000, vote: 'approve', delegators: read.hops,
      });
      expect(bytesToHex(again.dataForSignature)).toBe(bytesToHex(pre.dataForSignature));
      expect(nacl.sign.detached.verify(again.dataForSignature, sig, kp.publicKey)).toBe(true);
    }
  });

  it('feeding the outermost-first list back in produces a DIFFERENT preimage (the bug, made visible)', async () => {
    const { pre, wire } = signThrough([W, O]);
    const read = await readBack(wire);
    const backwards = buildPreimage(Buffer.from(TX, 'hex'), {
      publicKey: kp.publicKey, signerUrl: ALICE_PAGE, signerVersion: 1, timestamp: 1_790_000_000_000_000, vote: 'approve', delegators: read.delegators,
    });
    expect(bytesToHex(backwards.dataForSignature)).not.toBe(bytesToHex(pre.dataForSignature));
  });

  it('a one-hop path is the same in both fields (back-compat with every single-hop caller)', async () => {
    const read = await readBack(signThrough([W]).wire);
    expect(read.delegators).toEqual([W]);
    expect(read.hops).toEqual([W]);
  });

  it('a direct signature has empty delegators and empty hops', async () => {
    const read = await readBack(signThrough([]).wire);
    expect(read.delegators).toEqual([]);
    expect(read.hops).toEqual([]);
  });

  it('toHopOrder copies rather than reversing in place', () => {
    const outer = [O, W];
    expect(toHopOrder(outer)).toEqual([W, O]);
    expect(outer).toEqual([O, W]);
  });
});
