/**
 * DAX-F191: a bound decision is single-use for a vote that was SUBMITTED; a submission that signed nothing releases it for a retry.
 *
 * Live, tcl98 2026-11-24 (bank-risk, funding tx 8734b013..., 22f4fe86...): `decision bound and consumed`, then `could not sign as the named
 * approver` (no key "tomas.reyes" on the page), `vote submission failed`, and every later poll `decision_replayed`: the decision was burned
 * by a vote that never existed, and the payment could never complete even once the cause was fixed.
 *
 * The rule now: a failure where nothing was signed releases the decision (same bytes, same nonce, within its window) in ONE journal entry that
 * is also the failure record (`recheck.result`, outcome `decision_released`), with an audit line. A vote that was sent stays consumed unless
 * the chain, read, shows none of this signer's keys signed the transaction; a vote that landed, or whose outcome the chain cannot tell, stays
 * consumed. The real Orchestrator, journal and core binding over a temp directory; a mock Accumulate client. FICTIONAL.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { H, intentBody } from './support/binding-fixtures.js';
import { SIGNER, TX, approveFor, rig } from './support/binding-rig.js';
import { LocalSigner } from '../src/signer/signer.js';
import { MapKeyring, singleKeyring } from '../src/signer/keyring.js';
import type { Decision } from '../src/types.js';
import type { TxSignatures } from '../src/accumulate/client.js';

const BASE = intentBody();
const NONCE = H('nonce-fixed');
const SEED = new Uint8Array(32).fill(7);

/** the seat key, whose sign() refuses the first `failures` times (a custody refusal): nothing is signed */
function flakyKey(failures: number): LocalSigner {
  const k = new LocalSigner(SEED);
  let left = failures;
  const real = k.sign.bind(k);
  k.sign = async (m: Uint8Array) => {
    if (left > 0) { left -= 1; throw new Error('custody refused (FICTIONAL)'); }
    return real(m);
  };
  return k;
}

async function seatKeyHash(): Promise<string> {
  return createHash('sha256').update(await new LocalSigner(SEED).publicKey()).digest('hex');
}

const journalLines = (dir: string): Array<{ kind: string; payload: Record<string, unknown> }> =>
  readFileSync(join(dir, 'decision-journal.jsonl'), 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l) as { kind: string; payload: Record<string, unknown> });
const released = (dir: string) => journalLines(dir).filter((e) => e.kind === 'recheck.result' && e.payload['outcome'] === 'decision_released');

/** a chain reader answering `signatures` for the transaction */
const chainSays = (signatures: Array<{ publicKeyHash: string; vote?: 'approve' | 'reject' }>) =>
  async (): Promise<TxSignatures> => ({ status: 'pending', delivered: false, signatures: signatures.map((s) => ({ type: 'ed25519', publicKeyHash: s.publicKeyHash, delegators: [], hops: [], ...(s.vote ? { vote: s.vote } : {}) })) as never });
const chainUnreadable = async (): Promise<TxSignatures> => ({ status: '', delivered: false, signatures: [], unavailable: 'node timeout (FICTIONAL)' });

describe('DAX-F191: a submission that signed nothing releases the decision', () => {
  it('the live case: the decision names a key the seat signer does not hold; released, and the retry (Console fixed) signs once with the seat key', async () => {
    let named = true;
    const withRef = approveFor(BASE);
    const reply = (): Decision => {
      const d = withRef();
      return named ? { ...d, evidence: { approverKeyRefs: ['tomas.reyes'], approverKeyRef: 'tomas.reyes' } } : d;
    };
    // the mode (a) seat signer: the seat's machine key on its page, no approver keys (`known keys: none configured`)
    const r = rig({ body: BASE, reply, keyring: new MapKeyring([{ page: SIGNER, book: 'acc://o.acme/book', signer: new LocalSigner(SEED) }]) });
    const first = await r.handle();
    expect(first.status).toBe('error');
    expect(first.lastError).toMatch(/no key "tomas\.reyes"/);
    expect(r.acc.submissions).toHaveLength(0);
    // released: the nonce is no longer spent, and the journal entry that released it is the failure record
    expect(r.nonces.list()).toEqual([]);
    const rel = released(r.dir);
    expect(rel).toHaveLength(1);
    expect(rel[0]!.payload).toMatchObject({ nonce: NONCE, txHash: TX, chain: 'not_signed' });
    expect(String(rel[0]!.payload['error'])).toMatch(/no key "tomas\.reyes"/);

    named = false; // the Console no longer names a key on a mode (a) seat
    const second = await r.handle();
    expect(second.status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
    expect(r.nonces.list()).toEqual([NONCE]);
  });

  it('fail-before shape: a custody refusal (nothing signed), then the SAME decision bytes and nonce sign once; a landed vote is never re-cast', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE), keyring: singleKeyring(flakyKey(1)) });
    expect((await r.handle()).status).toBe('error');
    expect(r.acc.submissions).toHaveLength(0);
    expect(r.nonces.has(NONCE)).toBe(false);

    const second = await r.handle();
    expect(second.status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);

    // the vote landed: the same decision presented again, after a restart, is a replay and is never cast again
    const again = rig({ dir: r.dir, body: BASE, reply: approveFor(BASE) });
    const row = await again.handle();
    expect(row.lastError).toBe('binding: decision_replayed');
    expect(again.acc.submissions).toHaveLength(0);
    expect(released(r.dir)).toHaveLength(1);
  });

  it('a release survives a restart: the journal fold gives the nonce back exactly once', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE), keyring: singleKeyring(flakyKey(1)) });
    await r.handle();
    const restarted = rig({ dir: r.dir, body: BASE, reply: approveFor(BASE) });
    expect(restarted.nonces.has(NONCE)).toBe(false);
    expect((await restarted.handle()).status).toBe('signed');
    expect(restarted.nonces.list()).toEqual([NONCE]);
  });
});

describe('DAX-F191: a vote that was sent is released only on a chain read that shows it absent', () => {
  it('a refused submit, the chain read shows none of our keys: released, and the retry signs once', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE) });
    r.acc.submitQueue.push({ ok: false, code: 'error', error: 'node refused the envelope (FICTIONAL)' });
    (r.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = chainSays([{ publicKeyHash: 'ee'.repeat(32) }]);
    expect((await r.handle()).status).toBe('error');
    expect(r.acc.submissions).toHaveLength(1);
    expect(released(r.dir)[0]?.payload).toMatchObject({ nonce: NONCE, chain: 'absent' });
    expect((await r.handle()).status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(2);
  });

  it('a refused submit whose signature IS on chain (the vote landed) stays consumed: never re-cast', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE) });
    r.acc.submitQueue.push({ ok: false, code: 'error', error: 'node said error but executed it (FICTIONAL)' });
    (r.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = chainSays([{ publicKeyHash: await seatKeyHash() }]);
    expect((await r.handle()).status).toBe('error');
    expect(released(r.dir)).toHaveLength(0);
    expect(r.nonces.has(NONCE)).toBe(true);
    expect((await r.handle()).lastError).toBe('binding: decision_replayed');
    expect(r.acc.submissions).toHaveLength(1);
  });

  it('an ambiguous submit (no answer) is not released without a chain read: an unreadable chain keeps it consumed', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE), options: { submitOutcomeTimeoutMs: 1 } });
    r.acc.submitQueue.push({ ok: false, uncertain: true, error: 'timeout (FICTIONAL)' });
    (r.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = chainUnreadable;
    expect((await r.handle()).status).toBe('error');
    expect(released(r.dir)).toHaveLength(0);
    expect(r.nonces.has(NONCE)).toBe(true);
    expect((await r.handle()).lastError).toBe('binding: decision_replayed');
    expect(r.acc.submissions).toHaveLength(1);
  });

  it('an ambiguous submit with NO chain reader at all stays consumed', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE), options: { submitOutcomeTimeoutMs: 1 } });
    r.acc.submitQueue.push({ ok: false, uncertain: true, error: 'timeout (FICTIONAL)' });
    expect((await r.handle()).status).toBe('error');
    expect(released(r.dir)).toHaveLength(0);
    expect(r.nonces.has(NONCE)).toBe(true);
  });

  it('an ambiguous submit the chain read shows absent is released, and the retry signs once', async () => {
    const r = rig({ body: BASE, reply: approveFor(BASE), options: { submitOutcomeTimeoutMs: 1 } });
    r.acc.submitQueue.push({ ok: false, uncertain: true, error: 'timeout (FICTIONAL)' });
    (r.acc as unknown as { getTxSignatures: unknown }).getTxSignatures = chainSays([]);
    expect((await r.handle()).status).toBe('error');
    expect(released(r.dir)[0]?.payload).toMatchObject({ nonce: NONCE, chain: 'absent' });
    expect((await r.handle()).status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(2);
  });
});

describe('DAX-F191: a pause that stops the cast after the decision was bound signs nothing and releases it', () => {
  it('paused at the cast: released; resumed: the same decision signs once', async () => {
    let paused = false;
    let calls = 0;
    const gate = {
      check: () => {
        calls += 1;
        return paused ? { ok: false as const, reason: 'paused' } : ({ ok: true } as never);
      },
    };
    const r = rig({ body: BASE, reply: approveFor(BASE), pauseGate: gate as never, keyring: singleKeyring(new LocalSigner(SEED)) });
    // pause between the binding and the cast: the keyring's signer is asked for its public key only at the cast, after the bind
    const origScope = r.orch as unknown as { pausedFor: (...a: unknown[]) => unknown };
    const real = origScope.pausedFor.bind(r.orch);
    let n = 0;
    origScope.pausedFor = (...a: unknown[]) => { n += 1; if (n >= 3) paused = true; return real(...a); };
    const first = await r.handle();
    expect(first.lastError).toBe('paused');
    expect(r.acc.submissions).toHaveLength(0);
    expect(released(r.dir)[0]?.payload).toMatchObject({ nonce: NONCE, chain: 'not_signed' });
    paused = false;
    n = -100;
    expect((await r.handle()).status).toBe('signed');
    expect(r.acc.submissions).toHaveLength(1);
    expect(calls).toBeGreaterThan(0);
  });
});
