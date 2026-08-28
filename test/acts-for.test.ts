/**
 * When the organisation signs in somebody's name, the record says whose.
 *
 * Runbook F Phase F4. §0.4 accepts a real capability: the organisation may hold a key on a page inside
 * an employee's own identity, so that a certificate can be rotated when it expires and a leaver can be
 * retired. The price is that the same key can approve a payment in her name, and the runbook's job is
 * to make that "a thing the system detects and reports, not a thing the documentation discloses".
 *
 * ── WHY THIS IS DECLARED AND CANNOT BE INFERRED ───────────────────────────────────────────────────
 *
 * `RESEARCH-CONSOLE-AND-SIGNER.md` §5, from the protocol: a key page entry is `sha256(publicKey)` for
 * every key type alike, so **nothing on a page distinguishes a CA-issued certificate from a software
 * key**. An auditor asking "prove these entries are the certificates you say they are" cannot answer
 * it from the key page.
 *
 * So no amount of reading the chain establishes whose key a hash is. The two candidates for inferring
 * it both fail:
 *
 *   the ALGORITHM  looks decisive and is a heuristic. F2 made `ecdsa-p256` configurable for the
 *                  organisation's own key, so "ecdsaSha256 means somebody's certificate" is already
 *                  wrong in a deployment this repository supports.
 *   the PAGE URL   would have to be parsed, and the shape of a URL is a convention rather than a fact
 *                  the protocol enforces.
 *
 * What CAN be known for certain is the thing this file tests: whether the key THIS WALLET USED is one
 * it holds on a named person's behalf. That is not an inference about the chain — it is the
 * deployment's own statement about its own key, and the wallet is the only party that can make it.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DirectVoteBackend } from '../src/vote/backend.js';
import { LocalSigner } from '../src/signer/signer.js';
import { MapKeyring, bookOf, singleKeyring } from '../src/signer/keyring.js';
import { loadConfig } from '../src/config.js';

const silent = pino({ level: 'silent' });
const TX = 'cd'.repeat(32);
const ORG_PAGE = 'acc://bank.acme/book/1';
const HER_PAGE = 'acc://bank.acme/alice/book/1';

function acc() {
  return {
    getSignerInfo: async () => ({ version: 1, lastUsedOn: 0, creditBalance: 100 }),
    submit: async () => ({ ok: true }),
  } as never;
}

const votable = (signerUrl: string) => ({
  txHash: TX, signerUrl, signerVersion: 1, rawTransaction: { header: { principal: 'acc://x.acme/data' } },
  lastUsedOn: 0, account: 'acc://x.acme',
});

const key = (fill: number) => new LocalSigner(new Uint8Array(32).fill(fill));

describe('a key held on somebody else’s behalf', () => {
  it('says whose, when the deployment declared it', async () => {
    const ring = new MapKeyring([
      { page: HER_PAGE, book: bookOf(HER_PAGE), signer: key(1), actsFor: 'Alice Okonkwo' },
    ]);
    const res = await new DirectVoteBackend(acc(), ring, silent).cast(votable(HER_PAGE), 'approve');

    expect(res.ok).toBe(true);
    expect(res.signedBy?.onBehalfOf).toBe('Alice Okonkwo');
  });

  /**
   * The ordinary case, and it must stay silent. An organisation signing as itself is what this product
   * has always done; if that reported "on behalf of" anything, the alarm downstream would fire on
   * every transaction and be worth nothing within a week.
   */
  it('says nothing when the organisation is signing as itself', async () => {
    const ring = new MapKeyring([{ page: ORG_PAGE, book: bookOf(ORG_PAGE), signer: key(2) }]);
    const res = await new DirectVoteBackend(acc(), ring, silent).cast(votable(ORG_PAGE), 'approve');

    expect(res.signedBy?.page).toBe(ORG_PAGE);
    expect(res.signedBy?.onBehalfOf).toBeUndefined();
  });

  it('is absent on the single-key path too, which declares nothing', async () => {
    const res = await new DirectVoteBackend(acc(), singleKeyring(key(3), ORG_PAGE), silent).cast(votable(ORG_PAGE), 'approve');
    expect(res.signedBy?.onBehalfOf).toBeUndefined();
  });

  /**
   * It travels with the SIGNATURE, not with the transaction. A delegated vote is still made with the
   * organisation's key on a page it holds inside somebody's identity, and the seat it satisfies does
   * not change whose key produced it.
   */
  it('survives a delegated vote, where the seat is not the whole story', async () => {
    const ring = new MapKeyring([
      { page: HER_PAGE, book: bookOf(HER_PAGE), signer: key(4), actsFor: 'Alice Okonkwo' },
    ]);
    const res = await new DirectVoteBackend(acc(), ring, silent, { delegators: ['acc://bank.acme/roles/treasury/1'] })
      .cast(votable(HER_PAGE), 'approve');

    expect(res.signedBy?.onBehalfOf).toBe('Alice Okonkwo');
    expect(res.signedBy?.delegators).toEqual(['acc://bank.acme/roles/treasury/1']);
  });
});

describe('declaring it in a config file', () => {
  const write = (yaml: string): string => {
    const dir = mkdtempSync(join(tmpdir(), 'acts-for-'));
    const p = join(dir, 'config.yaml');
    writeFileSync(p, yaml);
    return p;
  };

  const base = (scopeExtra: string) => `
wallet:
  org_id: "bank"
  accumulate_endpoints: ["https://example.test/v3"]
  scopes:
    - page: "acc://bank.acme/alice/book/1"
      key: { provider: "local", local: { seed_hex: "${'a1'.repeat(32)}" } }
${scopeExtra}
policy: { url: "https://engine.test/decide", mode: "sync", auth: "none" }
store: { path: "./state.json" }
health: { bind: "127.0.0.1:8080" }
`;

  it('reads acts_for off a scope', () => {
    const cfg = loadConfig(write(base('      acts_for: "Alice Okonkwo"')));
    expect(cfg.wallet.scopes?.[0]?.acts_for).toBe('Alice Okonkwo');
  });

  it('leaves it absent when nobody declared it', () => {
    const cfg = loadConfig(write(base('')));
    expect(cfg.wallet.scopes?.[0]?.acts_for).toBeUndefined();
  });

  /**
   * An empty string is refused rather than treated as absent. "The organisation signs here on behalf
   * of somebody, and we did not say who" is not a state anybody meant to configure, and it would reach
   * a screen as a blank name beside an alarm.
   */
  it('refuses a blank name rather than reading it as nobody', () => {
    expect(() => loadConfig(write(base('      acts_for: ""')))).toThrow();
  });
});
