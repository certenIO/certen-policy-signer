/**
 * Multi-scope keyring + config scopes. Proves: the keyring routes signing to the key that sits on each
 * page, refuses pages it holds no key for (fail-closed), and that config parses both the single-scope and
 * multi-scope forms (rejecting an ambiguous or empty one).
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { MapKeyring, singleKeyring, bookOf, buildSignerFromSpec, SigningScope } from '../src/signer/keyring.js';
import { LocalSigner } from '../src/signer/signer.js';
import { loadConfig } from '../src/config.js';

const silent = pino({ level: 'silent' });
const SEED_A = 'a1'.repeat(32);
const SEED_B = 'b2'.repeat(32);

function scope(page: string, seedFill: number, book?: string): SigningScope {
  return { page, book: book ?? bookOf(page), signer: new LocalSigner(new Uint8Array(32).fill(seedFill)) };
}

describe('bookOf', () => {
  it('strips the page index to get the parent book', () => {
    expect(bookOf('acc://o.acme/book/1')).toBe('acc://o.acme/book');
    expect(bookOf('acc://o.acme/book2/3')).toBe('acc://o.acme/book2');
  });
});

describe('MapKeyring routing', () => {
  const a = scope('acc://a.acme/book/1', 1);
  const b = scope('acc://b.acme/book2/1', 2, 'acc://b.acme/book2');
  const ring = new MapKeyring([a, b]);

  it('returns the key that sits on each page', () => {
    expect(ring.forPage('acc://a.acme/book/1')).toBe(a.signer);
    expect(ring.forPage('acc://b.acme/book2/1')).toBe(b.signer);
    expect(ring.forPage('acc://a.acme/book/1')).not.toBe(b.signer);
  });

  it('normalises scheme, case, and trailing slash when matching', () => {
    expect(ring.forPage('a.acme/book/1')).toBe(a.signer);
    expect(ring.forPage('ACC://A.ACME/BOOK/1')).toBe(a.signer);
    expect(ring.forPage('acc://a.acme/book/1/')).toBe(a.signer);
  });

  it('FAILS CLOSED on a page it holds no key for', () => {
    expect(() => ring.forPage('acc://evil.acme/book/1')).toThrow(/no signing key configured/);
  });

  it('exposes every scope and rejects duplicates / empties', () => {
    expect(ring.scopes().map((s) => s.page)).toEqual(['acc://a.acme/book/1', 'acc://b.acme/book2/1']);
    expect(() => new MapKeyring([])).toThrow(/at least one/);
    expect(() => new MapKeyring([a, a])).toThrow(/duplicate/);
  });
});

describe('singleKeyring (wildcard)', () => {
  it('returns its one key for any page asked', () => {
    const s = new LocalSigner(new Uint8Array(32).fill(7));
    const ring = singleKeyring(s);
    expect(ring.forPage('acc://anything.acme/book/1')).toBe(s);
    expect(ring.forPage('acc://other.acme/book/9')).toBe(s);
  });
});

describe('buildSignerFromSpec', () => {
  it('builds a LocalSigner from a hex seed', async () => {
    const s = buildSignerFromSpec({ provider: 'local', local: { seed_hex: SEED_A } }, silent, 'test');
    expect((await s.publicKey()).length).toBe(32);
  });
  it('throws when a local provider has no seed and no ephemeral flag', () => {
    expect(() => buildSignerFromSpec({ provider: 'local', local: {} }, silent, 'test')).toThrow(/seed_hex or local.seed_file/);
  });
});

describe('config: scopes parsing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'certen-cfg-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const base = `
policy: { url: "http://127.0.0.1:9099/decision" }
`;
  const write = (name: string, body: string) => { const p = join(dir, name); writeFileSync(p, body); return p; };

  it('parses a MULTI-scope config and resolves per-scope env secrets', () => {
    process.env.KEYRING_TEST_SEED = SEED_A;
    const p = write('multi.yaml', `
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.example/v3"]
  scopes:
    - page: "acc://a.acme/book/1"
      key: { provider: "local", local: { seed_hex: "env:KEYRING_TEST_SEED" } }
    - page: "acc://b.acme/book2/1"
      book: "acc://b.acme/book2"
      key: { provider: "local", local: { seed_hex: "${SEED_B}" } }
${base}`);
    const cfg = loadConfig(p);
    expect(cfg.wallet.scopes).toHaveLength(2);
    expect(cfg.wallet.scopes![0].key.local!.seed_hex).toBe(SEED_A);   // env:… resolved
    expect(cfg.wallet.scopes![1].book).toBe('acc://b.acme/book2');
    delete process.env.KEYRING_TEST_SEED;
  });

  it('still parses the SINGLE-scope form (signer_url + signer)', () => {
    const p = write('single.yaml', `
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.example/v3"]
  signer_url: "acc://a.acme/book/1"
signer: { provider: "local", local: { seed_hex: "${SEED_A}" } }
${base}`);
    const cfg = loadConfig(p);
    expect(cfg.wallet.signer_url).toBe('acc://a.acme/book/1');
    expect(cfg.signer!.local!.seed_hex).toBe(SEED_A);
  });

  it('rejects a config that sets BOTH signer_url and scopes', () => {
    const p = write('both.yaml', `
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.example/v3"]
  signer_url: "acc://a.acme/book/1"
  scopes:
    - page: "acc://a.acme/book/1"
      key: { provider: "local", local: { seed_hex: "${SEED_A}" } }
signer: { provider: "local", local: { seed_hex: "${SEED_A}" } }
${base}`);
    expect(() => loadConfig(p)).toThrow(/EITHER wallet.scopes\[\] OR wallet.signer_url/);
  });

  it('rejects a config that sets NEITHER', () => {
    const p = write('neither.yaml', `
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.example/v3"]
${base}`);
    expect(() => loadConfig(p)).toThrow(/wallet.signer_url .* or wallet.scopes/);
  });
});
