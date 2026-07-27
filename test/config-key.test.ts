/**
 * Key injection for the standalone (pilot) deploy: the org's seed arrives via an `env:NAME` ref or a
 * mounted secret file. Both paths must produce the same 32 bytes, and a missing/garbled seed must
 * fail closed — a wallet that boots on the wrong key votes with a signature the network will not accept.
 */
import { describe, it, expect, afterEach, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, resolveLocalSeed } from '../src/config.js';

const SEED = 'a'.repeat(64);
const tmp = mkdtempSync(join(tmpdir(), 'certen-key-'));
let n = 0;

afterEach(() => { delete process.env.TEST_SIGNER_SEED; });
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function writeConfig(signer: string): string {
  const p = join(tmp, `cfg-${n++}.yaml`);
  writeFileSync(p, [
    'wallet: { org_id: "o", network: "kermit", accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"],',
    '          signer_url: "acc://o.acme/book/1", attachment_model: "authority" }',
    signer,
    'policy: { url: "http://127.0.0.1:9099/decision" }',
  ].join('\n'));
  return p;
}

describe('local signer seed injection', () => {
  it('resolves seed_hex from an env: ref (the documented pilot path)', () => {
    process.env.TEST_SIGNER_SEED = SEED;
    const cfg = loadConfig(writeConfig('signer: { provider: "local", local: { seed_hex: "env:TEST_SIGNER_SEED" } }'));
    expect(resolveLocalSeed(cfg.signer!.local)).toEqual(new Uint8Array(Buffer.from(SEED, 'hex')));
  });

  it('resolves an inline seed_hex unchanged', () => {
    const cfg = loadConfig(writeConfig(`signer: { provider: "local", local: { seed_hex: "${SEED}" } }`));
    expect(resolveLocalSeed(cfg.signer!.local)).toEqual(new Uint8Array(Buffer.from(SEED, 'hex')));
  });

  it('reads seed_file, tolerating the trailing newline a secret mount adds', () => {
    const f = join(tmp, 'seed');
    writeFileSync(f, `${SEED}\n`);
    expect(resolveLocalSeed({ seed_file: f })).toEqual(new Uint8Array(Buffer.from(SEED, 'hex')));
  });

  it('fails closed when the env ref is unset (would otherwise sign with a bogus key)', () => {
    const cfg = loadConfig(writeConfig('signer: { provider: "local", local: { seed_hex: "env:TEST_SIGNER_SEED" } }'));
    expect(cfg.signer!.local?.seed_hex).toBeUndefined();
    expect(resolveLocalSeed(cfg.signer!.local)).toBeUndefined(); // -> index.ts refuses to boot
  });

  it('rejects a seed that is not 32 bytes of hex', () => {
    expect(() => resolveLocalSeed({ seed_hex: 'deadbeef' })).toThrow(/64 hex chars/);
    expect(() => resolveLocalSeed({ seed_hex: 'env:TEST_SIGNER_SEED' })).toThrow(/64 hex chars/);
  });

  it('returns nothing when no key is configured, so boot can fail closed', () => {
    expect(resolveLocalSeed(undefined)).toBeUndefined();
    expect(resolveLocalSeed({ allow_ephemeral: true })).toBeUndefined();
  });
});

/**
 * Config sections left empty by commenting out their contents.
 *
 * Disabling options one line at a time leaves the section header behind, and YAML parses a header with
 * no keys as `null` rather than as absent. That used to fail validation with "Expected object, received
 * null" against a file that reads perfectly — a confusing failure at boot, for a shape that plainly
 * means "use the defaults".
 */
describe('an emptied config section falls back to defaults', () => {
  function withSections(extra: string[]): string {
    const p = join(tmp, `sec-${n++}.yaml`);
    writeFileSync(p, [
      'wallet: { org_id: "o", accumulate_endpoints: ["https://example.test/v3"],',
      '          signer_url: "acc://o.acme/book/1" }',
      'signer: { provider: "local", local: { seed_hex: "' + SEED + '" } }',
      'policy: { url: "http://127.0.0.1:9099/decision" }',
      ...extra,
    ].join('\n'));
    return p;
  }

  it('an all-commented section loads instead of throwing', () => {
    const p = withSections(['resolver:', '  # decoder_modules: ["./mine.mjs"]']);
    expect(() => loadConfig(p)).not.toThrow();
  });

  it('and yields the same defaults as omitting it entirely', () => {
    const emptied = loadConfig(withSections(['behavior:', '  # value_ceiling: "1000"']));
    const omitted = loadConfig(withSections([]));
    expect(emptied.behavior).toEqual(omitted.behavior);
    expect(emptied.behavior.max_bad_version_retries).toBe(3);
  });

  it('holds for every defaulted section at once', () => {
    const cfg = loadConfig(withSections(['resolver:', 'behavior:', 'trigger:', 'store:', 'admin:', 'health:', 'observability:', 'gateway:']));
    expect(cfg.health.bind).toBe('0.0.0.0:8080');
    expect(cfg.trigger.poller.interval_seconds).toBe(20);
    expect(cfg.gateway.enabled).toBe(false);
    expect(cfg.observability.log_level).toBe('info');
  });
});
