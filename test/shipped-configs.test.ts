/**
 * Every config file this repo ships must actually load.
 *
 * These are the files an integrator copies on day one, and a stale one fails in the least helpful way
 * possible: a startup error in someone else's terminal, on their first contact with the product, in a
 * config they did not write. They drift silently — a schema gains a `.strict()`, a key is renamed, a
 * validation rule is added — and nothing else in the suite reads them.
 *
 * The env vars each file needs are declared here rather than mocked away, so this doubles as the answer
 * to "what do I have to set before this config will boot".
 */
import { describe, it, expect, afterEach } from 'vitest';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, effectiveScopeRules } from '../src/config.js';

const ROOT = join(__dirname, '..');

/** Every `env:` ref the shipped configs point at, with a plausible value. */
const ENV: Record<string, string> = {
  VAULT_TOKEN: 'hvs.test-token',
  POLICY_HMAC_SECRET: 'policy-secret',
  WEBHOOK_HMAC_SECRET: 'webhook-secret',
  ADMIN_API_KEY: 'admin-key',
  GOVERNANCE_ADMIN_KEY: 'gov-key',
  GATEWAY_API_KEY: 'ck_live_test',
  TREASURY_SEED_HEX: '11'.repeat(32),
  TRADING_AGENT_HMAC: 'trading-secret',
  SIGNER_SEED_HEX: '22'.repeat(32),
  NOTIFY_HMAC_SECRET: 'notify-secret',
  TWILIO_ACCOUNT_SID: 'ACtest',
  TWILIO_AUTH_TOKEN: 'twilio-token',
  SENDGRID_API_KEY: 'SG.test',
  SLACK_WEBHOOK_URL: 'https://hooks.slack.test/services/T/B/X',
};

function withEnv<T>(fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(ENV)) { saved[k] = process.env[k]; process.env[k] = v; }
  try { return fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

/** Discovered rather than listed, so a config added later is covered without anyone remembering to. */
const shipped = [
  ...readdirSync(ROOT).filter((f) => /^config(\..+)?\.ya?ml$/.test(f) && f !== 'config.yaml' && f !== 'config.local.yaml').map((f) => join(ROOT, f)),
  ...readdirSync(join(ROOT, 'deploy')).filter((f) => /\.ya?ml$/.test(f) && f.startsWith('config.')).map((f) => join(ROOT, 'deploy', f)),
];

describe('shipped configs', () => {
  it('found the files to check (a passing empty list would prove nothing)', () => {
    expect(shipped.length).toBeGreaterThanOrEqual(4);
  });

  for (const path of shipped) {
    const name = path.slice(ROOT.length + 1).replace(/\\/g, '/');

    it(`${name} loads`, () => {
      const cfg = withEnv(() => loadConfig(path));
      expect(cfg.wallet.org_id).toBeTruthy();
      expect(cfg.policy.url).toBeTruthy();
      // Exactly one of the two signing-scope forms — the loader enforces it, but a shipped file that
      // sets neither would still be useless to whoever copies it.
      expect(Boolean(cfg.wallet.signer_url) || Boolean(cfg.wallet.scopes?.length)).toBe(true);
    });

    it(`${name} resolves every scope's effective rules`, () => {
      const cfg = withEnv(() => loadConfig(path));
      for (const s of cfg.wallet.scopes ?? []) {
        const eff = effectiveScopeRules(cfg, s);
        expect(eff.policy.url, `${name} ${s.page}`).toBeTruthy();
        // A ceiling that is not a whole number would throw at BigInt() the first time that page saw
        // work — long after boot, and only for that one scope.
        if (eff.behavior.value_ceiling) expect(() => BigInt(eff.behavior.value_ceiling!)).not.toThrow();
      }
    });
  }

  /**
   * The minimal config is a promise: these five fields and nothing else. If a schema change makes a sixth
   * field mandatory, this is what says so — otherwise the README goes on claiming five while the file it
   * points at no longer boots.
   */
  it('config.minimal.yaml needs no environment at all beyond its seed file', () => {
    // Deliberately NOT wrapped in withEnv: nothing in it may depend on an env var.
    const cfg = loadConfig(join(ROOT, 'config.minimal.yaml'));
    expect(cfg.policy.auth).toBe('none');
    expect(cfg.wallet.signer_url).toBeTruthy();
    expect(cfg.signer?.provider).toBe('local');
  });

  /** The multi-scope example is the fleet story; if its overrides stop taking effect it teaches a lie. */
  it('config.multi-scope.example.yaml actually demonstrates divergent rules', () => {
    const cfg = withEnv(() => loadConfig(join(ROOT, 'config.multi-scope.example.yaml')));
    const rules = cfg.wallet.scopes!.map((s) => effectiveScopeRules(cfg, s));

    expect(rules.some((r) => !r.overridden), 'an inheriting scope').toBe(true);
    expect(rules.some((r) => r.overridden), 'an overriding scope').toBe(true);

    const urls = new Set(rules.map((r) => r.policy.url));
    expect(urls.size, 'more than one policy engine').toBeGreaterThan(1);

    const ceilings = new Set(rules.map((r) => r.behavior.value_ceiling));
    expect(ceilings.size, 'more than one value ceiling').toBeGreaterThan(1);

    expect(rules.some((r) => r.behavior.submit_reject_vote), 'a scope with a veto').toBe(true);
    expect(rules.some((r) => !r.behavior.submit_reject_vote), 'a scope that withholds').toBe(true);
  });
});
