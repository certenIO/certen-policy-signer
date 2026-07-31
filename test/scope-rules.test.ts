/**
 * Per-scope rules — a fleet of agents under divergent rulebooks in one process.
 *
 * The failure this guards against is quiet and expensive: a scope whose override does not take effect runs
 * under the DEFAULT engine and the DEFAULT ceiling while its config says otherwise. Nothing errors, nothing
 * logs, and a page meant to be capped at 100 signs for 5,000,000. So the tests here are mostly about
 * routing being exact — right engine, right ceiling, right page, every time.
 */
import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { Orchestrator, ScopeRules } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import { makeValueCeilingGuard } from '../src/guard.js';
import { loadConfig, effectiveScopeRules } from '../src/config.js';

const silent = pino({ level: 'silent' });
const PAGE_A = 'acc://agent-a.acme/book/1';
const PAGE_B = 'acc://agent-b.acme/book/1';

/** A pipeline where each page can be given its own rules. `amount` drives the value-ceiling tests. */
function build(scopeRules: Map<string, ScopeRules>, defaults: {
  policy?: MockPolicyClient; guard?: ReturnType<typeof makeValueCeilingGuard>; submitRejectVote?: boolean;
} = {}) {
  const acc = new MockAccumulateClient();
  const store = new MemoryStore();
  const defaultPolicy = defaults.policy ?? new MockPolicyClient({ decision: 'approve' });
  const orchestrator = new Orchestrator({
    accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(3))),
    policy: defaultPolicy, store, resolver: new Resolver(acc), logger: silent,
    scopeRules,
    options: { guard: defaults.guard, submitRejectVote: defaults.submitRejectVote ?? false },
  });
  const add = (tx: string, amount: string) => acc.addPending(tx, {
    body: { type: 'sendTokens', to: [{ url: 'acc://x.acme/tokens', amount }] },
    principal: 'acc://x.acme/tokens',
  });
  return { orchestrator, store, acc, add, defaultPolicy };
}

describe('per-scope policy routing', () => {
  it('sends each page to its own engine, and unlisted pages to the default', async () => {
    const engineA = new MockPolicyClient({ decision: 'approve', reason: 'engine-A' });
    const engineDefault = new MockPolicyClient({ decision: 'approve', reason: 'default' });
    const { orchestrator, store, add } = build(
      new Map([[PAGE_A.toLowerCase(), { policy: engineA }]]),
      { policy: engineDefault },
    );
    add('a'.repeat(64), '10');
    add('b'.repeat(64), '10');

    await orchestrator.handle({ txHash: 'a'.repeat(64), signerUrl: PAGE_A });
    await orchestrator.handle({ txHash: 'b'.repeat(64), signerUrl: PAGE_B });

    expect(engineA.calls).toHaveLength(1);
    expect(engineDefault.calls).toHaveLength(1);
    expect((await store.getReceipt('a'.repeat(64)))?.reason).toBe('engine-A');
    expect((await store.getReceipt('b'.repeat(64)))?.reason).toBe('default');
  });

  /**
   * Accumulate URLs are case-insensitive, so a scope written with capitals in config must still match the
   * page the node reports. A miss here does not error — it silently runs that page under the DEFAULT
   * rules, which is precisely the failure per-scope rules exist to prevent.
   */
  it('matches the page case-insensitively', async () => {
    const engineA = new MockPolicyClient({ decision: 'approve', reason: 'engine-A' });
    const { orchestrator, add } = build(new Map([[PAGE_A.toLowerCase(), { policy: engineA }]]));
    add('c'.repeat(64), '10');
    await orchestrator.handle({ txHash: 'c'.repeat(64), signerUrl: 'acc://Agent-A.acme/BOOK/1'.replace('BOOK', 'book') });
    expect(engineA.calls).toHaveLength(1);
  });

  it('one engine being down does not stop another page from signing', async () => {
    const broken = new MockPolicyClient(() => { throw new Error('engine A is down'); });
    const { orchestrator, store, add } = build(new Map([[PAGE_A.toLowerCase(), { policy: broken }]]));
    add('d'.repeat(64), '10');
    add('e'.repeat(64), '10');

    const a = await orchestrator.handle({ txHash: 'd'.repeat(64), signerUrl: PAGE_A });
    const b = await orchestrator.handle({ txHash: 'e'.repeat(64), signerUrl: PAGE_B });

    expect(a.status).toBe('awaiting_policy');      // withheld, fail-closed
    expect(b.status).toBe('signed');               // unaffected
  });
});

describe('per-scope value ceiling', () => {
  it('applies each page\'s own ceiling', async () => {
    const { orchestrator, store, add } = build(new Map([
      [PAGE_A.toLowerCase(), { guard: makeValueCeilingGuard(100n) }],
      [PAGE_B.toLowerCase(), { guard: makeValueCeilingGuard(5_000_000n) }],
    ]));
    add('1'.repeat(64), '1000');
    add('2'.repeat(64), '1000');

    const a = await orchestrator.handle({ txHash: '1'.repeat(64), signerUrl: PAGE_A });
    const b = await orchestrator.handle({ txHash: '2'.repeat(64), signerUrl: PAGE_B });

    // Same amount, same engine approval — only the page differs.
    expect(a.status).toBe('rejected');
    expect(a.lastError).toBe('local_guard_block');
    expect(b.status).toBe('signed');
  });

  it('a scope without a ceiling inherits the default one', async () => {
    const { orchestrator, add } = build(
      new Map([[PAGE_A.toLowerCase(), { submitRejectVote: true }]]),   // overrides something else entirely
      { guard: makeValueCeilingGuard(100n) },
    );
    add('3'.repeat(64), '1000');
    expect((await orchestrator.handle({ txHash: '3'.repeat(64), signerUrl: PAGE_A })).lastError).toBe('local_guard_block');
  });
});

describe('per-scope reject-vote behavior', () => {
  it('one page casts reject votes while another withholds', async () => {
    const { orchestrator, store, add } = build(
      new Map([[PAGE_A.toLowerCase(), { submitRejectVote: true }]]),
      { policy: new MockPolicyClient({ decision: 'deny', reason: 'nope' }), submitRejectVote: false },
    );
    add('4'.repeat(64), '10');
    add('5'.repeat(64), '10');

    await orchestrator.handle({ txHash: '4'.repeat(64), signerUrl: PAGE_A });
    await orchestrator.handle({ txHash: '5'.repeat(64), signerUrl: PAGE_B });

    // A panel seat that withholds and a treasury page with a veto, in one process.
    expect((await store.getReceipt('4'.repeat(64)))?.vote).toBe('reject');
    expect((await store.getReceipt('5'.repeat(64)))?.vote).toBeUndefined();
  });
});

// ── config layer ────────────────────────────────────────────────────────────────────────────────────

function writeConfig(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'signer-cfg-'));
  const p = join(dir, 'config.yaml');
  writeFileSync(p, body, 'utf8');
  return p;
}

const BASE = `
wallet:
  org_id: fleet
  accumulate_endpoints: ["https://example.test/v3"]
  scopes:
    - page: "acc://agent-a.acme/book/1"
      key: { provider: local, local: { seed_hex: "${'11'.repeat(32)}" } }
      SCOPE_A_EXTRA
    - page: "acc://agent-b.acme/book/1"
      key: { provider: local, local: { seed_hex: "${'22'.repeat(32)}" } }
policy:
  url: "https://default.test/decision"
behavior:
  value_ceiling: "1000"
`;

const withScopeA = (extra: string) => BASE.replace('SCOPE_A_EXTRA', extra);

describe('config: per-scope overrides', () => {
  it('merges an override over the defaults, field by field', () => {
    const cfg = loadConfig(writeConfig(withScopeA(`
      policy: { url: "https://agent-a.test/decision" }
      behavior: { value_ceiling: "50" }`)));

    const a = effectiveScopeRules(cfg, cfg.wallet.scopes![0]);
    const b = effectiveScopeRules(cfg, cfg.wallet.scopes![1]);

    expect(a.policy.url).toBe('https://agent-a.test/decision');
    expect(a.behavior.value_ceiling).toBe('50');
    expect(a.overridden).toBe(true);
    // Inherited, not lost: the override stated a url, so everything else still comes from the default.
    expect(a.policy.timeout_ms).toBe(cfg.policy.timeout_ms);

    expect(b.policy.url).toBe('https://default.test/decision');
    expect(b.behavior.value_ceiling).toBe('1000');
    expect(b.overridden).toBe(false);
  });

  /**
   * A misspelled key would otherwise mean "inherit", and the scope would run under rules its own config
   * appears to contradict. Naming the key at boot is the only cheap moment to catch it.
   */
  it('rejects an unknown key in an override instead of silently inheriting', () => {
    expect(() => loadConfig(writeConfig(withScopeA('behavior: { value_celing: "50" }'))))
      .toThrow(/unrecognized key|Unrecognized key/i);
  });

  it('holds a scope override to the same policy.auth rules as the default', () => {
    // hmac with no secret anywhere — the scope must not be allowed to state authentication it lacks.
    expect(() => loadConfig(writeConfig(withScopeA('policy: { auth: "hmac" }'))))
      .toThrow(/scope acc:\/\/agent-a\.acme\/book\/1: policy\.auth is "hmac"/);
  });

  it('refuses mtls in a scope override, as at the top level', () => {
    expect(() => loadConfig(writeConfig(withScopeA('policy: { auth: "mtls" }'))))
      .toThrow(/not implemented/);
  });

  it('a scope inheriting a default secret satisfies its own hmac override', () => {
    process.env.TEST_SCOPE_SECRET = 's3cret';
    const cfg = loadConfig(writeConfig(`
wallet:
  org_id: fleet
  accumulate_endpoints: ["https://example.test/v3"]
  scopes:
    - page: "acc://agent-a.acme/book/1"
      key: { provider: local, local: { seed_hex: "${'11'.repeat(32)}" } }
      policy: { url: "https://agent-a.test/decision" }
policy:
  url: "https://default.test/decision"
  auth: "hmac"
  hmac_secret: "env:TEST_SCOPE_SECRET"
`));
    expect(effectiveScopeRules(cfg, cfg.wallet.scopes![0]).policy.hmac_secret).toBe('s3cret');
    delete process.env.TEST_SCOPE_SECRET;
  });

  it('resolves a scope\'s OWN env: secret ref', () => {
    process.env.TEST_AGENT_A_SECRET = 'a-only';
    const cfg = loadConfig(writeConfig(withScopeA(
      'policy: { auth: "hmac", hmac_secret: "env:TEST_AGENT_A_SECRET" }')));
    expect(effectiveScopeRules(cfg, cfg.wallet.scopes![0]).policy.hmac_secret).toBe('a-only');
    delete process.env.TEST_AGENT_A_SECRET;
  });

  /** Two pollers on one page race each other and both compete in the keyring. Always a copy-paste slip. */
  it('rejects duplicate pages', () => {
    expect(() => loadConfig(writeConfig(`
wallet:
  org_id: fleet
  accumulate_endpoints: ["https://example.test/v3"]
  scopes:
    - page: "acc://dup.acme/book/1"
      key: { provider: local, local: { seed_hex: "${'11'.repeat(32)}" } }
    - page: "acc://DUP.acme/book/1"
      key: { provider: local, local: { seed_hex: "${'22'.repeat(32)}" } }
policy:
  url: "https://default.test/decision"
`))).toThrow(/two entries for/);
  });

  it('rejects a non-numeric value ceiling rather than throwing at BigInt() later', () => {
    expect(() => loadConfig(writeConfig(withScopeA('behavior: { value_ceiling: "1_000" }'))))
      .toThrow(/value_ceiling must be a whole number/);
  });
});
