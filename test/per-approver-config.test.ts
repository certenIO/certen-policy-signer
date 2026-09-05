/**
 * Config -> keyring, for a role page with one seat per approver. Runbook F, T29-b.
 *
 * `scopes[].keys` has existed since F2, and T29 gave the refs a meaning: each one is an approver's
 * CONSOLE SIGN-IN, because that is the string the console puts on its decision. This proves the whole
 * path — a YAML file with two approvers produces a keyring that returns a different key for each, and
 * refuses a ref it was not given.
 *
 * The refusal is the part worth testing. A wallet that fell back to the scope's own key for an unknown
 * ref would sign one person's approval with the organisation's key, and the record would carry that
 * forever with nothing to show it happened.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { loadConfig } from '../src/config.js';
import { MapKeyring, bookOf, buildSignerFromSpec, type SigningScope } from '../src/signer/keyring.js';

const silent = pino({ level: 'silent' });
const dir = mkdtempSync(join(tmpdir(), 'certen-approver-cfg-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const PAGE = 'acc://bank.acme/roles/treasury/1';
const ALICE = 'alice@bank.example';
const BOB = 'bob@bank.example';

const ORG_SEED = '11'.repeat(32);
const ALICE_SEED = '22'.repeat(32);
const BOB_SEED = '33'.repeat(32);

/** A config with one role page and a seat per approver, keyed by console sign-in. */
function configFile(body: string): string {
  const p = join(dir, `cfg-${Math.random().toString(36).slice(2)}.yaml`);
  writeFileSync(p, body);
  return p;
}

const YAML = `
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"]
  scopes:
    - page: "${PAGE}"
      key:  { provider: "local", local: { seed_hex: "${ORG_SEED}" } }
      keys:
        "${ALICE}": { provider: "local", local: { seed_hex: "${ALICE_SEED}" } }
        "${BOB}":   { provider: "local", local: { seed_hex: "${BOB_SEED}" } }
policy: { url: "http://127.0.0.1:9099/decision" }
`;

/** Build the keyring the way src/index.ts does, from a loaded config. */
function keyringFrom(cfgPath: string): MapKeyring {
  const cfg = loadConfig(cfgPath);
  const scopes: SigningScope[] = cfg.wallet.scopes!.map((s, i) => ({
    page: s.page,
    book: s.book ?? bookOf(s.page),
    signer: buildSignerFromSpec(s.key, silent, `scope[${i}]`),
    ...(s.keys
      ? { keys: Object.fromEntries(Object.entries(s.keys).map(([ref, spec]) => [ref, buildSignerFromSpec(spec, silent, `scope[${i}] key[${ref}]`)])) }
      : {}),
  }));
  return new MapKeyring(scopes);
}

const pub = async (k: { publicKey(): Promise<Uint8Array> }) => Buffer.from(await k.publicKey()).toString('hex');

describe('a role page with one seat per approver', () => {
  it('gives each approver their own key, and the organisation a different one again', async () => {
    const ring = keyringFrom(configFile(YAML));

    const org = await pub(ring.forPage(PAGE));
    const alice = await pub(ring.forPage(PAGE, ALICE));
    const bob = await pub(ring.forPage(PAGE, BOB));

    expect(new Set([org, alice, bob]).size).toBe(3);
  });

  it('accepts a console sign-in verbatim as the ref, "@" and all', async () => {
    // The console sends the account somebody signed in with. A config keyed on "alice" would match
    // nothing this console ever sends, and every one of her votes would be refused.
    const ring = keyringFrom(configFile(YAML));
    expect(() => ring.forPage(PAGE, ALICE)).not.toThrow();
    expect(() => ring.forPage(PAGE, 'alice')).toThrow(/no key "alice" configured/);
  });

  it('REFUSES a ref it holds no key for rather than falling back to the organisation', async () => {
    const ring = keyringFrom(configFile(YAML));
    expect(() => ring.forPage(PAGE, 'mallory@bank.example'))
      // The message names the page AND lists the refs it does hold, so an operator who mistyped one
      // can see the difference rather than guess at it.
      .toThrow(/no key "mallory@bank.example" configured on page acc:\/\/bank\.acme\/roles\/treasury\/1 \(known keys: alice@bank\.example, bob@bank\.example\)/);
  });

  it('reports health across every seat, not only the scope key', async () => {
    // A roster whose second seat cannot reach its custody backend fails when somebody votes, and
    // /healthz exists to say so before then.
    const ring = keyringFrom(configFile(YAML));
    expect(await ring.healthy()).toBe(true);
  });

  it('carries a windows-cert-store seat through config without any key material', () => {
    // The Runbook F posture: the approver's certificate stays in the store and the file names only a
    // thumbprint. Constructing it must not need Windows -- the agent is only reached when it signs.
    const p = configFile(`
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"]
  scopes:
    - page: "${PAGE}"
      key:  { provider: "local", local: { seed_hex: "${ORG_SEED}" } }
      keys:
        "${ALICE}":
          provider: "windows-cert-store"
          windows: { thumbprint: "9BAE0FE822B270A258395C26436CEFC8BB42E37B", agent_path: "agent/windows-cert-store/bin/Release/net9.0/certen-cert-agent.exe" }
policy: { url: "http://127.0.0.1:9099/decision" }
`);
    const ring = keyringFrom(p);
    const seat = ring.forPage(PAGE, ALICE);
    // The type is not known until the certificate has been read -- it comes from the certificate, not
    // from config, so that the two can never disagree.
    expect(() => seat.signatureType).toThrow(/not known until the certificate has been read/);
  });

  it('refuses a windows seat that names no certificate', () => {
    const p = configFile(`
wallet:
  org_id: test
  accumulate_endpoints: ["https://kermit.accumulatenetwork.io/v3"]
  scopes:
    - page: "${PAGE}"
      key:  { provider: "local", local: { seed_hex: "${ORG_SEED}" } }
      keys:
        "${ALICE}": { provider: "windows-cert-store", windows: { agent_path: "certen-cert-agent.exe" } }
policy: { url: "http://127.0.0.1:9099/decision" }
`);
    expect(() => keyringFrom(p)).toThrow(/requires windows.thumbprint/);
  });
});
