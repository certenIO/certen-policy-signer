/**
 * Operator tool: rotate the Accumulate key-page key. Procedure and mode selection: docs/OPERATIONS.md.
 *
 * Reads the WALLET'S OWN config, so it signs with whatever key posture is deployed — a local seed or a
 * Vault-held key. It never needs the private key material itself.
 *
 *   npx tsx scripts/rotate-key.ts --config deploy/config.pilot.yaml --new-key-hash <64hex> [--mode updateKey]
 *   npx tsx scripts/rotate-key.ts --config <cfg> --new-seed-hex <64hex>     # local: derive the hash for you
 *   npx tsx scripts/rotate-key.ts --config <cfg> --new-vault-key org-accum-v2   # vault: read the new pubkey
 *
 * Modes:
 *   updateKey        (default) atomic single tx; the signing key is replaced. Restart the wallet after.
 *   update           atomic, expressed as a key-page operation.
 *   add-then-remove  zero-downtime: adds the new key, waits for it to be live, then removes the old one.
 *                    Use with --pause-before-remove to switch the wallet over in between.
 *
 * It CONFIRMS the rotation by polling the key page's listed keys — a submitted tx is not a rotated key.
 */
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import nacl from 'tweetnacl';
import { loadConfig } from '../src/config.js';
import { logger } from '../src/logger.js';
import { RawAccumulateClient } from '../src/accumulate/raw-client.js';
import { MapKeyring, buildSignerFromSpec, bookOf } from '../src/signer/keyring.js';
import { VaultTransitSigner } from '../src/signer/vault-transit.js';
import { rotateKey, readPage, RotateMode } from '../src/ops/rotate.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const has = (name: string) => process.argv.includes(`--${name}`);

async function main() {
  const configPath = arg('config');
  if (!configPath) throw new Error('--config <wallet config.yaml> is required');
  const cfg = loadConfig(configPath);
  const acc = new RawAccumulateClient(cfg.wallet.accumulate_endpoints[0], logger);
  const mode = (arg('mode') ?? 'updateKey') as RotateMode;

  // --- the CURRENT signer: build the keyring exactly as the daemon does (single- or multi-scope),
  //     then pick the key that sits on the page we are rotating ---
  const scopes = (cfg.wallet.scopes?.length)
    ? cfg.wallet.scopes.map((s, i) => ({ page: s.page, book: s.book ?? bookOf(s.page), signer: buildSignerFromSpec(s.key, logger, `scope[${i}] ${s.page}`) }))
    : [{ page: cfg.wallet.signer_url!, book: bookOf(cfg.wallet.signer_url!), signer: buildSignerFromSpec(cfg.signer!, logger, cfg.wallet.signer_url!) }];
  const keyring = new MapKeyring(scopes);
  const page = arg('page') ?? scopes[0].page;
  const signer = keyring.forPage(page);

  // --- the NEW key: given as a hash, derived from a new seed, or read from a new Vault key ---
  let newKeyHash = arg('new-key-hash');
  const newSeed = arg('new-seed-hex');
  const newVaultKey = arg('new-vault-key');
  if (!newKeyHash && newSeed) {
    const pub = nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(newSeed.trim(), 'hex'))).publicKey;
    newKeyHash = createHash('sha256').update(pub).digest('hex');
  }
  if (!newKeyHash && newVaultKey) {
    const v = cfg.signer?.vault;
    if (!v?.addr || !v.token) throw new Error('--new-vault-key needs signer.vault.addr/token in the config');
    const pub = await new VaultTransitSigner({ addr: v.addr, keyName: newVaultKey, token: v.token }).publicKey();
    newKeyHash = createHash('sha256').update(pub).digest('hex');
    console.log(`  new Vault key "${newVaultKey}" pubkey hash: ${newKeyHash}`);
  }
  if (!newKeyHash) throw new Error('one of --new-key-hash / --new-seed-hex / --new-vault-key is required');

  const before = await readPage(acc, page);
  const currentHash = createHash('sha256').update(await signer.publicKey()).digest('hex');
  console.log(`\npage:        ${page}`);
  console.log(`version:     ${before.version}`);
  console.log(`keys on page:${before.keyHashes.map((k) => `\n  - ${k}${k === currentHash ? '   <- the key we sign with' : ''}`).join('')}`);
  console.log(`\nmode:        ${mode}`);
  console.log(`rotating:    ${currentHash}\n         ->  ${newKeyHash}\n`);

  // The default mode is the WRONG one for a compromise, so say so at the moment of choosing.
  if (mode === 'updateKey') {
    console.log('note:        updateKey does NOT advance the key page version, so it does not reset nonces');
    console.log('             or invalidate signatures the old key already made. That is fine for a routine');
    console.log('             rotation. If this key may be COMPROMISED, abort and use --mode update.\n');
  }

  if (!has('yes')) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const ans = await rl.question('This changes who can sign for the org. Type "rotate" to proceed: ');
    rl.close();
    if (ans.trim() !== 'rotate') { console.log('aborted'); process.exit(1); }
  }

  const res = await rotateKey({ accumulate: acc, signer, logger }, { page, newKeyHash, mode });

  console.log('\n--- result ---');
  console.log(`submitted:   ${res.submitted.join(', ') || '(none)'}`);
  console.log(`page version:${res.before.version} -> ${res.after.version}`);
  console.log(`keys now:    ${res.after.keyHashes.join(', ')}`);
  if (!res.ok) {
    console.error(`\nROTATION FAILED: ${res.error}`);
    console.error('The old key may STILL be the only valid one. Do not decommission it until the page confirms.');
    process.exit(1);
  }
  console.log('\nROTATION CONFIRMED ON-CHAIN ✅');
  console.log('Next: point the wallet at the new key (signer.local.seed_hex / signer.vault.key_name) and restart it.');
  console.log('It will refuse to boot (SR6) if the new key is not the one on the page — that is your final check.');
}

main().catch((e) => { console.error('FATAL', e.message); process.exit(1); });
