/**
 * Vault-Transit integration test, self-contained: boots a dev Vault, creates the ed25519 transit key,
 * runs test/vault-transit.test.ts against it, tears it down. `npm run test:vault`.
 *
 * This is the PRODUCTION key posture (the key never leaves Vault), so it must be runnable on demand —
 * a skipped test proves nothing.
 */
import { execFileSync, spawnSync } from 'node:child_process';

const NAME = 'certen-vault-it';
const ADDR = 'http://127.0.0.1:8200';
const sh = (args, opts = {}) => execFileSync('docker', args, { encoding: 'utf8', stdio: 'pipe', ...opts });

const rm = () => { try { sh(['rm', '-f', NAME]); } catch {} };

rm();
console.log('[vault-it] starting dev Vault...');
sh(['run', '-d', '--name', NAME, '-p', '8200:8200',
  '-e', 'VAULT_DEV_ROOT_TOKEN_ID=root', '-e', 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200',
  '--cap-add=IPC_LOCK', 'hashicorp/vault', 'server', '-dev']);

try {
  // Probe from the HOST, not inside the container: Vault answers `vault status` internally before
  // Docker's port mapping is usable, and the tests connect over the mapped port.
  let ready = false;
  for (let i = 0; i < 60 && !ready; i++) {
    ready = await fetch(`${ADDR}/v1/sys/health`).then((r) => r.status < 500).catch(() => false);
    if (!ready) await new Promise((r) => setTimeout(r, 500));
  }
  if (!ready) throw new Error(`dev Vault never became reachable on ${ADDR}`);

  sh(['exec', '-e', `VAULT_ADDR=http://127.0.0.1:8200`, '-e', 'VAULT_TOKEN=root', NAME,
    'sh', '-c', 'vault secrets enable transit && vault write -f transit/keys/wallet-test type=ed25519']);
  console.log('[vault-it] transit ed25519 key ready — running tests\n');

  // Invoke vitest directly rather than through npx (npm's spawn is EPERM-blocked in some environments).
  const res = spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', 'test/vault-transit.test.ts'], {
    stdio: 'inherit',
    env: { ...process.env, VAULT_ADDR: ADDR, VAULT_TOKEN: 'root', VAULT_KEY: 'wallet-test' },
  });
  process.exitCode = res.status ?? 1;
} finally {
  rm();
  console.log('\n[vault-it] dev Vault removed');
}
