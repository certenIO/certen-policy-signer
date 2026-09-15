/**
 * AWS KMS integration test, self-contained: starts LocalStack (kms only) in Docker, runs
 * test/cloud-kms-aws.test.ts against it, removes the container. `npm run test:kms`.
 *
 * The test creates its own keys inside LocalStack KMS. The AWS credentials below are LocalStack's
 * documented placeholder values, not secrets. Host port 15466 (contract §1.2: ports from 15000 upward).
 */
import { execFileSync, spawnSync } from 'node:child_process';

const NAME = 'certen-signer-kms-it';
const IMAGE = process.env.LOCALSTACK_IMAGE ?? 'localstack/localstack:4.4.0';
const PORT = process.env.KMS_IT_PORT ?? '15466';
const ENDPOINT = `http://127.0.0.1:${PORT}`;
const sh = (args) => execFileSync('docker', args, { encoding: 'utf8', stdio: 'pipe' });
const rm = () => { try { sh(['rm', '-f', NAME]); } catch {} };

rm();
console.log(`[kms-it] starting ${IMAGE} (kms) on ${ENDPOINT}...`);
sh(['run', '-d', '--name', NAME, '-p', `127.0.0.1:${PORT}:4566`, '-e', 'SERVICES=kms', IMAGE]);

try {
  // Heartbeat keeps the event loop alive while a probe hangs on a port nobody listens on yet (see vault-it.mjs).
  let ready = false;
  const heartbeat = setInterval(() => {}, 250);
  try {
    for (let i = 0; i < 120 && !ready; i++) {
      ready = await fetch(`${ENDPOINT}/_localstack/health`, { signal: AbortSignal.timeout(1000) })
        .then(async (r) => r.ok && ['available', 'running'].includes((await r.json())?.services?.kms))
        .catch(() => false);
      if (!ready) await new Promise((r) => setTimeout(r, 500));
    }
  } finally {
    clearInterval(heartbeat);
  }
  if (!ready) throw new Error(`LocalStack KMS never became available on ${ENDPOINT}`);
  console.log('[kms-it] LocalStack KMS ready — running tests\n');

  const res = spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', 'test/cloud-kms-aws.test.ts'], {
    stdio: 'inherit',
    env: { ...process.env, KMS_ENDPOINT: ENDPOINT, AWS_REGION: 'us-east-1', AWS_ACCESS_KEY_ID: 'test', AWS_SECRET_ACCESS_KEY: 'test' },
  });
  process.exitCode = res.status ?? 1;
} catch (e) {
  try { console.error(sh(['logs', '--tail', '40', NAME])); } catch {}
  throw e;
} finally {
  rm();
  console.log('[kms-it] LocalStack removed');
}
