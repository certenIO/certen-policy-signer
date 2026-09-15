/**
 * PKCS#11 integration test, self-contained: builds test/docker/softhsm (SoftHSM2 + the explicitly built
 * pkcs11js addon), runs the suite in a throwaway container, removes it. `npm run test:pkcs11`.
 *
 * The token, its PINs and its keys are created inside the container and die with it. Nothing about them
 * reaches this process except the test output.
 */
import { spawnSync } from 'node:child_process';

const IMAGE = 'certen-signer-softhsm-it:local';
const NAME = 'certen-signer-softhsm-it';
const docker = (args) => spawnSync('docker', args, { stdio: 'inherit' });

spawnSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' });
console.log('[pkcs11-it] building the SoftHSM2 test image...');
const built = docker(['build', '-f', 'test/docker/softhsm/Dockerfile', '-t', IMAGE, '.']);
if (built.status !== 0) {
  process.exitCode = built.status ?? 1;
} else {
  console.log('[pkcs11-it] running the pkcs11 suite against SoftHSM2\n');
  const res = docker(['run', '--rm', '--name', NAME, '--network', 'none', IMAGE]);
  process.exitCode = res.status ?? 1;
  spawnSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' });
}
