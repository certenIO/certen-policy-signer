/**
 * Build the deployable bundle.
 *
 * A script rather than an inline esbuild command line for one reason: the output needs a `#!` banner.
 * `package.json.bin` points at this file, and npm's launcher reads the shebang to decide what runs it —
 * without one, the Windows shim invokes the .cjs by file association (silently nothing) and the POSIX
 * symlink is exec'd as a shell script. Quoting `#!/usr/bin/env node` identically in cmd and sh is not
 * worth the trouble.
 *
 * pino and pino-pretty stay external: they resolve transports by path at runtime, which a bundle breaks.
 */
import { build } from 'esbuild';
import { existsSync } from 'node:fs';

const ENTRY = 'src/index.ts';
const OUTFILE = 'dist/signer.cjs';

// `prepare` runs during `npm ci`, and the Dockerfile installs dependencies in a layer that deliberately
// holds only package.json and the postinstall patch — src/ arrives later, for caching. A dependency-only
// install has nothing to bundle, so skip rather than fail. The Dockerfile still calls this explicitly
// once src/ is present, and that call cannot be skipped this way.
if (!existsSync(ENTRY)) {
  console.log(`no ${ENTRY} — dependency-only install, nothing to bundle`);
  process.exit(0);
}

await build({
  entryPoints: [ENTRY],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  outfile: OUTFILE,
  external: ['pino', 'pino-pretty'],
  banner: { js: '#!/usr/bin/env node' },
});

console.log(`built ${OUTFILE}`);
