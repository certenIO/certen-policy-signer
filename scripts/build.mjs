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
import { existsSync } from 'node:fs';

const ENTRY = 'src/index.ts';
const OUTFILE = 'dist/signer.cjs';

// This runs two ways, and they want opposite failure behaviour.
//
// As the `prepare` lifecycle hook it fires during any install, including ones where building is neither
// possible nor wanted: the Dockerfile's dependency layer holds no src/ yet (kept that way for caching),
// and `npm ci --omit=dev` has no esbuild because esbuild is a devDependency. Neither is an error — a
// production install has nothing to bundle — so skip.
//
// Invoked directly as `npm run build`, the same conditions ARE errors: someone asked for a bundle and
// must not be told it succeeded.
//
// The caller says which it is. `npm_lifecycle_event` cannot: `prepare` shells out to `npm run build`,
// so by the time this file runs the variable reads "build" either way.
const viaPrepare = process.argv.includes('--if-possible');

function unavailable(why) {
  if (viaPrepare) {
    console.log(`skipping bundle: ${why}`);
    process.exit(0);
  }
  console.error(`cannot build: ${why}`);
  process.exit(1);
}

if (!existsSync(ENTRY)) unavailable(`no ${ENTRY} in ${process.cwd()}`);

let build;
try {
  ({ build } = await import('esbuild'));
} catch {
  unavailable("esbuild is not installed (it is a devDependency; a production install has none)");
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
