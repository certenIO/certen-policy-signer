#!/usr/bin/env node
/**
 * Copy the shared core into this repository, byte for byte (MOD-03).
 *
 *   node scripts/sync-core.mjs            copy every file at CORE_SOURCE_COMMIT and rewrite src/core/SOURCE.json
 *   node scripts/sync-core.mjs --check    verify the copy, the manifest and the commit; write nothing; exit 1 on a difference
 *
 * The source is read with `git show <commit>:<dir>/<file>` from a transaction-controls checkout or worktree (it is never
 * written to): CERTEN_TCL_REPO, else ../transaction-controls next to this repository. The copy carries no added header:
 * a banner would be an edit, and an edited file cannot be compared byte for byte. Provenance is src/core/SOURCE.json.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CORE_COPY_DIR, CORE_FILES, CORE_MANIFEST, CORE_SOURCE_COMMIT, CORE_SOURCE_DIR } from './core-source.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(HERE, '..');

export const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

/** The transaction-controls checkout to read from, or undefined when none is reachable. */
export function sourceRepo() {
  const candidates = [process.env.CERTEN_TCL_REPO, resolve(REPO, '..', 'transaction-controls')].filter(Boolean).map((p) => resolve(p));
  for (const c of candidates) {
    if (!existsSync(join(c, '.git')) && !existsSync(join(c, 'packages'))) continue;
    try {
      execFileSync('git', ['-C', c, 'cat-file', '-e', `${CORE_SOURCE_COMMIT}^{commit}`], { stdio: 'ignore' });
      return c;
    } catch {
      /* this checkout does not hold the commit */
    }
  }
  return undefined;
}

/** The canonical bytes of one file at the constant commit. */
export function canonicalBytes(repo, file) {
  return execFileSync('git', ['-C', repo, 'show', `${CORE_SOURCE_COMMIT}:${CORE_SOURCE_DIR}/${file}`], { maxBuffer: 16 * 1024 * 1024 });
}

export function manifestFor(files) {
  return `${JSON.stringify({ commit: CORE_SOURCE_COMMIT, dir: CORE_SOURCE_DIR, files }, null, 2)}\n`;
}

function main() {
  const check = process.argv.includes('--check');
  const repo = sourceRepo();
  if (repo === undefined) {
    console.error(`no transaction-controls checkout holding ${CORE_SOURCE_COMMIT} was found; set CERTEN_TCL_REPO to a worktree of it`);
    process.exit(2);
  }
  const hashes = {};
  let bad = 0;
  mkdirSync(join(REPO, CORE_COPY_DIR), { recursive: true });
  for (const f of CORE_FILES) {
    const want = canonicalBytes(repo, f);
    hashes[f] = sha256Hex(want);
    const dst = join(REPO, CORE_COPY_DIR, f);
    const have = existsSync(dst) ? readFileSync(dst) : null;
    if (have !== null && want.equals(have)) {
      console.log(`identical ${f}`);
      continue;
    }
    if (check) {
      console.log(`${have === null ? 'missing  ' : 'drifted  '} ${f}`);
      bad++;
      continue;
    }
    writeFileSync(dst, want);
    console.log(`${have === null ? 'created  ' : 'updated  '} ${f} (${want.length} bytes)`);
  }
  const manifest = manifestFor(hashes);
  const manifestPath = join(REPO, CORE_MANIFEST);
  const haveManifest = existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8') : null;
  if (haveManifest === manifest) console.log('identical SOURCE.json');
  else if (check) {
    console.log('drifted   SOURCE.json');
    bad++;
  } else {
    writeFileSync(manifestPath, manifest);
    console.log('written   SOURCE.json');
  }
  if (bad > 0) {
    console.error('The copied core has DRIFTED from transaction-controls (or the constant moved). Run `node scripts/sync-core.mjs` and read the diff.');
    process.exit(1);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
