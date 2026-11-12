/**
 * DAX-4-A10 (MOD-03): the signer's copy of the shared core is BYTE FOR BYTE the canonical one, and a re-sync is one command.
 *
 * Three references, each catching a different failure:
 *   - src/core/SOURCE.json (commit + sha256 of every file) against the copies: an edited copy fails on ANY machine, with or
 *     without the canonical repository (one flipped byte changes the hash);
 *   - scripts/core-source.mjs (the one constant) against SOURCE.json: moving the constant without re-syncing fails;
 *   - the canonical repository (`git show <commit>:packages/core/src/<file>` in a transaction-controls worktree, CERTEN_TCL_REPO
 *     or ../transaction-controls) against the copies AND the manifest: where it exists the comparison is the bytes themselves.
 * Where no canonical repository is reachable only the first two run (the same pattern as the Console's contract-drift test);
 * CLAIMS says so.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_COPY_DIR, CORE_FILES, CORE_MANIFEST, CORE_SOURCE_COMMIT, CORE_SOURCE_DIR } from '../scripts/core-source.mjs';
import { REPO, canonicalBytes, sha256Hex, sourceRepo } from '../scripts/sync-core.mjs';

const manifestPath = join(REPO, CORE_MANIFEST);
const manifest = (): { commit: string; dir: string; files: Record<string, string> } => JSON.parse(readFileSync(manifestPath, 'utf8'));
const repo = sourceRepo();

describe('the copied core (MOD-03, DAX-4-A10)', () => {
  it('has the manifest and every copied file', () => {
    expect(existsSync(manifestPath)).toBe(true);
    for (const f of CORE_FILES) expect(existsSync(join(REPO, CORE_COPY_DIR, f)), f).toBe(true);
  });

  it('copies exactly the listed files and nothing else (an extra file is an unreviewed fork)', () => {
    const present = readdirSync(join(REPO, CORE_COPY_DIR)).filter((n) => n !== 'SOURCE.json').sort();
    expect(present).toEqual([...CORE_FILES].sort());
  });

  it('names the same commit and directory as the one constant', () => {
    const m = manifest();
    expect(m.commit).toBe(CORE_SOURCE_COMMIT);
    expect(m.dir).toBe(CORE_SOURCE_DIR);
    expect(Object.keys(m.files).sort()).toEqual([...CORE_FILES].sort());
  });

  it('keeps every copied file byte for byte equal to the manifest hash (one flipped byte fails here)', () => {
    const m = manifest();
    for (const f of CORE_FILES) {
      const have = readFileSync(join(REPO, CORE_COPY_DIR, f));
      expect(sha256Hex(have), `${f} differs from the canonical file recorded at ${m.commit}`).toBe(m.files[f]);
    }
  });

  it.runIf(repo !== undefined)('is byte for byte identical to the canonical file in transaction-controls at the constant commit', () => {
    for (const f of CORE_FILES) {
      const want = canonicalBytes(repo!, f);
      const have = readFileSync(join(REPO, CORE_COPY_DIR, f));
      expect(have.equals(want), `${f} differs from ${CORE_SOURCE_COMMIT}:${CORE_SOURCE_DIR}/${f}`).toBe(true);
      expect(manifest().files[f], `${f} manifest hash`).toBe(sha256Hex(want));
    }
  });

  it.runIf(repo !== undefined)('passes its own sync --check (the script is what is tested, so it cannot rot into a no-op)', () => {
    const out = execFileSync(process.execPath, [join(REPO, 'scripts', 'sync-core.mjs'), '--check'], { cwd: REPO, encoding: 'utf8', env: { ...process.env, CERTEN_TCL_REPO: repo } });
    expect(out).toContain('identical SOURCE.json');
    expect(out).not.toMatch(/drifted|missing/);
  });
});
