/**
 * The command-line surface.
 *
 * `--help` is the first thing a new install is asked for, and it has to answer without a config, a key
 * or a network. The end-to-end cases spawn the real built bundle so the published artifact — not just
 * the source — is what gets checked.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { parseArgs, helpText, BIN, VERSION } from '../src/cli.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE = join(ROOT, 'dist', 'signer.cjs');

describe('argument parsing', () => {
  it('treats no arguments as a run against the default config path', () => {
    delete process.env.CONFIG_PATH;
    expect(parseArgs([])).toEqual({ mode: 'run', configPath: './config.yaml' });
  });

  it('takes the config path positionally', () => {
    expect(parseArgs(['/etc/signer/config.yaml'])).toEqual({ mode: 'run', configPath: '/etc/signer/config.yaml' });
  });

  it('falls back to CONFIG_PATH, and the argument wins over it', () => {
    process.env.CONFIG_PATH = '/from/env.yaml';
    try {
      expect(parseArgs([])).toEqual({ mode: 'run', configPath: '/from/env.yaml' });
      expect(parseArgs(['/from/argv.yaml'])).toEqual({ mode: 'run', configPath: '/from/argv.yaml' });
    } finally {
      delete process.env.CONFIG_PATH;
    }
  });

  it.each(['--help', '-h'])('%s asks for help', (flag) => {
    expect(parseArgs([flag])).toEqual({ mode: 'help' });
  });

  it.each(['--version', '-v'])('%s asks for the version', (flag) => {
    expect(parseArgs([flag])).toEqual({ mode: 'version' });
  });

  it('answers help even when a config path is also given', () => {
    expect(parseArgs(['config.yaml', '--help'])).toEqual({ mode: 'help' });
  });

  // Silently ignoring a flag lets an operator believe they configured something that never took effect.
  it('rejects an unknown option rather than ignoring it', () => {
    expect(parseArgs(['--dry-run'])).toEqual({ mode: 'error', message: 'unknown option: --dry-run' });
  });

  it('rejects a second positional argument', () => {
    const r = parseArgs(['a.yaml', 'b.yaml']);
    expect(r.mode).toBe('error');
  });
});

describe('help text', () => {
  const text = helpText();

  it('names the binary that npm actually installs', () => {
    expect(BIN).toBe('certen-external-policy-signer');
    expect(text).toContain(BIN);
  });

  it('reports the package version', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
    expect(text).toContain(VERSION);
  });

  it('documents the config resolution order that parseArgs implements', () => {
    expect(text).toContain('CONFIG_PATH');
    expect(text).toContain('./config.yaml');
  });

  it('lists the admin routes and says they are disabled without an api key', () => {
    for (const route of ['/healthz', '/metrics', '/v1/pending', '/v1/requests', '/v1/admin/pause']) {
      expect(text).toContain(route);
    }
    expect(text).toMatch(/admin\.api_key/);
  });

  it('points at docs that exist', () => {
    for (const doc of text.match(/docs\/[A-Z]+\.md/g) ?? []) {
      expect(existsSync(join(ROOT, doc)), `${doc} referenced in --help but missing`).toBe(true);
    }
  });
});

// These are the cases that actually failed before: the bundle treated `--help` as a filename.
describe('the built bundle', () => {
  const run = (args: string[]) =>
    execFileSync(process.execPath, [BUNDLE, ...args], { encoding: 'utf8', cwd: ROOT, timeout: 20_000 });

  // Built here rather than skipped when absent: "the bundle mishandles --help" is exactly the class of
  // bug this file exists to catch, so it must not quietly go unchecked on a machine that hasn't built.
  // It runs the real build script, so what is tested is what ships.
  beforeAll(() => {
    execFileSync(process.execPath, [join(ROOT, 'scripts', 'build.mjs')], { cwd: ROOT, timeout: 120_000 });
  }, 120_000);

  // npm's launcher reads the shebang to decide what interprets the bin. Without one the Windows shim
  // invokes the .cjs by file association and does nothing at all, which is how this was found.
  it('starts with a node shebang so the installed bin is executable', () => {
    expect(readFileSync(BUNDLE, 'utf8').split('\n', 1)[0]).toBe('#!/usr/bin/env node');
  });

  it('prints help to stdout and exits 0', () => {
    const out = run(['--help']);
    expect(out).toContain('USAGE');
    expect(out).toContain(BIN);
    // Help is plain text, not a log line.
    expect(out.trimStart().startsWith('{')).toBe(false);
  });

  it('prints the version and exits 0', () => {
    expect(run(['--version']).trim()).toBe(`${BIN} ${VERSION}`);
  });

  it('exits 2 with usage guidance on an unknown option', () => {
    let code: number | undefined;
    let stderr = '';
    try {
      run(['--nope']);
    } catch (e) {
      const err = e as { status?: number; stderr?: string };
      code = err.status;
      stderr = err.stderr ?? '';
    }
    expect(code).toBe(2);
    expect(stderr).toContain('unknown option: --nope');
    expect(stderr).toContain('--help');
  });
});
