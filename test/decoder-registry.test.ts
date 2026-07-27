/**
 * The intent-decoder seam (src/decode/).
 *
 * These tests are about the CONTRACT an integrator writes against, not about any one payload format:
 * order decides who claims a transaction, declining is safe, throwing cannot stall the queue, and a
 * misconfigured chain fails at boot rather than quietly changing what the policy engine is told.
 */
import { describe, it, expect } from 'vitest';
import { DecoderRegistry, buildRegistry, loadDecoderModules, BUILTIN_DECODERS } from '../src/decode/registry.js';
import { SummaryDecoder } from '../src/decode/types.js';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CTX = { principal: 'acc://org.acme/data' };

/** A decoder that claims every body and reports its own name, so we can see who won. */
const claimer = (name: string): SummaryDecoder => ({
  name,
  decode: () => ({ summary: { action: `claimed-by-${name}` } }),
});

describe('decoder chain order', () => {
  it('first claim wins — an earlier decoder shadows a later one', () => {
    const r = new DecoderRegistry([claimer('first'), claimer('second')]);
    const out = r.decode({ type: 'writeData' }, CTX);
    expect(out.summary.action).toBe('claimed-by-first');
    expect(out.decodedBy).toBe('first');
  });

  it('a decoder that declines passes the transaction along', () => {
    const decliner: SummaryDecoder = { name: 'decliner', decode: () => undefined };
    const out = new DecoderRegistry([decliner, claimer('second')]).decode({ type: 'writeData' }, CTX);
    expect(out.decodedBy).toBe('second');
  });

  it('reports the resolution order including the implicit terminal fallback', () => {
    expect(new DecoderRegistry([claimer('a')]).names()).toEqual(['a', 'fallback']);
  });
});

describe('a transaction is always described', () => {
  it('an empty chain still yields a summary — never nothing', () => {
    const out = new DecoderRegistry([]).decode({ type: 'someFutureBodyType' }, CTX);
    expect(out.decodedBy).toBe('fallback');
    expect(out.summary.action).toBe('someFutureBodyType on acc://org.acme/data');
  });

  it('an unrecognized data write says so, rather than inventing a description', () => {
    const out = buildRegistry(undefined).decode({ type: 'writeData', entry: { data: [] } }, CTX);
    expect(out.summary.action).toContain('Unrecognized');
    expect(out.summary.value).toBeUndefined();
  });
});

describe('a throwing decoder cannot stall the queue', () => {
  const thrower: SummaryDecoder = {
    name: 'thrower',
    decode: () => { throw new Error('malformed payload'); },
  };

  it('is treated as a decline, and the next decoder still runs', () => {
    const out = new DecoderRegistry([thrower, claimer('after')]).decode({ type: 'writeData' }, CTX);
    expect(out.decodedBy).toBe('after');
  });

  it('logs a warning, so a permanently-failing decoder is visible', () => {
    const warnings: Array<Record<string, unknown>> = [];
    const log = { warn: (o: Record<string, unknown>) => void warnings.push(o) };
    new DecoderRegistry([thrower], log).decode({ type: 'writeData' }, CTX);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ decoder: 'thrower', err: 'malformed payload' });
  });
});

describe('buildRegistry configuration', () => {
  it('honors an explicit order over the default one', () => {
    // `write-data` claims every data write, so putting it first must shadow `certen-intent`.
    const r = buildRegistry(['write-data', 'certen-intent']);
    expect(r.names()).toEqual(['write-data', 'certen-intent', 'fallback']);
  });

  it('rejects an unknown decoder name at build time rather than running one short', () => {
    expect(() => buildRegistry(['send-tokens', 'typo-here'])).toThrow(/unknown decoder "typo-here"/);
  });

  it('lists the available names in the error, so the fix is obvious', () => {
    expect(() => buildRegistry(['nope'])).toThrow(/send-tokens/);
  });

  it('puts external decoders ahead of the built-ins by default', () => {
    const mine = claimer('my-format');
    expect(buildRegistry(undefined, [mine]).names()[0]).toBe('my-format');
  });

  it('an external decoder may override a built-in by reusing its name', () => {
    const r = buildRegistry(['send-tokens'], [claimer('send-tokens')]);
    expect(r.decode({ type: 'sendTokens', to: [{ url: 'acc://x.acme/t', amount: '5' }] }, CTX).summary.action)
      .toBe('claimed-by-send-tokens');
  });

  it('ships the documented built-in names', () => {
    expect(Object.keys(BUILTIN_DECODERS).sort()).toEqual(['certen-intent', 'send-tokens', 'write-data']);
  });
});

describe('loading decoders from an external module', () => {
  const dir = mkdtempSync(join(tmpdir(), 'decoder-mod-'));

  it('loads a module that default-exports a decoder', async () => {
    const f = join(dir, 'single.mjs');
    writeFileSync(f, `export default { name: 'from-module', decode: () => ({ summary: { action: 'ok' } }) };`);
    const [d] = await loadDecoderModules([f]);
    expect(d.name).toBe('from-module');
  });

  it('loads a module that default-exports an array of decoders', async () => {
    const f = join(dir, 'many.mjs');
    writeFileSync(f, `export default [
      { name: 'a', decode: () => undefined },
      { name: 'b', decode: () => undefined },
    ];`);
    expect((await loadDecoderModules([f])).map((d) => d.name)).toEqual(['a', 'b']);
  });

  it('loads nothing when none are configured', async () => {
    expect(await loadDecoderModules(undefined)).toEqual([]);
  });

  it('fails loudly on a module that cannot be found', async () => {
    await expect(loadDecoderModules([join(dir, 'missing.mjs')])).rejects.toThrow(/failed to load/);
  });

  it('fails loudly on a module whose export is not a decoder', async () => {
    const f = join(dir, 'bad.mjs');
    writeFileSync(f, `export default { nope: true };`);
    await expect(loadDecoderModules([f])).rejects.toThrow(/must default-export a decoder/);
  });

  it('an external decoder actually decodes once registered', async () => {
    const f = join(dir, 'acme.mjs');
    writeFileSync(f, `export default {
      name: 'acme',
      decode: (body) => body.type === 'writeData' && body.acme
        ? { summary: { action: 'ACME transfer', values: ['10', '20'] }, operationId: 'op-1' }
        : undefined,
    };`);
    const r = buildRegistry(undefined, await loadDecoderModules([f]));
    const out = r.decode({ type: 'writeData', acme: true }, CTX);
    expect(out.decodedBy).toBe('acme');
    expect(out.operationId).toBe('op-1');
    // Every amount reaches the value ceiling, not just the first.
    expect(out.summary.values).toEqual(['10', '20']);
  });
});

describe('built-in send-tokens', () => {
  it('surfaces EVERY output amount, so a ceiling cannot be evaded by splitting outputs', () => {
    const out = buildRegistry(undefined).decode(
      { type: 'sendTokens', to: [{ url: 'acc://a.acme/t', amount: '5' }, { url: 'acc://b.acme/t', amount: '9999' }] },
      CTX,
    );
    expect(out.decodedBy).toBe('send-tokens');
    expect(out.summary.values).toEqual(['5', '9999']);
    expect(out.summary.value).toBe('5');          // representative = output 0, for display
    expect(out.summary.action).toContain('more output');
  });
});
