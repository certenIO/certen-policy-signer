/**
 * The shipped examples must actually work.
 *
 * examples/ is the first thing an integrator copies, and a broken example costs more trust than a missing
 * one. These tests load the real files from disk — not a copy — so the published examples cannot rot
 * silently behind a refactor of the seams they demonstrate.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { spawn, ChildProcess } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { buildRegistry, loadDecoderModules } from '../src/decode/registry.js';
import { HttpPolicyClient, DEFAULT_SIGNATURE_HEADER } from '../src/policy/policy.js';
import { loadConfig } from '../src/config.js';
import { PolicyRequest } from '../src/types.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DECODER = join(ROOT, 'examples', 'custom-decoder.mjs');
const ENGINE = join(ROOT, 'examples', 'policy-engine.mjs');

const hexJson = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
const poBody = (lines: Array<{ amount: string; vendor: string }>, extra: Record<string, unknown> = {}) => ({
  type: 'writeData',
  entry: { data: [hexJson({ kind: 'ACME_PURCHASE_ORDER', poNumber: 'PO-1043', currency: 'USDC', lines, ...extra })] },
});
const CTX = { principal: 'acc://acme.acme/orders' };

describe('the shipped example configs are valid', () => {
  // A config file that does not parse is a broken front door: it is the first thing anyone copies.
  for (const f of ['config.example.yaml', 'config.multi-scope.example.yaml']) {
    it(`${f} loads through the real config loader`, () => {
      expect(() => loadConfig(join(ROOT, f))).not.toThrow();
    });
  }

  it('config.example.yaml documents decoder options that the loader actually accepts', () => {
    const cfg = loadConfig(join(ROOT, 'config.example.yaml'));
    expect(cfg.resolver).toBeDefined();
    // Commented out in the file, so the built-in chain applies — which is what the comment claims.
    expect(cfg.resolver.decoders).toBeUndefined();
  });
});

describe('examples/custom-decoder.mjs', () => {
  it('loads through the documented resolver.decoder_modules path', async () => {
    const [d] = await loadDecoderModules([DECODER]);
    expect(d.name).toBe('acme-purchase-order');
  });

  it('runs ahead of the built-ins, as the docs promise', async () => {
    const r = buildRegistry(undefined, await loadDecoderModules([DECODER]));
    expect(r.names()[0]).toBe('acme-purchase-order');
  });

  it('decodes its own payload into a summary the policy engine can gate on', async () => {
    const r = buildRegistry(undefined, await loadDecoderModules([DECODER]));
    const out = r.decode(poBody([{ amount: '25000', vendor: 'Northwind' }]) as any, CTX);
    expect(out.decodedBy).toBe('acme-purchase-order');
    expect(out.operationId).toBe('PO-1043');
    expect(out.summary.action).toContain('PO-1043');
    expect(out.summary.target).toBe('Northwind');
  });

  it('surfaces EVERY line amount — the rule the file tells integrators to follow', async () => {
    const r = buildRegistry(undefined, await loadDecoderModules([DECODER]));
    const out = r.decode(
      poBody([{ amount: '25000', vendor: 'Northwind' }, { amount: '500', vendor: 'Contoso' }]) as any,
      CTX,
    );
    expect(out.summary.values).toEqual(['25000', '500']);
    expect(out.summary.value).toBe('25000');
    expect(out.summary.action).toContain('more line');
  });

  it('declines a payload that is not its own, rather than guessing', async () => {
    const r = buildRegistry(undefined, await loadDecoderModules([DECODER]));
    const other = { type: 'writeData', entry: { data: [hexJson({ kind: 'SOMETHING_ELSE' })] } };
    expect(r.decode(other as any, CTX).decodedBy).not.toBe('acme-purchase-order');
  });

  it('declines its own payload when it is too malformed to describe honestly', async () => {
    const r = buildRegistry(undefined, await loadDecoderModules([DECODER]));
    expect(r.decode(poBody([]) as any, CTX).decodedBy).not.toBe('acme-purchase-order');
  });

  it('declines unparseable entry bytes instead of throwing', async () => {
    const r = buildRegistry(undefined, await loadDecoderModules([DECODER]));
    const garbage = { type: 'writeData', entry: { data: ['zzzz'] } };
    expect(() => r.decode(garbage as any, CTX)).not.toThrow();
  });
});

describe('examples/policy-engine.mjs', () => {
  const kids: ChildProcess[] = [];
  afterAll(() => kids.forEach((k) => { try { k.kill('SIGKILL'); } catch { /* already gone */ } }));

  /** Boot the real example engine on an ephemeral port and wait for it to listen. */
  async function start(env: Record<string, string>): Promise<string> {
    const port = 19000 + Math.floor(kids.length) + Number(process.pid % 500);
    const child = spawn(process.execPath, [ENGINE], {
      env: { ...process.env, ...env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    kids.push(child);
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('example engine did not start')), 10_000);
      child.stdout!.on('data', (b: Buffer) => {
        if (b.toString().includes('listening on')) { clearTimeout(t); resolve(); }
      });
      child.on('error', reject);
    });
    return `http://127.0.0.1:${port}/decision`;
  }

  const REQ = (values: string[]): PolicyRequest => ({
    requestId: 'r-' + values.join('-'), txHash: 'ab'.repeat(32), account: 'acc://acme.acme/orders',
    actionSummary: 'Purchase order PO-1043', value: values[0], values,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });

  it('approves and denies by a real rule, so the gate is demonstrably live', async () => {
    const url = await start({ POLICY_MODE: 'parity' });
    const client = new HttpPolicyClient({ url });
    expect((await client.decide(REQ(['4000']))).decision).toBe('approve');
    expect((await client.decide(REQ(['4001']))).decision).toBe('deny');
  });

  it('gates on EVERY amount — one odd value denies the whole transaction', async () => {
    const url = await start({ POLICY_MODE: 'parity' });
    const d = await new HttpPolicyClient({ url }).decide(REQ(['4000', '4002', '4001']));
    expect(d.decision).toBe('deny');
  });

  it('answers "pending" while a challenge is open, then approves — keyed on txHash across polls', async () => {
    const url = await start({ POLICY_MODE: 'pending', POLICY_PENDING_POLLS: '3' });
    const client = new HttpPolicyClient({ url });
    // The same tx polled repeatedly: the engine must remember it, not reopen a challenge each time.
    expect((await client.decide(REQ(['10']))).decision).toBe('pending');
    expect((await client.decide(REQ(['10']))).decision).toBe('pending');
    expect((await client.decide(REQ(['10']))).decision).toBe('approve');
  });

  it('an outage never becomes an approval — the signer fails closed', async () => {
    const url = await start({ POLICY_MODE: 'fail' });
    await expect(new HttpPolicyClient({ url }).decide(REQ(['10']))).rejects.toThrow(/HTTP 500/);
  });

  it('signs and verifies the channel with the signer default headers', async () => {
    const SECRET = 'shared-secret';
    const url = await start({ POLICY_MODE: 'approve', POLICY_HMAC_SECRET: SECRET });
    const d = await new HttpPolicyClient({ url, hmacSecret: SECRET }).decide(REQ(['10']));
    expect(d.decision).toBe('approve');
  });

  it('rejects a request signed with the wrong secret — 401, which fails closed', async () => {
    const url = await start({ POLICY_MODE: 'approve', POLICY_HMAC_SECRET: 'the-real-secret' });
    await expect(new HttpPolicyClient({ url, hmacSecret: 'wrong-secret' }).decide(REQ(['10'])))
      .rejects.toThrow(/HTTP 401/);
  });

  it('rejects a stale signature, bounding replay', async () => {
    const SECRET = 'shared-secret';
    const url = await start({ POLICY_MODE: 'approve', POLICY_HMAC_SECRET: SECRET });
    const body = JSON.stringify(REQ(['10']));
    const oldTs = String(Date.now() - 10 * 60 * 1000);   // outside the engine's 5-minute window
    const mac = createHmac('sha256', SECRET).update(`${oldTs}.${body}`).digest('hex');
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', [DEFAULT_SIGNATURE_HEADER]: `t=${oldTs},v1=${mac}` },
      body,
    });
    expect(res.status).toBe(401);
  });
});
