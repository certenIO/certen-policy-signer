/**
 * Phase 6c/6d — live Kermit verification of the certen-sdk CLI, MCP and SDK sign paths.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-gw-live.ts [scenario...]
 *
 * Lives here so the preimage can be recomputed with THIS repo's independent implementation
 * (src/accumulate/signing.ts) rather than trusting any of the three surfaces under test.
 * Fixtures come from $PHASE0_STATE, minted by certen-gw-fixtures.ts / certen-gw-inbox-fixtures.ts.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { buildPreimage } from '../../src/accumulate/signing.js';

const REPO = process.env.CERTEN_SDK_REPO ?? 'C:/Accumulate_Stuff/certen/certen-sdk';
const CLI = `${REPO}/packages/cli/dist/index.js`;
const MCP = `${REPO}/packages/mcp/dist/index.js`;
const GW = 'https://gateway.kompendium.co';
const KERMIT = 'https://kermit.accumulatenetwork.io/v3';

const STATE_PATH = process.env.PHASE0_STATE ?? 'phase0-state.json';
const API_KEY = JSON.parse(readFileSync(join(homedir(), '.certen', 'config.json'), 'utf8')).api_key;
const state: any = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
const saveState = () => writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));

const B = {
  adi: state.identity.adi_url as string,
  page: state.identity.key_page_url as string,
  pub: state.bKey.publicKeyHex as string,
  seed: state.bKey.seedHex as string,
};
const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(B.seed, 'hex')));
const sign = (hex: string) =>
  Buffer.from(nacl.sign.detached(new Uint8Array(Buffer.from(hex, 'hex')), kp.secretKey)).toString('hex');

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const line = (s = '') => console.log(s);

function takeFixture(kind: 'tx' | 'inbox' = 'tx') {
  const list = kind === 'tx' ? state.fixtures : state.inboxFixtures;
  const fx = list.find((f: any) => !f.used);
  if (!fx) throw new Error(`no unused ${kind} fixture left`);
  fx.used = true;
  saveState();
  return fx;
}

// ---- surfaces -----------------------------------------------------------------------------

function certen(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, CERTEN_API_KEY: API_KEY, CERTEN_API_URL: GW },
  });
  return { code: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** Drive the real MCP server over stdio. */
async function mcp(calls: Array<{ name: string; arguments: Record<string, unknown> }>) {
  const child = spawn(process.execPath, [MCP], {
    env: { ...process.env, CERTEN_API_KEY: API_KEY, CERTEN_API_URL: GW, CERTEN_MCP_ALLOW_WRITES: '1' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let buf = '';
  const pending = new Map<number, (m: any) => void>();
  child.stdout.on('data', (d) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const raw = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!raw) continue;
      const msg = JSON.parse(raw);
      const resolve = pending.get(msg.id);
      if (resolve) { pending.delete(msg.id); resolve(msg); }
    }
  });
  let id = 0;
  const call = (method: string, params: unknown) => new Promise<any>((resolve) => {
    id += 1;
    pending.set(id, resolve);
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  await call('initialize', {
    protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'live', version: '0' },
  });
  const out: any[] = [];
  for (const c of calls) out.push(await call('tools/call', c));
  child.stdin.end();
  child.kill();
  return out;
}

const mcpJson = (res: any) => JSON.parse(res.result.content[0].text);

async function gw(method: string, path: string, body?: unknown) {
  const res = await fetch(`${GW}${path}`, {
    method,
    headers: { 'X-API-Key': API_KEY, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: any; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

async function txState(hash: string, principal: string) {
  const res = await fetch(KERMIT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { scope: `acc://${hash}@${principal}` } }),
  });
  const j: any = await res.json();
  const code = String(j?.result?.status?.code ?? j?.result?.status ?? '');
  if (/delivered/i.test(code)) return 'delivered';
  if (/expired/i.test(code)) return 'expired';
  if (/fail|error|reject/i.test(code)) return 'rejected';
  return code || 'pending';
}

async function waitFor(hash: string, principal: string, want: string, tries = 40) {
  for (let i = 0; i < tries; i++) {
    const st = await txState(hash, principal);
    if (['delivered', 'rejected', 'expired'].includes(st)) {
      line(`    tx ${hash.slice(0, 12)} -> ${st}${st === want ? '' : ` (wanted ${want})`}`);
      return st;
    }
    await sleep(8000);
  }
  line(`    tx ${hash.slice(0, 12)} -> still pending`);
  return 'pending';
}

/** Independent preimage: SHA256( SHA256(encode(sig metadata)) || txHash ). */
function localPreimage(o: { signer: string; version: number; ts: number; txHash: string; vote?: 'approve' | 'reject' | 'abstain' }) {
  return Buffer.from(buildPreimage(new Uint8Array(Buffer.from(o.txHash, 'hex')), {
    publicKey: new Uint8Array(Buffer.from(B.pub, 'hex')),
    signerUrl: o.signer,
    signerVersion: o.version,
    timestamp: o.ts,
    vote: o.vote ?? 'approve',
  }).dataForSignature).toString('hex');
}

// ---- scenarios ----------------------------------------------------------------------------

const results: Array<{ n: string; name: string; pass: boolean; detail: string }> = [];
const record = (n: string, name: string, pass: boolean, detail: string) => {
  results.push({ n, name, pass, detail });
  line(`  ${pass ? 'PASS' : 'FAIL'} — ${detail}`);
};

function cliSubmit(requestId: string, dataForSignature: string) {
  const signature = sign(dataForSignature);
  const r = certen(['--json', 'pending', 'submit', requestId, '--signature', signature, '--public-key', B.pub]);
  return { r, signature };
}

async function scenario1() {
  line('\n[1] CLI, inbox UUID, registered ADI');
  const fx = takeFixture('inbox');
  const inbox = await gw('GET', `/v1/pending?identity=${encodeURIComponent(B.adi)}&limit=50`);
  const row = (inbox.body.actions ?? []).find((a: any) => a.tx_hash === fx.txHash);
  if (!row) return record('1', 'CLI inbox UUID', false, `no inbox row for ${fx.txHash}`);
  line(`    inbox id ${row.id} for tx ${fx.txHash}`);
  const r = certen(['--json', 'pending', 'sign', row.id]);
  line(`    sign exit=${r.code} ${r.stdout.trim().slice(0, 260)}`);
  if (r.code !== 0) return record('1', 'CLI inbox UUID', false, `sign exited ${r.code}: ${r.stderr.slice(0, 200)}`);
  const data = JSON.parse(r.stdout.trim()).data;
  const { r: sub } = cliSubmit(data.sign_request_id, data.signing_data.data_for_signature);
  line(`    submit exit=${sub.code} ${sub.stdout.trim().slice(0, 200)}`);
  const st = await waitFor(fx.txHash, fx.principal, 'delivered');
  record('1', 'CLI inbox UUID', r.code === 0 && sub.code === 0 && st === 'delivered',
    `sign exit ${r.code}, submit exit ${sub.code}, tx ${st}`);
}

async function scenarioHash(n: string, label: string, targetOf: (fx: any) => string) {
  line(`\n[${n}] ${label}`);
  const fx = takeFixture('tx');
  const target = targetOf(fx);
  line(`    target ${target}`);
  const r = certen(['--json', 'pending', 'sign', target,
    '--identity', B.adi, '--signer-url', B.page, '--public-key', B.pub]);
  line(`    sign exit=${r.code} ${r.stdout.trim().slice(0, 260)}`);
  if (r.code !== 0) return record(n, label, false, `sign exited ${r.code}: ${r.stderr.slice(0, 240)}`);
  const data = JSON.parse(r.stdout.trim()).data;
  const { r: sub } = cliSubmit(data.sign_request_id, data.signing_data.data_for_signature);
  line(`    submit exit=${sub.code} ${sub.stdout.trim().slice(0, 200)}`);
  const st = await waitFor(fx.txHash, fx.principal, 'delivered');
  record(n, label, sub.code === 0 && st === 'delivered',
    `hash sent as ${data.signing_data.transaction_hash}, tx ${st}`);
}

async function scenario4() {
  line('\n[4] CLI, hash with no --public-key');
  const hash = 'a'.repeat(64);
  const t0 = Date.now();
  const r = certen(['--json', 'pending', 'sign', hash, '--identity', B.adi, '--signer-url', B.page]);
  line(`    exit=${r.code} in ${Date.now() - t0}ms`);
  line(`    stdout=${r.stdout.trim().slice(0, 300)}`);
  const env = JSON.parse(r.stdout.trim());
  record('4', 'CLI hash without --public-key',
    r.code === 2 && env.error?.code === 'MISSING_SIGNER_DETAILS',
    `exit ${r.code}, error.code ${env.error?.code}`);
}

async function scenario5() {
  line('\n[5] MCP, id from certen_pending_list');
  const fx = takeFixture('inbox');
  const listed = await mcp([{ name: 'certen_pending_list', arguments: { identity: B.adi, limit: 50 } }]);
  const actions = mcpJson(listed[0]).actions ?? [];
  const row = actions.find((a: any) => a.tx_hash === fx.txHash);
  if (!row) return record('5', 'MCP inbox id', false, `certen_pending_list did not list ${fx.txHash}`);
  line(`    certen_pending_list gave id ${row.id}`);
  const signed = await mcp([{ name: 'certen_sign_create', arguments: { targetId: row.id, confirm: true } }]);
  const out = mcpJson(signed[0]);
  line(`    certen_sign_create -> ${JSON.stringify(out).slice(0, 260)}`);
  if (!out.sign_request_id) return record('5', 'MCP inbox id', false, JSON.stringify(out).slice(0, 240));
  const sub = await mcp([{
    name: 'certen_sign_submit_signature',
    arguments: {
      signRequestId: out.sign_request_id,
      signature: sign(out.signing_data.data_for_signature),
      publicKey: B.pub,
      confirm: true,
    },
  }]);
  line(`    certen_sign_submit_signature -> ${JSON.stringify(mcpJson(sub[0])).slice(0, 200)}`);
  const st = await waitFor(fx.txHash, fx.principal, 'delivered');
  record('5', 'MCP inbox id', st === 'delivered', `signed straight from the inbox id, tx ${st}`);
}

async function scenario6() {
  line('\n[6] MCP, hash target (regression)');
  const fx = takeFixture('tx');
  const signed = await mcp([{
    name: 'certen_sign_create',
    arguments: { targetId: fx.txHash, identity: B.adi, signerUrl: B.page, publicKey: B.pub, confirm: true },
  }]);
  const out = mcpJson(signed[0]);
  line(`    certen_sign_create -> ${JSON.stringify(out).slice(0, 260)}`);
  if (!out.sign_request_id) return record('6', 'MCP hash target', false, JSON.stringify(out).slice(0, 240));
  const sub = await mcp([{
    name: 'certen_sign_submit_signature',
    arguments: {
      signRequestId: out.sign_request_id,
      signature: sign(out.signing_data.data_for_signature),
      publicKey: B.pub,
      confirm: true,
    },
  }]);
  line(`    submit -> ${JSON.stringify(mcpJson(sub[0])).slice(0, 200)}`);
  const st = await waitFor(fx.txHash, fx.principal, 'delivered');
  record('6', 'MCP hash target', st === 'delivered', `tx ${st}`);
}

async function scenario7() {
  line('\n[7] CLI, --vote reject on a hash target');
  const fx = takeFixture('tx');
  const r = certen(['--json', 'pending', 'sign', fx.txHash,
    '--identity', B.adi, '--signer-url', B.page, '--public-key', B.pub, '--vote', 'reject']);
  line(`    sign exit=${r.code} ${r.stdout.trim().slice(0, 260)}`);
  if (r.code !== 0) return record('7', 'CLI --vote reject', false, r.stderr.slice(0, 240));
  const data = JSON.parse(r.stdout.trim()).data;
  const { r: sub } = cliSubmit(data.sign_request_id, data.signing_data.data_for_signature);
  line(`    submit exit=${sub.code} ${sub.stdout.trim().slice(0, 200)}`);
  const st = await waitFor(fx.txHash, fx.principal, 'rejected');
  record('7', 'CLI --vote reject', st === 'rejected', `tx ${st}`);
}

async function scenario6d() {
  line('\n[6d] cross-surface signature equivalence');
  const fx = takeFixture('tx');
  line(`    fixed transaction ${fx.txHash}`);

  const cli = certen(['--json', 'pending', 'sign', fx.txHash,
    '--identity', B.adi, '--signer-url', B.page, '--public-key', B.pub]);
  if (cli.code !== 0) return record('6d', 'cross-surface equivalence', false, cli.stderr.slice(0, 240));
  const cliData = JSON.parse(cli.stdout.trim()).data;

  const m = await mcp([{
    name: 'certen_sign_create',
    arguments: {
      targetId: `acc://${fx.txHash}@${fx.principal}`,
      identity: B.adi, signerUrl: B.page, publicKey: B.pub, confirm: true,
    },
  }]);
  const mcpData = mcpJson(m[0]);

  const { CertenClient } = await import(`file:///${REPO}/packages/sdk/dist/index.js`);
  const sdkData = await new CertenClient({ apiKey: API_KEY, baseUrl: GW }).sign.create({
    type: 'pending_tx', targetId: fx.txHash, identity: B.adi, signerUrl: B.page, publicKey: B.pub, vote: 'approve',
  });

  const rows = ([['CLI', cliData], ['MCP', mcpData], ['SDK', sdkData]] as Array<[string, any]>)
    .map(([name, r]) => ({
      name,
      requestId: r.sign_request_id,
      signer: r.signing_data.signer_url,
      version: Number(r.signing_data.signer_version),
      ts: Number(r.signing_data.timestamp),
      txHash: r.signing_data.transaction_hash,
      preimage: String(r.signing_data.data_for_signature),
      signature: sign(String(r.signing_data.data_for_signature)),
    }));

  line('');
  line('    as issued (each request gets its own anti-replay timestamp):');
  for (const r of rows) {
    line(`      ${r.name}: signer=${r.signer} version=${r.version} ts=${r.ts} tx=${r.txHash}`);
    line(`           preimage  ${r.preimage}`);
    line(`           signature ${r.signature}`);
  }

  // Every field the gateway reports must be reproducible from this repo's own encoder. If a surface
  // sent a different signer, version, transaction or vote, this is where it shows.
  const reproduced = rows.map((r) => ({
    name: r.name,
    ok: localPreimage({ signer: r.signer, version: r.version, ts: r.ts, txHash: r.txHash }) === r.preimage,
  }));
  line('');
  for (const r of reproduced) line(`    ${r.name} preimage reproduced independently: ${r.ok}`);

  // Same signer facts across surfaces, then the same bytes once the timestamp is held fixed.
  const sameShape = rows.every((r) => r.signer === rows[0].signer
    && r.version === rows[0].version && r.txHash === rows[0].txHash);
  const fixedTs = rows[0].ts;
  const fixed = rows.map((r) => ({
    name: r.name,
    preimage: localPreimage({ signer: r.signer, version: r.version, ts: fixedTs, txHash: r.txHash }),
  }));
  const sigs = fixed.map((f) => ({ name: f.name, sig: sign(f.preimage) }));
  line('');
  line(`    recomputed at one fixed timestamp (${fixedTs}):`);
  for (const f of fixed) line(`      ${f.name} preimage  ${f.preimage}`);
  for (const s of sigs) line(`      ${s.name} signature ${s.sig}`);

  const identical = new Set(fixed.map((f) => f.preimage)).size === 1
    && new Set(sigs.map((s) => s.sig)).size === 1;

  record('6d', 'cross-surface equivalence',
    sameShape && identical && reproduced.every((r) => r.ok),
    `same signer/version/tx across surfaces: ${sameShape}; identical signature bytes at a fixed `
    + `timestamp: ${identical}; each gateway preimage reproduced independently: `
    + `${reproduced.every((r) => r.ok)}`);

  const { r: sub } = cliSubmit(cliData.sign_request_id, cliData.signing_data.data_for_signature);
  line(`    submitted via CLI, exit=${sub.code}`);
  await waitFor(fx.txHash, fx.principal, 'delivered');
}

const MAP: Record<string, () => Promise<unknown>> = {
  1: scenario1,
  2: () => scenarioHash('2', 'CLI bare 64-hex hash, header-authority signer', (fx) => fx.txHash),
  3: () => scenarioHash('3', 'CLI acc://<hash>@<account> TxID', (fx) => fx.txid),
  4: scenario4,
  5: scenario5,
  6: scenario6,
  7: scenario7,
  8: () => scenarioHash('8', 'CLI, enrollment shape end to end', (fx) => fx.txHash),
  '6d': scenario6d,
};

const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(MAP);
for (const k of wanted) {
  await MAP[k]();
}
line('\n==== summary ====');
for (const r of results) line(`  ${r.pass ? 'PASS' : 'FAIL'}  [${r.n}] ${r.name} — ${r.detail}`);
process.exitCode = results.every((r) => r.pass) ? 0 : 1;
