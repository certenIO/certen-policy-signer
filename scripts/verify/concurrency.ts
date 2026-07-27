/**
 * Concurrency and idempotency: several pending transactions at once, each voted on EXACTLY ONCE.
 *
 * Double-voting is the failure mode that matters most in a signer, because it is invisible until it is
 * expensive. This writes three transactions before the daemon ever starts, then boots the real daemon
 * with nothing handed to it and lets it discover all three across many poll cycles.
 *
 *   even amount  -> approved -> executed
 *   odd  amount  -> denied   -> rejected
 *   even amount  -> approved -> executed
 *
 * The assertion that carries the weight: across every poll cycle, each transaction was voted on once.
 * The poller sees them repeatedly; the durable store is what makes that safe.
 *
 *   npx tsx scripts/verify/concurrency.ts
 */
import { spawn, ChildProcess } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import pino from 'pino';
import nacl from 'tweetnacl';
import { createHash } from 'node:crypto';
import { RawAccumulateClient } from '../../src/accumulate/raw-client.js';
import * as signingNs from 'accumulate.js/signing';
import * as coreNs from 'accumulate.js/core';
import * as msgNs from 'accumulate.js/messaging';

/* eslint-disable @typescript-eslint/no-explicit-any */
const S: any = (signingNs as any).default ?? signingNs;
const core: any = (coreNs as any).default ?? coreNs;
const msg: any = (msgNs as any).default ?? msgNs;

const log = pino({ level: 'warn' });
const ENDPOINT = process.env.ACC ?? 'https://kermit.accumulatenetwork.io/v3';
const raw = new RawAccumulateClient(ENDPOINT, log);
const rpc = (m: string, p: unknown) => (raw as any).rpc(m, p);
const query = (s: string, q?: unknown) => (raw as any).query(s, q);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const ENGINE_PORT = 9108, HEALTH_PORT = 18091;

let tsCounter = 0;
const nextTs = () => Date.now() * 1000 + tsCounter++;
function liteId(pub: Uint8Array): string {
  const keyStr = Buffer.from(sha(pub)).subarray(0, 20).toString('hex');
  const checksum = createHash('sha256').update(Buffer.from(keyStr, 'utf8')).digest('hex').slice(-8);
  return `acc://${keyStr}${checksum}`;
}
function ed(seedFill: number) {
  const seed = nacl.randomBytes(32); seed[0] = seedFill;
  const kp = nacl.sign.keyPair.fromSeed(seed);
  const key = S.ED25519Key.from ? S.ED25519Key.from(kp.secretKey) : new S.ED25519Key(kp.secretKey);
  return { seed, kp, key, pub: kp.publicKey };
}
async function submit(tx: any, signer: any, label: string): Promise<string> {
  const sig = await signer.sign(tx, { timestamp: nextTs() });
  const res: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
  const txid = res?.result?.[0]?.status?.txID ?? res?.result?.[1]?.status?.txID;
  if (!res.ok) throw new Error(`${label} submit failed: ${JSON.stringify(res).slice(0, 300)}`);
  return String(txid ?? '');
}
async function waitForAccount(url: string, label: string) {
  for (let i = 0; i < 25; i++) { await sleep(3000); const r: any = await query(url).catch(() => undefined); if (r?.account) { console.log(`  [${label}] exists`); return; } }
  throw new Error(`${label} (${url}) never appeared`);
}
async function waitForCredits(url: string, label: string) {
  for (let i = 0; i < 20; i++) { await sleep(3000); const info = await raw.getSignerInfo(url).catch(() => ({ creditBalance: 0 })); if ((info.creditBalance ?? 0) > 0) { console.log(`  [${label}] credits=${info.creditBalance}`); return; } }
  throw new Error(`${label} (${url}) never got credits`);
}
async function txState(hash: string, principal: string): Promise<string> {
  const r: any = await query(`acc://${hash}@${principal}`).catch(() => undefined);
  const code = String(r?.status?.code ?? r?.status ?? '');
  if (/delivered/i.test(code)) return 'delivered';
  if (/fail|error|reject/i.test(code)) return 'rejected';
  return code || 'pending';
}
function certenIntentTx(dataAccount: string, oBook: string, amountWei: string) {
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const blobs = [
    { kind: 'CERTEN_INTENT', version: '2.0', intent_id: `intent-${amountWei}`, description: `Transfer ${amountWei} wei` },
    { protocol: 'CERTEN', version: '2.0', legs: [{ legId: 'leg-1', chain: 'ethereum-sepolia', asset: { symbol: 'ETH', decimals: 18 }, to: '0xBe0043', amountWei, amountEth: '0.0' }] },
    { organizationAdi: 'acc://o.acme', authorization: { required_key_book: oBook, signature_threshold: 1 } },
    { nonce: `certen_${amountWei}`, expires_at: 1999999999 },
  ];
  return new core.Transaction({ header: { principal: dataAccount, authorities: [oBook], memo: 'CERTEN_INTENT' }, body: { type: 'writeData', entry: { type: 'doubleHash', data: blobs.map(toHex) } } });
}

const children: ChildProcess[] = [];
const killAll = () => { for (const c of children) { try { c.kill('SIGKILL'); } catch {} } };

async function main() {
  const ts = Date.now();
  const adiA = `acc://a-${ts}.acme`, adiO = `acc://o-${ts}.acme`;
  const aBook = `${adiA}/book`, oBook = `${adiO}/book`, aPage = `${aBook}/1`, oPage = `${oBook}/1`;
  const dataAccount = `${adiA}/data`, dataPrincipal = `a-${ts}.acme/data`;
  const funding = ed(0x11), aKey = ed(0x22), oKey = ed(0x33);
  const fLite = liteId(funding.pub), fLta = `${fLite}/ACME`;

  console.log('=== CONCURRENCY: 3 pending transactions at once, each voted exactly once ===');
  console.log('A:', adiA, '| O:', adiO, '\n');
  const net: any = await rpc('network-status', {}); const oracle = net?.oracle?.price ?? 10000000;

  console.log('[1] faucet + credits');
  for (let i = 0; i < 3; i++) { await rpc('faucet', { account: fLta }).catch(() => rpc('faucet', { url: fLta })); await sleep(2500); }
  for (let i = 0; i < 12; i++) { await sleep(3000); const b: any = await query(fLta).catch(() => undefined); if (Number(b?.account?.balance ?? 0) > 0) { console.log('  funded', b.account.balance); break; } }
  await submit(new core.Transaction({ header: { principal: fLta }, body: { type: 'addCredits', recipient: fLite, amount: '600000000', oracle } }), S.Signer.forLite(funding.key), 'cr-lite');
  await waitForCredits(fLite, 'funding lite'); // poll until settled — a fixed sleep races the test network
  console.log('[2] createIdentity A + O');
  await submit(new core.Transaction({ header: { principal: fLite }, body: { type: 'createIdentity', url: adiA, keyHash: sha(aKey.pub), keyBookUrl: aBook } }), S.Signer.forLite(funding.key), 'adi-A');
  await submit(new core.Transaction({ header: { principal: fLite }, body: { type: 'createIdentity', url: adiO, keyHash: sha(oKey.pub), keyBookUrl: oBook } }), S.Signer.forLite(funding.key), 'adi-O');
  await waitForAccount(aPage, 'A book/1'); await waitForAccount(oPage, 'O book/1');
  console.log('[3] credits -> pages');
  await submit(new core.Transaction({ header: { principal: fLta }, body: { type: 'addCredits', recipient: aPage, amount: '400000000', oracle } }), S.Signer.forLite(funding.key), 'cr-A');
  await submit(new core.Transaction({ header: { principal: fLta }, body: { type: 'addCredits', recipient: oPage, amount: '200000000', oracle } }), S.Signer.forLite(funding.key), 'cr-O');
  await waitForCredits(aPage, 'A page'); await waitForCredits(oPage, 'O page');
  console.log('[4] createDataAccount');
  await submit(new core.Transaction({ header: { principal: adiA }, body: { type: 'createDataAccount', url: dataAccount } }), S.Signer.forPage(aPage, aKey.key).withVersion((await raw.getSignerInfo(aPage)).version), 'data');
  await waitForAccount(dataAccount, 'data account');

  console.log('\n[5] A writes 3 intents tagging O (even/odd/even) -> all PENDING');
  const plan = [{ amountWei: '4000', expect: 'delivered' }, { amountWei: '4001', expect: 'rejected' }, { amountWei: '4002', expect: 'delivered' }];
  const cases: Array<{ amountWei: string; expect: string; hash: string }> = [];
  for (const p of plan) {
    const v = (await raw.getSignerInfo(aPage)).version;
    const tx = certenIntentTx(dataAccount, oBook, p.amountWei);
    const sig = await S.Signer.forPage(aPage, aKey.key).withVersion(v).sign(tx, { timestamp: nextTs() });
    const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
    const hash = String(r?.result?.[0]?.status?.txID ?? '').replace(/^acc:\/\//, '').split('@')[0];
    console.log(`  intent ${p.amountWei} (${p.expect}) -> ${hash} ok:${r.ok}`);
    cases.push({ ...p, hash });
    await sleep(2000);
  }

  const configPath = 'config.concurrency.generated.yaml';
  writeFileSync(configPath,
`signer: { org_id: "o-${ts}", network: "the test network", accumulate_endpoints: ["${ENDPOINT}"], signer_url: "${oPage}", attachment_model: "per_tx" }
signer: { provider: "local", local: { seed_hex: "${Buffer.from(oKey.seed).toString('hex')}" } }
policy: { url: "http://127.0.0.1:${ENGINE_PORT}/decision", mode: "sync", auth: "none", timeout_ms: 4000 }
trigger: { webhook: { enabled: false, bind: "127.0.0.1:${HEALTH_PORT}" }, poller: { enabled: true, interval_seconds: 15 } }
behavior: { submit_reject_vote: true }
admin: { bind: "127.0.0.1:${HEALTH_PORT}" }
health: { bind: "127.0.0.1:${HEALTH_PORT}" }
observability: { log_level: "info" }
`);

  console.log('\n[6] spawn engine + real daemon; watch it auto-handle all 3');
  const walletLog: string[] = [];
  const engine = spawn('node', ['examples/policy-engine.mjs'], { env: { ...process.env, PORT: String(ENGINE_PORT) } });
  children.push(engine); engine.stdout?.on('data', (d) => process.stdout.write(`    [engine] ${d}`));
  await sleep(1500);
  const daemon = spawn('node', ['node_modules/tsx/dist/cli.mjs', 'src/index.ts', configPath]);
  children.push(daemon);
  const onLine = (d: Buffer) => { const s = d.toString(); walletLog.push(s); for (const ln of s.split('\n')) if (/vote submitted|SR6|poller started|listening|policy denied|error/i.test(ln)) process.stdout.write(`    [signer] ${ln.trim()}\n`); };
  daemon.stdout?.on('data', onLine); daemon.stderr?.on('data', onLine);

  console.log('\n[7] waiting for all 3 to reach terminal state (up to ~220s)...');
  const states: Record<string, string> = {};
  for (let i = 0; i < 55; i++) {
    await sleep(4000);
    for (const c of cases) states[c.hash] = await txState(c.hash, dataPrincipal);
    if (cases.every((c) => states[c.hash] === c.expect)) break;
  }

  // idempotency: count "vote submitted" per tx from the daemon log
  const voteLines = walletLog.join('').split('\n').filter((l) => /"msg":"vote submitted"/.test(l));
  const votesByTx: Record<string, string[]> = {};
  for (const l of voteLines) { try { const j = JSON.parse(l); (votesByTx[j.tx] ||= []).push(j.vote); } catch {} }

  console.log('\n[8] RESULTS');
  console.log('  ┌─ amountWei ─┬─ expect ───┬─ on-chain ─┬─ vote ────┬─ #votes(idempotency) ─┐');
  let allPass = true;
  for (const c of cases) {
    const votes = votesByTx[c.hash] ?? [];
    const statePass = states[c.hash] === c.expect;
    const idemPass = votes.length === 1;
    if (!statePass || !idemPass) allPass = false;
    console.log(`  │ ${c.amountWei.padEnd(10)} │ ${c.expect.padEnd(10)} │ ${(states[c.hash] ?? '?').padEnd(10)} │ ${(votes[0] ?? '-').padEnd(9)} │ ${String(votes.length).padEnd(21)} │ ${statePass && idemPass ? '✅' : '❌'}`);
  }
  console.log('  └─────────────┴────────────┴────────────┴───────────┴───────────────────────┘');
  const bootOk = /SR6 self-check OK/i.test(walletLog.join('')) && /poller started/i.test(walletLog.join(''));
  console.log('  daemon SR6 + poller:', bootOk);

  killAll();
  const pass = allPass && bootOk;
  console.log('\n=== CONCURRENCY:', pass
    ? 'PASS ✅ — real daemon autonomously approved 2 even + rejected 1 odd, each signed exactly once.'
    : 'INCOMPLETE — see table.', '===');
  await sleep(500);
  process.exit(pass ? 0 : 1);
}
main().catch((e) => { console.error('FATAL', e.message); console.error(e.stack?.split('\n').slice(0, 4).join('\n')); killAll(); process.exit(1); });
