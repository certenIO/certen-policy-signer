/**
 * Shared helpers for the live verification scripts: test-network provisioning, writing transactions that
 * require an authority, and running the signer as a real child process.
 *
 * Not a test itself — see the scripts beside it, and scripts/verify/README.md.
 *
 * Everything here targets a PUBLIC TEST NETWORK and provisions its own throwaway identities from a
 * faucet, so no script needs pre-existing state, funds, or a shared account. Override the endpoint with
 * ACC=<url> to run against your own node or devnet.
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
export const S: any = (signingNs as any).default ?? signingNs;
export const core: any = (coreNs as any).default ?? coreNs;
export const msg: any = (msgNs as any).default ?? msgNs;
export const ENDPOINT = process.env.ACC ?? 'https://kermit.accumulatenetwork.io/v3';
export const raw = new RawAccumulateClient(ENDPOINT, pino({ level: 'warn' }));
export const rpc = (m: string, p: unknown) => (raw as any).rpc(m, p);
export const query = (s: string, q?: unknown) => (raw as any).query(s, q);
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
let tsC = 0;
export const nextTs = () => Date.now() * 1000 + tsC++;

export function liteId(pub: Uint8Array): string {
  const keyStr = Buffer.from(sha(pub)).subarray(0, 20).toString('hex');
  const checksum = createHash('sha256').update(Buffer.from(keyStr, 'utf8')).digest('hex').slice(-8);
  return `acc://${keyStr}${checksum}`;
}
export function ed(seedFill: number) {
  const seed = nacl.randomBytes(32); seed[0] = seedFill;
  const kp = nacl.sign.keyPair.fromSeed(seed);
  const key = S.ED25519Key.from ? S.ED25519Key.from(kp.secretKey) : new S.ED25519Key(kp.secretKey);
  return { seed, kp, key, pub: kp.publicKey };
}
export async function submit(tx: any, signer: any, label: string): Promise<string> {
  const sig = await signer.sign(tx, { timestamp: nextTs() });
  const res: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
  if (!res.ok) throw new Error(`${label} submit failed: ${JSON.stringify(res).slice(0, 300)}`);
  return String(res?.result?.[0]?.status?.txID ?? res?.result?.[1]?.status?.txID ?? '');
}
export async function waitForAccount(url: string, label: string) {
  for (let i = 0; i < 25; i++) { await sleep(3000); const r: any = await query(url).catch(() => undefined); if (r?.account) { console.log(`  [${label}] exists`); return; } }
  throw new Error(`${label} (${url}) never appeared`);
}
export async function waitForCredits(url: string, label: string) {
  for (let i = 0; i < 20; i++) { await sleep(3000); const info = await raw.getSignerInfo(url).catch(() => ({ creditBalance: 0 })); if ((info.creditBalance ?? 0) > 0) { console.log(`  [${label}] credits=${info.creditBalance}`); return; } }
  throw new Error(`${label} (${url}) never got credits`);
}
/** delivered | rejected | expired | pending | <raw code> */
export async function txState(hash: string, principal: string): Promise<string> {
  const r: any = await query(`acc://${hash}@${principal}`).catch(() => undefined);
  const code = String(r?.status?.code ?? r?.status ?? '');
  if (/delivered/i.test(code)) return 'delivered';
  if (/expired/i.test(code)) return 'expired';
  if (/fail|error|reject/i.test(code)) return 'rejected';
  return code || 'pending';
}

/**
 * Build an example payload in the reference intent format — the one the built-in `certen-intent` decoder
 * understands (src/decode/decoders/certen-intent.ts).
 *
 * Four hex-encoded JSON blobs: [intent, crossChain, governance, replay]. The amounts that a policy engine
 * gates on live in `crossChain.legs[].amountWei`.
 *
 * To verify against YOUR OWN payload format instead, pass `data:` to writeIntent() with your bytes and
 * point the signer's `resolver.decoder_modules` at your decoder — see examples/custom-decoder.mjs. That
 * substitution is the whole extension seam, exercised live.
 */
export function intentBlobs(amountWei: string, legs?: any[]): string[] {
  const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
  const legArr = legs ?? [{ legId: 'l1', chain: 'ethereum-sepolia', asset: { symbol: 'ETH', decimals: 18 }, to: '0xBe0043', amountWei, amountEth: '0.0' }];
  return [
    { kind: 'CERTEN_INTENT', version: '2.0', intent_id: `i-${amountWei}`, description: `Transfer ${amountWei} wei` },
    { protocol: 'CERTEN', version: '2.0', legs: legArr },
    { organizationAdi: 'acc://o.acme', authorization: { signature_threshold: 1 } },
    { nonce: `n-${amountWei}`, expires_at: 1999999999 },
  ].map(toHex);
}

export interface Org { adi: string; book: string; page: string; key: ReturnType<typeof ed>; }
export interface Principal extends Org { dataAccount: string; dataPrincipal: string; }

export async function fundLite() {
  const funding = ed(0x11); const fLite = liteId(funding.pub); const fLta = `${fLite}/ACME`;
  const net: any = await rpc('network-status', {}); const oracle = net?.oracle?.price ?? 10000000;
  for (let i = 0; i < 4; i++) { await rpc('faucet', { account: fLta }).catch(() => rpc('faucet', { url: fLta }).catch(() => {})); await sleep(2500); }
  for (let i = 0; i < 14; i++) { await sleep(3000); const b: any = await query(fLta).catch(() => undefined); if (Number(b?.account?.balance ?? 0) > 0) { console.log('  funded', b.account.balance); break; } }
  await submit(new core.Transaction({ header: { principal: fLta }, body: { type: 'addCredits', recipient: fLite, amount: '700000000', oracle } }), S.Signer.forLite(funding.key), 'cr-lite');
  await waitForCredits(fLite, 'funding lite credits'); // poll until settled — a fixed sleep is flaky under load
  return { funding, fLite, fLta, oracle };
}
export async function createOrg(f: any, adi: string, seedFill: number, pageCredit?: string): Promise<Org> {
  const key = ed(seedFill); const book = `${adi}/book`, page = `${book}/1`;
  await submit(new core.Transaction({ header: { principal: f.fLite }, body: { type: 'createIdentity', url: adi, keyHash: sha(key.pub), keyBookUrl: book } }), S.Signer.forLite(f.funding.key), `adi ${adi}`);
  await waitForAccount(page, `${adi} page`);
  if (pageCredit) { await submit(new core.Transaction({ header: { principal: f.fLta }, body: { type: 'addCredits', recipient: page, amount: pageCredit, oracle: f.oracle } }), S.Signer.forLite(f.funding.key), `cr ${adi}`); await waitForCredits(page, `${adi} page`); }
  return { adi, book, page, key };
}
export async function createPrincipal(f: any, adi: string, seedFill: number, pageCredit = '400000000'): Promise<Principal> {
  const org = await createOrg(f, adi, seedFill, pageCredit);
  const dataAccount = `${adi}/data`, dataPrincipal = adi.replace(/^acc:\/\//, '') + '/data';
  await submit(new core.Transaction({ header: { principal: adi }, body: { type: 'createDataAccount', url: dataAccount } }), S.Signer.forPage(org.page, org.key.key).withVersion((await raw.getSignerInfo(org.page)).version), 'dataAccount');
  await waitForAccount(dataAccount, 'data account');
  return { ...org, dataAccount, dataPrincipal };
}

export async function writeIntent(A: Principal, opts: { authorities: string[]; amountWei?: string; legs?: any[]; memo?: string | null; data?: string[]; expireAt?: Date }): Promise<{ hash: string; txid: string; ok: boolean; error?: string }> {
  const v = (await raw.getSignerInfo(A.page)).version;
  const header: any = { principal: A.dataAccount, authorities: opts.authorities };
  if (opts.memo !== null) header.memo = opts.memo ?? 'CERTEN_INTENT';
  if (opts.expireAt) header.expire = { atTime: opts.expireAt }; // encoding fixed in accumulate.js Time.encode (signed varint + floor)
  const data = opts.data ?? intentBlobs(opts.amountWei ?? '0', opts.legs);
  const tx = new core.Transaction({ header, body: { type: 'writeData', entry: { type: 'doubleHash', data } } });
  const sig = await S.Signer.forPage(A.page, A.key.key).withVersion(v).sign(tx, { timestamp: nextTs() });
  const r: any = await raw.submit(new msg.Envelope({ transaction: [tx], signatures: [sig] }).asObject());
  const txid = String(r?.result?.[0]?.status?.txID ?? '');
  return { hash: txid.replace(/^acc:\/\//, '').split('@')[0], txid, ok: r.ok, error: r.ok ? undefined : JSON.stringify(r).slice(0, 400) };
}

export function writeConfig(path: string, o: { orgId: string; oPage: string; oSeedHex: string; enginePort: number; healthPort: number; hmacSecret?: string; adminKey?: string; govKey?: string; interval?: number; storePath?: string; allowUnverified?: boolean }) {
  const policyAuth = o.hmacSecret ? `auth: "hmac", hmac_secret: "${o.hmacSecret}", ` : `auth: "none", `;
  // Admin shares the health listener; api_key is what gates it (no key => admin routes 403).
  const gov = o.govKey ? `, governance_admin_key: "${o.govKey}"` : '';
  const adminLine = o.adminKey ? `admin: { api_key: "${o.adminKey}"${gov} }\n` : '';
  const storeLine = o.storePath ? `store: { path: "${o.storePath}" }\n` : '';
  const unverified = o.allowUnverified ? ', allow_unverified_signer: true' : '';
  writeFileSync(path,
`wallet: { org_id: "${o.orgId}", accumulate_endpoints: ["${ENDPOINT}"], signer_url: "${o.oPage}", attachment_model: "per_tx"${unverified} }
signer: { provider: "local", local: { seed_hex: "${o.oSeedHex}" } }
policy: { url: "http://127.0.0.1:${o.enginePort}/decision", mode: "sync", ${policyAuth}timeout_ms: 4000 }
trigger: { webhook: { enabled: false, bind: "127.0.0.1:${o.healthPort}" }, poller: { enabled: true, interval_seconds: ${o.interval ?? 12} } }
behavior: { submit_reject_vote: true }
${storeLine}${adminLine}health: { bind: "127.0.0.1:${o.healthPort}" }
observability: { log_level: "info" }
`);
}

export function spawnEngine(port: number, hmacSecret?: string): ChildProcess {
  const env: any = { ...process.env, PORT: String(port) };
  if (hmacSecret) env.POLICY_HMAC_SECRET = hmacSecret;
  const c = spawn('node', ['examples/policy-engine.mjs'], { env });
  c.stdout?.on('data', (d) => process.stdout.write(`    [engine:${port}] ${d}`));
  return c;
}
/**
 * Spawn the signer daemon and surface its interesting log lines.
 *   currentHash  optional focus filter — hide tx-specific lines for OTHER transactions.
 *   render       optional formatter — turn a parsed pino line into a human-readable string (return null to
 *                drop it). When omitted, the raw JSON is printed as `[signer] {…}`.
 */
export function spawnDaemon(
  configPath: string,
  log: string[],
  currentHash?: () => string | null,
  render?: (parsed: any, raw: string) => string | null,
): ChildProcess {
  const c = spawn('node', ['node_modules/tsx/dist/cli.mjs', 'src/index.ts', configPath]);
  const show = /discovered pending intent|requesting decision|vote submission failed|vote submitted|SR6|poller started|listening|policy denied|policy decision failed|signing paused|submit failed|fatal|refus/i;
  const on = (d: Buffer) => {
    const s = d.toString(); log.push(s);
    for (const ln of s.split('\n')) {
      if (!show.test(ln)) continue;
      // Optional focus filter: when a "current tx" is set, hide tx-specific lines for OTHER transactions
      // (e.g. a tx left pending by an earlier demo run). Keeps repeatable-demo output on the tx in play;
      // the signer still processes the others — they are just not printed here.
      if (currentHash) { const m = /"tx":"([0-9a-f]{64})"/.exec(ln); if (m) { const h = currentHash(); if (!h || m[1] !== h) continue; } }
      if (render) {
        let parsed: any = null; try { parsed = JSON.parse(ln.trim()); } catch { /* not JSON — leave null */ }
        const out = render(parsed, ln.trim());
        if (out == null) continue; // formatter chose to drop this line
        process.stdout.write(out.endsWith('\n') ? out : out + '\n');
      } else {
        process.stdout.write(`      [signer] ${ln.trim()}\n`);
      }
    }
  };
  c.stdout?.on('data', on); c.stderr?.on('data', on);
  return c;
}
export const kill = (c?: ChildProcess) => { try { c?.kill('SIGKILL'); } catch {} };
