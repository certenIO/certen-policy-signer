/**
 * The safety envelope, live: five ways things go wrong, and what the signer does about each.
 *
 * These are the properties a security review asks about, checked against a real network rather than
 * asserted in prose:
 *
 *   1. REFUSES TO BOOT ON THE WRONG KEY. Started with a key that is not on the configured page, the
 *      daemon exits instead of starting. The failure it prevents is silent — a signer on the wrong key
 *      looks healthy while every vote it casts is discarded by the network.
 *   2. SURVIVES A POLICY-ENGINE OUTAGE. Engine down: the transaction stays pending and nothing is
 *      signed. Engine back: it signs. An outage delays; it never approves.
 *   3. PAUSE MEANS PAUSE. With signing paused, an `approve` still produces no signature.
 *   4. THE SIGNED CHANNEL WORKS END TO END, with HMAC on both request and response.
 *   5. AN UNREADABLE PAYLOAD IS NOT A BLANK CHEQUE. A data write no decoder understands reaches the
 *      engine described generically, and is denied.
 *
 *   npx tsx scripts/verify/resilience.ts
 *   ACC=<endpoint> npx tsx scripts/verify/resilience.ts     # against your own node
 */
import { unlinkSync } from 'node:fs';
import { ENDPOINT, fundLite, createOrg, createPrincipal, writeIntent, writeConfig, spawnEngine, spawnDaemon, kill, txState, sleep, ed, raw } from './_lib.js';

const ENGINE = 9110, HEALTH = 18110;
const results: Record<string, string> = {};
const admin = (path: string) => fetch(`http://127.0.0.1:${HEALTH}${path}`, { method: 'POST', headers: { 'x-api-key': 'adminkey' } });
const seenAfter = async (pred: () => boolean, iters: number, ms = 4000) => { for (let i = 0; i < iters; i++) { await sleep(ms); if (pred()) return true; } return pred(); };

async function main() {
  console.log('=== SAFETY ENVELOPE on', ENDPOINT, '===');
  const f = await fundLite();
  const ts = Date.now();
  const A = await createPrincipal(f, `acc://a-r1-${ts}.acme`, 0x22);
  const O = await createOrg(f, `acc://o-r1-${ts}.acme`, 0x33, '400000000');
  const oSeed = Buffer.from(O.key.seed).toString('hex');
  console.log('  A:', A.adi, '| O:', O.adi, '\n');

  // ---- 3: SR6 refuse-to-boot (wrong seed vs O's page) ----
  console.log('[3] SR6 refuse-to-boot (wrong seed)');
  {
    const path = 'config.r1s3.generated.yaml';
    writeConfig(path, { orgId: 'r1s3', oPage: O.page, oSeedHex: Buffer.from(ed(0x99).seed).toString('hex'), enginePort: ENGINE, healthPort: HEALTH });
    const logL: string[] = []; const d = spawnDaemon(path, logL);
    const code = await new Promise<number>((res) => { d.on('exit', (c) => res(c ?? 0)); setTimeout(() => { kill(d); res(d.exitCode ?? -1); }, 30000); });
    const refused = /SR6|does not match|refusing to start|fatal startup/i.test(logL.join(''));
    results['3 SR6 refuse-boot'] = (code !== 0 && refused) ? 'PASS' : 'FAIL';
    console.log(`  -> exit=${code} refused=${refused} => ${results['3 SR6 refuse-boot']}`);
    try { unlinkSync(path); } catch {}
    await sleep(2000);
  }

  // ---- 1: policy-down recovery ----
  console.log('\n[1] policy-down recovery');
  {
    const intent = await writeIntent(A, { authorities: [O.book], amountWei: '5000' });
    const path = 'config.r1s1.generated.yaml';
    writeConfig(path, { orgId: 'r1s1', oPage: O.page, oSeedHex: oSeed, enginePort: ENGINE, healthPort: HEALTH });
    const logL: string[] = []; const d = spawnDaemon(path, logL);       // engine intentionally NOT started
    const failLogged = await seenAfter(() => /policy decision failed/i.test(logL.join('')), 18);
    const stillPending = (await txState(intent.hash, A.dataPrincipal)) !== 'delivered';
    console.log(`  engine down: policyFailLogged=${failLogged} stillPending=${stillPending}`);
    const eng = spawnEngine(ENGINE);                                    // heal
    let delivered = false; for (let i = 0; i < 22; i++) { await sleep(4000); if (await txState(intent.hash, A.dataPrincipal) === 'delivered') { delivered = true; break; } }
    results['1 policy-down recovery'] = (failLogged && stillPending && delivered) ? 'PASS' : 'FAIL';
    console.log(`  after engine up: delivered=${delivered} => ${results['1 policy-down recovery']}`);
    kill(d); kill(eng); try { unlinkSync(path); } catch {} await sleep(2000);
  }

  // ---- 2: SR8 pause ----
  console.log('\n[2] SR8 pause → withhold → resume → sign');
  {
    const intent = await writeIntent(A, { authorities: [O.book], amountWei: '5002' });
    const path = 'config.r1s2.generated.yaml';
    writeConfig(path, { orgId: 'r1s2', oPage: O.page, oSeedHex: oSeed, enginePort: ENGINE, healthPort: HEALTH, adminKey: 'adminkey' });
    const logL: string[] = []; const eng = spawnEngine(ENGINE); await sleep(1200); const d = spawnDaemon(path, logL);
    await seenAfter(() => /http server listening/i.test(logL.join('')), 10, 1000);
    await admin('/v1/admin/pause').catch(() => {});                     // pause before discovery
    const withheld = await seenAfter(() => /signing paused; withholding/i.test(logL.join('')), 16);
    const pendingWhilePaused = (await txState(intent.hash, A.dataPrincipal)) !== 'delivered';
    console.log(`  paused: withheldLogged=${withheld} stillPending=${pendingWhilePaused}`);
    await admin('/v1/admin/resume').catch(() => {});                    // resume
    let delivered = false; for (let i = 0; i < 20; i++) { await sleep(4000); if (await txState(intent.hash, A.dataPrincipal) === 'delivered') { delivered = true; break; } }
    results['2 SR8 pause'] = (withheld && pendingWhilePaused && delivered) ? 'PASS' : 'FAIL';
    console.log(`  after resume: delivered=${delivered} => ${results['2 SR8 pause']}`);
    kill(d); kill(eng); try { unlinkSync(path); } catch {} await sleep(2000);
  }

  // ---- 7: HMAC-authenticated policy ----
  console.log('\n[7] HMAC-authenticated policy');
  {
    const intent = await writeIntent(A, { authorities: [O.book], amountWei: '5004' });
    const path = 'config.r1s7.generated.yaml'; const secret = 'hmac-shared-secret';
    writeConfig(path, { orgId: 'r1s7', oPage: O.page, oSeedHex: oSeed, enginePort: ENGINE, healthPort: HEALTH, hmacSecret: secret });
    const logL: string[] = []; const eng = spawnEngine(ENGINE, secret); await sleep(1200); const d = spawnDaemon(path, logL);
    let delivered = false; for (let i = 0; i < 25; i++) { await sleep(4000); if (await txState(intent.hash, A.dataPrincipal) === 'delivered') { delivered = true; break; } }
    const signed = /vote submitted/i.test(logL.join(''));
    results['7 HMAC policy'] = (delivered && signed) ? 'PASS' : 'FAIL';
    console.log(`  delivered=${delivered} signed=${signed} => ${results['7 HMAC policy']}`);
    kill(d); kill(eng); try { unlinkSync(path); } catch {} await sleep(2000);
  }

  // ---- 6: non-CERTEN / malformed intent → fallback → fail-closed reject ----
  console.log('\n[6] non-CERTEN intent → fail-closed reject');
  {
    const garbage = [Buffer.from('this is not a certen intent', 'utf8').toString('hex')];
    const intent = await writeIntent(A, { authorities: [O.book], memo: null, data: garbage });
    const path = 'config.r1s6.generated.yaml';
    writeConfig(path, { orgId: 'r1s6', oPage: O.page, oSeedHex: oSeed, enginePort: ENGINE, healthPort: HEALTH });
    const logL: string[] = []; const eng = spawnEngine(ENGINE); await sleep(1200); const d = spawnDaemon(path, logL);
    let rejected = false; for (let i = 0; i < 25; i++) { await sleep(4000); if (await txState(intent.hash, A.dataPrincipal) === 'rejected') { rejected = true; break; } }
    const deny = /policy denied/i.test(logL.join(''));
    results['6 non-CERTEN fallback'] = (rejected && deny) ? 'PASS' : 'FAIL';
    console.log(`  rejected=${rejected} denyLogged=${deny} => ${results['6 non-CERTEN fallback']}`);
    kill(d); kill(eng); try { unlinkSync(path); } catch {} await sleep(1500);
  }

  console.log('\n=== RESULTS ===');
  for (const [k, v] of Object.entries(results)) console.log(`  ${v === 'PASS' ? '✅' : '❌'} ${k}: ${v}`);
  const pass = Object.values(results).every((v) => v === 'PASS');
  console.log('\n=== SAFETY ENVELOPE:', pass ? 'PASS ✅ (all resilience/safety scenarios)' : 'FAIL ❌ (see above)', '===');
  process.exit(pass ? 0 : 1);
}
main().catch((e) => { console.error('FATAL', e.message); console.error(e.stack?.split('\n').slice(0, 4).join('\n')); process.exit(1); });
