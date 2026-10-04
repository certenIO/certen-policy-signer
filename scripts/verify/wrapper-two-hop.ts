/**
 * The Trust Stamp wrapper delegate model, end to end on a live network. Wrapper runbook, change 7.
 *
 * The world it builds (all throwaway, from the faucet):
 *
 *   T   T/book/1 { K_ts } 1-of-1           Trust Stamp. The SIGNER UNDER TEST holds K_ts and runs in
 *                                           `attachment_model: wrapper`, as a child process.
 *   P   P/book/1 { K_alice } 1-of-1        Alice's own book.
 *       P/id/1   2-of-2 { → P/book , → T/book }   Alice's wrapper, built in step 2.
 *   O   O/book/1 { K_org }, then 2-of-2 { K_org , → P/id }    The org, and a data account it governs.
 *   Q   (step 7) Bob, with Q/id the same shape; O/book/1 becomes 3-of-3.
 *   Z   (step 9) a subscriber whose book name sorts BEFORE T's — the UpdateKey re-index question.
 *
 * T is named so its book sorts before P's and Q's (lowercase URL order): the signer's wrapper check
 * requires Trust Stamp's entry to be every wrapper page's FIRST entry (see src/delegation/wrapper.ts for
 * why), and refuses a wrapper that does not satisfy it.
 *
 * What it proves, each as an assertion observed on chain (evidence in scripts/verify/out/):
 *   2  wrapper creation co-signed DIRECTLY as a new owner; the result is a valid 2-of-2; registry active.
 *   3  seat attach co-signed through [P/id/1]; the registry records the seat only after execution.
 *   4  a two-hop vote: discovered on P/id's pending list (and NOT on Trust Stamp's page or book), voted
 *      with hops [P/id/1, O/book/1], executed; read back outermost-first, with the evidence digest in `data`.
 *   5  Trust Stamp is mandatory: denied by the engine, the transaction stays pending.
 *   6  (optional) the reversed delegator order is refused or counts toward nothing.
 *   7  (optional) Alice AND Bob: one transaction, two Trust Stamp votes on two paths, executed.
 *   9  (optional, not in the runbook) the UpdateKey re-index bypass, attempted on a wrapper the signer
 *      would refuse: does the network let a 2-of-2 pass without Trust Stamp?
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/wrapper-two-hop.ts
 *   SKIP_OPTIONAL=1 to run steps 1-5 only.
 */
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { LocalSigner } from '../../src/signer/signer.js';
import { DirectVoteBackend } from '../../src/vote/backend.js';
import { singleKeyring } from '../../src/signer/keyring.js';
import { readPage } from '../../src/ops/rotate.js';
import { chainWrapperReader, checkWrapper } from '../../src/delegation/wrapper.js';
import { buildPreimage, buildDelegatedSignatureObject, buildSigMetaHash, buildSubmitEnvelope, bytesToHex, computeTimestamp, hexToBytes } from '../../src/accumulate/signing.js';
import {
  ENDPOINT, raw, core, S, sha, sleep, submit, fundLite, createOrg, createPrincipal, query, waitForAccount, waitForCredits, ed, spawnDaemon, kill,
} from './_lib.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
const logger = pino({ level: 'warn' });
const line = (s = '') => console.log(s);
const OPTIONAL = process.env.SKIP_OPTIONAL !== '1';
const POLL_S = 6;

const evidence: any = { endpoint: ENDPOINT, startedAt: new Date().toISOString(), world: {}, txids: {}, queries: {}, assertions: [] as any[] };
const assert = (step: string, what: string, pass: boolean, detail?: unknown) => {
  evidence.assertions.push({ step, what, pass, ...(detail !== undefined ? { detail } : {}) });
  line(`      ${pass ? '✅' : '❌'} ${what}${detail !== undefined && !pass ? `  — ${JSON.stringify(detail).slice(0, 300)}` : ''}`);
  return pass;
};
const digestFor = (txHash: string) => createHash('sha256').update(`wrapper-two-hop|${txHash}`).digest('hex');

/** tx status at its principal: delivered | pending | expired | failed | missing */
async function status(hash: string, principal: string): Promise<string> {
  const r: any = await query(`acc://${hash}@${principal.replace(/^acc:\/\//, '')}`).catch((e: Error) => ({ __err: e.message }));
  if (r?.__err) return /not found/i.test(r.__err) ? 'missing' : 'unknown';
  const s = String(r?.status ?? '');
  if (/delivered/i.test(s)) return 'delivered';
  if (/expired/i.test(s)) return 'expired';
  if (/fail|error|reject/i.test(s)) return 'failed';
  return s || 'pending';
}
async function waitStatus(hash: string, principal: string, want: string[], seconds: number): Promise<string> {
  let s = '';
  for (let i = 0; i < seconds / 3; i++) { s = await status(hash, principal); if (want.includes(s)) return s; await sleep(3000); }
  return s;
}
/** The pending list of an account, raw, and whether it holds this hash. */
async function pendingList(account: string): Promise<{ raw: unknown; hashes: string[] }> {
  const r: any = await query(account, { queryType: 'pending', range: { expand: true } }).catch((e: Error) => ({ error: e.message }));
  const hashes = ((r?.records ?? []) as any[]).map((x) => String(x?.id ?? x?.value?.id ?? '').replace(/^acc:\/\//, '').split('@')[0]!.toLowerCase());
  return { raw: r, hashes };
}

/** Initiate a transaction on `page` with an Ed25519 key. Returns the hash. */
async function initiate(tx: any, page: string, key: ReturnType<typeof ed>, label: string): Promise<string> {
  const v = (await raw.getSignerInfo(page)).version;
  const txid = await submit(tx, S.Signer.forPage(page, key.key).withVersion(v), label);
  return txid.replace(/^acc:\/\//, '').split('@')[0]!.toLowerCase();
}
/** Co-sign an existing pending tx with a key on `page`, through `hops` (hop order), via the product's own vote path. */
async function cosign(seed: Uint8Array, page: string, txHash: string, principal: string, hops: string[], label: string): Promise<void> {
  let p: any;
  for (let i = 0; i < 20; i++) { p = await raw.getPendingTx(txHash, principal); if (p.found) break; await sleep(2000); }
  if (!p?.found) throw new Error(`${label}: ${txHash} not readable at ${principal}`);
  const info = await raw.getSignerInfo(page);
  const res = await new DirectVoteBackend(raw as any, singleKeyring(new LocalSigner(seed), page), logger, hops.length ? { delegators: hops } : {})
    .cast({ txHash, signerUrl: page, signerVersion: info.version, rawTransaction: p.rawTransaction, lastUsedOn: info.lastUsedOn, account: principal }, 'approve');
  if (!res.ok) throw new Error(`${label}: ${res.error}`);
}

/** Every key signature recorded at `account`'s partition for a tx, unwrapped: inner signer, hops, outer-first delegators, data. */
async function keySignaturesAt(hash: string, account: string): Promise<any[]> {
  const r: any = await query(`acc://${hash}@${account.replace(/^acc:\/\//, '')}`).catch(() => undefined);
  const out: any[] = [];
  const walk = (n: any, d = 0) => {
    if (!n || typeof n !== 'object' || d > 10) return;
    if (Array.isArray(n)) { n.forEach((c) => walk(c, d + 1)); return; }
    const s = n?.message?.signature;
    if (s && typeof s === 'object') {
      let inner = s; const outer: string[] = [];
      while (inner?.type === 'delegated') { outer.push(String(inner.delegator)); inner = inner.signature; }
      if (inner?.publicKey) out.push({ signer: inner.signer, delegatorsOuterFirst: outer, hops: [...outer].reverse(), data: inner.data ?? null, memo: inner.memo ?? null, vote: inner.vote ?? 'accept' });
    }
    for (const k of ['records', 'signatures', 'value']) if (n[k]) walk(n[k], d + 1);
  };
  walk(r?.signatures);
  return out;
}

/** A policy engine this script controls: approve with the evidence digest, deny the hashes in `deny`. */
function startEngine(deny: Set<string>, seen: any[]): Promise<{ port: number; close: () => void }> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const r = JSON.parse(Buffer.concat(chunks).toString() || '{}');
      seen.push({ txHash: r.txHash, wrapper: r.wrapper, attachmentKind: r.attachmentKind, account: r.account });
      const d = deny.has(String(r.txHash))
        ? { decision: 'deny', reason: 'step 5: the live check failed' }
        : { decision: 'approve', reason: 'live check passed', evidence: { signatureData: digestFor(String(r.txHash)), signatureMemo: 'wrapper-two-hop live check' } };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(d));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() })));
}

async function admin(port: number, method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { 'x-api-key': 'wrapper-two-hop-admin', 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const t = await res.text();
  return { status: res.status, json: t ? JSON.parse(t) : undefined };
}

/** Build a wrapper: P/id with a temporary key, then one UpdateKeyPage (adds, threshold, temp key out). */
async function createWrapperBook(f: any, person: { adi: string; book: string; page: string; key: ReturnType<typeof ed> }) {
  const temp = ed(0x5e);
  const wBook = `${person.adi}/id`, wPage = `${wBook}/1`;
  await initiate(new core.Transaction({ header: { principal: person.adi }, body: { type: 'createKeyBook', url: wBook, publicKeyHash: sha(temp.pub) } }), person.page, person.key, `createKeyBook ${wBook}`);
  await waitForAccount(wPage, `${wBook} page`);
  await submit(new core.Transaction({ header: { principal: f.fLta }, body: { type: 'addCredits', recipient: wPage, amount: '90000', oracle: f.oracle } }), S.Signer.forLite(f.funding.key), `credits ${wPage}`);
  await waitForCredits(wPage, `${wBook} page`);
  return { wBook, wPage, temp };
}
function creationBody(personBook: string, tBook: string, temp: ReturnType<typeof ed>) {
  return {
    type: 'updateKeyPage', operation: [
      { type: 'add', entry: { delegate: personBook } },
      { type: 'add', entry: { delegate: tBook } },
      { type: 'setThreshold', threshold: 2 },
      { type: 'remove', entry: { keyHash: sha(temp.pub) } },
    ],
  };
}


/**
 * Step 9 (optional; not in the runbook): the UpdateKey re-index question, on a wrapper the signer refuses.
 * Runs with the signer's key T but without the signer: the script co-signs as T itself.
 */
async function bypassStep(f: any, T: { adi: string; book: string; page: string; key: ReturnType<typeof ed> }, control = false) {
  const ts = Date.now();
  const step = control ? '9c' : '9';
  const label = control ? 'CONTROL: subscriber sorts AFTER Trust Stamp' : 'subscriber sorts BEFORE Trust Stamp';
  // ── 9. the UpdateKey re-index question ──────────────────────────────────────────────────────────
    line(`
[${step}] The UpdateKey re-index (${label})…`);
    const Z = await createOrg(f, control ? `acc://z${ts}.acme` : `acc://a0${ts}.acme`, 0x75, '200000');
    assert(step, `the subscriber sorts ${control ? 'after' : 'before'} Trust Stamp (${Z.book} vs ${T.book})`, control ? Z.book.toLowerCase() > T.book.toLowerCase() : Z.book.toLowerCase() < T.book.toLowerCase());
    const WZ = await createWrapperBook(f, Z);
    // The signer under test REFUSES this wrapper (Trust Stamp would not be the first entry), so the
    // script co-signs its creation as T itself — it holds K_ts because it generated it.
    const zCreate = await initiate(new core.Transaction({ header: { principal: WZ.wPage }, body: creationBody(Z.book, T.book, WZ.temp) }), WZ.wPage, WZ.temp, 'Z wrapper creation');
    await cosign(Z.key.seed, Z.page, zCreate, WZ.wPage, [], 'Z as new owner');
    await cosign(T.key.seed, T.page, zCreate, WZ.wPage, [], 'T as new owner (by the script)');
    assert(step, 'the Z wrapper is created 2-of-2', (await waitStatus(zCreate, WZ.wPage, ['delivered', 'failed', 'expired'], 120)) === 'delivered');
    const zBefore = await readPage(raw as any, WZ.wPage);
    evidence.queries[control ? 'controlWrapperBefore' : 'zWrapperBefore'] = zBefore;
    const zCheck = await checkWrapper(chainWrapperReader(raw as any), WZ.wBook, T.book);
    assert(step, control ? 'the signer check ACCEPTS this wrapper' : 'the signer check refuses this wrapper', control ? zCheck.ok : !zCheck.ok, zCheck);
    // A data account governed only by the Z wrapper. Naming WZ as its authority needs WZ's own approval,
    // which is Z's and T's votes through [WZ/1] (the script holds both keys).
    const zData = `${Z.adi}/zdata`;
    const mk = await initiate(new core.Transaction({ header: { principal: Z.adi }, body: { type: 'createDataAccount', url: zData, authorities: [WZ.wBook] } }), Z.page, Z.key, 'zdata');
    await cosign(Z.key.seed, Z.page, mk, Z.adi, [WZ.wPage], 'Z approves zdata through WZ').catch((e) => line(`      (${(e as Error).message})`));
    await cosign(T.key.seed, T.page, mk, Z.adi, [WZ.wPage], 'T approves zdata through WZ').catch((e) => line(`      (${(e as Error).message})`));
    await waitForAccount(zData, 'zdata');
    const X = await initiate(new core.Transaction({ header: { principal: zData }, body: { type: 'writeData', entry: { type: 'doubleHash', data: [Buffer.from('x').toString('hex')] } } }), Z.page, Z.key, 'X on zdata').catch((e) => { evidence.queries.zX = String(e); return ''; });
    if (X) {
      evidence.txids[control ? 'controlX' : 'bypassX'] = `${X}@${zData}`;
      await cosign(Z.key.seed, Z.page, X, zData, [WZ.wPage], 'Z votes on X through the wrapper (first time)');
      await sleep(10000);
      const mid = await status(X, zData);
      assert(step, 'after one vote X is pending (the 2-of-2 wrapper needs a second entry)', mid !== 'delivered', mid);
      // Z's book alone runs UpdateKey on the wrapper page: its entry gains a key hash and re-sorts.
      // UpdateKey looks its delegate up by the INITIATOR's page (chain/update_key.go:27-44, :92-140): the
      // initiator is Z's key signing DIRECTLY on Z/book/1, so Z/book votes straight at the principal as
      // the delegate whose entry is updated. (A first attempt initiated it through [WZ/1]; that routes
      // Z/book's vote to the wrapper page instead, and the transaction waits forever.)
      const newKey = ed(0x76);
      const ukHash = await initiate(new core.Transaction({ header: { principal: WZ.wPage }, body: { type: 'updateKey', newKeyHash: sha(newKey.pub) } }), Z.page, Z.key, 'UpdateKey by the subscriber alone');
      evidence.txids[control ? 'controlUpdateKey' : 'updateKey'] = `${ukHash}@${WZ.wPage}`;
      const ukState = await waitStatus(ukHash, WZ.wPage, ['delivered', 'failed', 'expired'], 90);
      evidence.queries[control ? 'controlUpdateKeyState' : 'updateKeyState'] = ukState;
      line(`      UpdateKey: ${ukState}`);
      await sleep(15000);
      const zAfter = await readPage(raw as any, WZ.wPage);
      evidence.queries[control ? 'controlWrapperAfter' : 'zWrapperAfterUpdateKey'] = zAfter;
      const ukRan = zAfter.version === zBefore.version && JSON.stringify(zAfter.entries) !== JSON.stringify(zBefore.entries);
      assert(step, 'UpdateKey by the subscriber alone changed the page without a version bump', ukRan, { before: zBefore, after: zAfter });
      if (ukRan) {
        await cosign(Z.key.seed, Z.page, X, zData, [WZ.wPage], 'Z votes on X again');
        const end = await waitStatus(X, zData, ['delivered', 'failed', 'expired'], 60);
        evidence.queries[control ? 'controlOutcome' : 'bypassOutcome'] = end;
        line(`      X after the second vote: ${end}  ${end === 'delivered' ? '(2-of-2 met WITHOUT Trust Stamp)' : '(still needs Trust Stamp)'}`);
        evidence[control ? 'control' : 'bypass'] = { delivered: end === 'delivered', state: end };
        if (control) assert(step, 'with Trust Stamp first, the re-vote does NOT pass the wrapper without it', end !== 'delivered', end);
      }
    }
}

async function main() {
  const ts = Date.now();
  line('\n════════════════════════════════════════════════════════════════════');
  line('  WRAPPER DELEGATE — two hops, on a live network');
  line('════════════════════════════════════════════════════════════════════\n');
  line(`  network: ${ENDPOINT}\n`);

  if (process.env.ONLY_BYPASS === '1') {
    line('[9 only] Provisioning T and a subscriber that sorts before it…');
    const f9 = await fundLite();
    const T9 = await createOrg(f9, `acc://a${ts}ts.acme`, 0x71, '200000');
    evidence.world = { T: T9.book, only: 'step 9' };
    try { await bypassStep(f9, T9); await bypassStep(f9, T9, true); } finally {
      evidence.finishedAt = new Date().toISOString();
      mkdirSync('scripts/verify/out', { recursive: true });
      const out = `scripts/verify/out/wrapper-two-hop-bypass-${ts}.json`;
      writeFileSync(out, JSON.stringify(evidence, null, 2) + '\n');
      line(`\n  evidence: ${out}`);
    }
    process.exit(0);
  }

  // ── 1. world ────────────────────────────────────────────────────────────────────────────────────
  line('[1] Provisioning T (Trust Stamp), P (Alice), O (the org) from the faucet…');
  const f = await fundLite();
  const T = await createOrg(f, `acc://a${ts}ts.acme`, 0x71, '200000');
  const P = await createOrg(f, `acc://p${ts}.acme`, 0x72, '200000');
  const O = await createPrincipal(f, `acc://o${ts}.acme`, 0x73, '200000');
  evidence.world = { T: T.book, P: P.book, O: O.book, oData: O.dataAccount };
  line(`      T ${T.page}\n      P ${P.page}\n      O ${O.page}  data ${O.dataAccount}`);
  assert('1', `Trust Stamp's book sorts before Alice's (${T.book} < ${P.book})`, T.book.toLowerCase() < P.book.toLowerCase());

  // The signer under test.
  const deny = new Set<string>();
  const asked: any[] = [];
  const engine = await startEngine(deny, asked);
  const dir = mkdtempSync(join(tmpdir(), 'wrapper-two-hop-'));
  const healthPort = 18000 + (ts % 1000);
  const cfgPath = join(dir, 'signer.yaml');
  writeFileSync(cfgPath,
`wallet: { org_id: "trust-stamp-${ts}", accumulate_endpoints: ["${ENDPOINT}"], signer_url: "${T.page}", attachment_model: "wrapper" }
signer: { provider: "local", local: { seed_hex: "${Buffer.from(T.key.seed).toString('hex')}" } }
policy: { url: "http://127.0.0.1:${engine.port}/decision", mode: "sync", auth: "none", timeout_ms: 4000 }
trigger: { webhook: { enabled: false }, poller: { enabled: true, interval_seconds: ${POLL_S} } }
behavior: { submit_reject_vote: false, require_signature_data: true }
store: { path: "${join(dir, 'state.json').replace(/\\/g, '/')}" }
admin: { api_key: "wrapper-two-hop-admin" }
health: { bind: "127.0.0.1:${healthPort}" }
observability: { log_level: "info" }
`);
  const log: string[] = [];
  const signer = spawnDaemon(cfgPath, log);
  evidence.signerConfig = cfgPath;
  try {
    for (let i = 0; i < 40; i++) { await sleep(1500); const h = await fetch(`http://127.0.0.1:${healthPort}/healthz`).catch(() => undefined); if (h) break; }
    line('      signer under test is up (wrapper mode, push disabled, wrapper source on)\n');

    // ── 2. wrapper creation ─────────────────────────────────────────────────────────────────────────
    line('[2] Wrapper creation: P/id with a temporary key, then one UpdateKeyPage…');
    const W = await createWrapperBook(f, P);
    const reg = await admin(healthPort, 'POST', '/v1/admin/wrappers', { wrapper_book: W.wBook, subject_id: 'alice', subscriber_book: P.book });
    assert('2', 'the wrapper is registered as ENROLLING', reg.status === 201 && reg.json?.wrapper?.status === 'enrolling', reg);
    // The naming rule, at registration: a subscriber book that sorts before Trust Stamp's is refused there.
    const early = await admin(healthPort, 'POST', '/v1/admin/wrappers', { wrapper_book: `acc://a0${ts}.acme/id`, subject_id: 'eve', subscriber_book: `acc://a0${ts}.acme/book` });
    assert('2', 'a subscriber book sorting before the Trust Stamp book is refused at registration (422 wrapper_order)', early.status === 422 && early.json?.error === 'wrapper_order', early);
    const createTx = await initiate(new core.Transaction({ header: { principal: W.wPage }, body: creationBody(P.book, T.book, W.temp) }), W.wPage, W.temp, 'wrapper creation');
    evidence.txids.wrapperCreate = `${createTx}@${W.wPage}`;
    line(`      creation tx ${createTx}`);
    await cosign(P.key.seed, P.page, createTx, W.wPage, [], 'Alice as new owner (direct)');
    line('      Alice signed as new owner; waiting for the signer to co-sign directly as new owner of T/book…');
    const created = await waitStatus(createTx, W.wPage, ['delivered', 'failed', 'expired'], 150);
    assert('2', 'the wrapper creation executes', created === 'delivered', created);
    const wp = await readPage(raw as any, W.wPage);
    evidence.queries.wrapperPageAfterCreate = wp;
    const dels = wp.entries.map((e) => (e.delegate ?? '').toLowerCase()).sort();
    assert('2', 'P/id/1 is 2-of-2 with exactly → P/book and → T/book', wp.threshold === 2 && wp.entries.length === 2 && JSON.stringify(dels) === JSON.stringify([P.book, T.book].map((x) => x.toLowerCase()).sort()), wp);
    const chk = await checkWrapper(chainWrapperReader(raw as any), W.wBook, T.book);
    assert('2', 'the Phase 5 wrapper check passes on the live wrapper', chk.ok, chk);
    const ourCreateSig = (await keySignaturesAt(createTx, T.page)).find((s) => String(s.signer).toLowerCase() === T.page.toLowerCase());
    assert('2', 'our creation vote was DIRECT (no delegators)', !!ourCreateSig && ourCreateSig.hops.length === 0, ourCreateSig);
    let active = false;
    for (let i = 0; i < 20 && !active; i++) { await sleep(3000); active = (await admin(healthPort, 'GET', '/v1/admin/wrappers')).json?.wrappers?.some((e: any) => e.wrapperBook.toLowerCase() === W.wBook.toLowerCase() && e.status !== 'enrolling'); }
    assert('2', 'the registry made the wrapper ACTIVE after execution', active);

    // ── 3. seat attach ──────────────────────────────────────────────────────────────────────────────
    line('\n[3] Seat attach: O/book/1 adds → P/id and goes 2-of-2…');
    await admin(healthPort, 'POST', '/v1/admin/pause');   // so the "not before execution" check sees a pending tx
    const seatTx = await initiate(new core.Transaction({ header: { principal: O.page }, body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: W.wBook } }, { type: 'setThreshold', threshold: 2 }] } }), O.page, O.key, 'seat attach');
    evidence.txids.seatAttach = `${seatTx}@${O.page}`;
    await cosign(P.key.seed, P.page, seatTx, O.page, [W.wPage], 'Alice through [P/id/1]');
    await sleep(POLL_S * 2000);
    const seatPending = await status(seatTx, O.page);
    const regMid = (await admin(healthPort, 'GET', '/v1/admin/wrappers')).json?.wrappers?.find((e: any) => e.wrapperBook.toLowerCase() === W.wBook.toLowerCase());
    assert('3', 'while the seat attach is pending, the registry has NO seat', seatPending !== 'delivered' && (regMid?.seats ?? []).length === 0, { seatPending, seats: regMid?.seats });
    await admin(healthPort, 'POST', '/v1/admin/resume');
    const seated = await waitStatus(seatTx, O.page, ['delivered', 'failed', 'expired'], 150);
    assert('3', 'the seat attach executes', seated === 'delivered', seated);
    const ourSeatSig = (await keySignaturesAt(seatTx, T.page)).find((s) => String(s.signer).toLowerCase() === T.page.toLowerCase());
    assert('3', 'our seat-attach vote went through [P/id/1]', JSON.stringify(ourSeatSig?.hops) === JSON.stringify([W.wPage]), ourSeatSig);
    let seat = false;
    for (let i = 0; i < 20 && !seat; i++) { await sleep(3000); seat = (await admin(healthPort, 'GET', '/v1/admin/wrappers')).json?.wrappers?.some((e: any) => e.wrapperBook.toLowerCase() === W.wBook.toLowerCase() && e.seats?.some((s: any) => s.orgPage.toLowerCase() === O.page.toLowerCase())); }
    assert('3', 'the registry recorded the seat after execution', seat);

    // ── 4. the two-hop vote ─────────────────────────────────────────────────────────────────────────
    line('\n[4] The two-hop vote: K_org writes to O/data; Alice signs through [P/id/1, O/book/1]…');
    await admin(healthPort, 'POST', '/v1/admin/pause');   // hold the signer so the pending lists can be read first
    const writeTx = async (label: string) => initiate(new core.Transaction({ header: { principal: O.dataAccount }, body: { type: 'writeData', entry: { type: 'doubleHash', data: [Buffer.from(`${label}-${Date.now()}`).toString('hex')] } } }), O.page, O.key, label);
    const voteTx = await writeTx('two-hop');
    evidence.txids.twoHop = `${voteTx}@${O.dataAccount}`;
    await cosign(P.key.seed, P.page, voteTx, O.dataAccount, [W.wPage, O.page], 'Alice two-hop');
    await sleep(8000);
    const onWrapper = await pendingList(W.wBook);
    const onTsPage = await pendingList(T.page);
    const onTsBook = await pendingList(T.book);
    evidence.queries.pendingOnWrapperBook = onWrapper.raw;
    evidence.queries.pendingOnTsPage = onTsPage.raw;
    evidence.queries.pendingOnTsBook = onTsBook.raw;
    assert('4', "the tx IS on P/id's pending list", onWrapper.hashes.includes(voteTx), onWrapper.hashes);
    assert('4', "the tx is NOT on T/book/1's pending list", !onTsPage.hashes.includes(voteTx), onTsPage.hashes);
    assert('4', "the tx is NOT on T/book's pending list", !onTsBook.hashes.includes(voteTx), onTsBook.hashes);
    await admin(healthPort, 'POST', '/v1/admin/resume');
    const voted = await waitStatus(voteTx, O.dataAccount, ['delivered', 'failed', 'expired'], 150);
    assert('4', 'the two-hop transaction EXECUTES', voted === 'delivered', voted);
    const rows = (await admin(healthPort, 'GET', '/v1/requests?limit=50')).json?.requests ?? [];
    const row = rows.map((r: any) => r.request).find((r: any) => r.txHash === voteTx);
    evidence.queries.signerRow = row;
    assert('4', 'the signer found it through the wrapper (principal from the pending txID, path from P/id)', !!row && row.principal?.toLowerCase() === O.dataAccount.toLowerCase() && JSON.stringify(row.delegators) === JSON.stringify([W.wPage, O.page]), row);
    const metrics = await fetch(`http://127.0.0.1:${healthPort}/metrics`, { headers: { 'x-api-key': 'wrapper-two-hop-admin' } }).then((r) => r.text()).catch(() => '');
    const hits = Number(/^wallet_wrapper_hits_total (\d+)/m.exec(metrics)?.[1] ?? 0);
    assert('4', 'discovery counted hits on wrapper books', hits > 0, { hits });
    const ours = (await keySignaturesAt(voteTx, T.page)).filter((s) => String(s.signer).toLowerCase() === T.page.toLowerCase());
    evidence.queries.ourTwoHopSignature = ours;
    assert('4', 'it voted with hops [P/id/1, O/book/1]', ours.some((s) => JSON.stringify(s.hops.map((h: string) => h.toLowerCase())) === JSON.stringify([W.wPage, O.page].map((h) => h.toLowerCase()))), ours);
    assert('4', 'read back, our delegators are outermost first [O/book/1, P/id/1]', ours.some((s) => JSON.stringify(s.delegatorsOuterFirst.map((h: string) => h.toLowerCase())) === JSON.stringify([O.page, W.wPage].map((h) => h.toLowerCase()))), ours);
    assert('4', "the signature's data equals the supplied digest", ours.some((s) => String(s.data).toLowerCase() === digestFor(voteTx)), { want: digestFor(voteTx), got: ours.map((s) => s.data) });

    // ── 5. Trust Stamp is mandatory ─────────────────────────────────────────────────────────────────
    line('\n[5] A second transaction the engine DENIES; Alice signs…');
    const deniedTx = await writeTx('denied');
    deny.add(deniedTx);
    evidence.txids.denied = `${deniedTx}@${O.dataAccount}`;
    await cosign(P.key.seed, P.page, deniedTx, O.dataAccount, [W.wPage, O.page], 'Alice on the denied tx');
    await sleep(POLL_S * 1000 * 5);
    const deniedState = await status(deniedTx, O.dataAccount);
    assert('5', 'it stays pending past a full poll window (O/book/1 cannot complete without Trust Stamp)', deniedState !== 'delivered', deniedState);
    assert('5', 'the engine was asked and denied it', asked.some((a) => a.txHash === deniedTx));
    const tsOnDenied = (await keySignaturesAt(deniedTx, T.page)).filter((s) => String(s.signer).toLowerCase() === T.page.toLowerCase());
    assert('5', 'Trust Stamp cast no vote on it', tsOnDenied.length === 0, tsOnDenied);

    // ── 6. the reversed-order bug is real ───────────────────────────────────────────────────────────
    if (OPTIONAL) {
      line('\n[6] A Trust Stamp vote with the hops NOT reversed, on the denied tx…');
      const p = await raw.getPendingTx(deniedTx, O.dataAccount);
      const info = await raw.getSignerInfo(T.page);
      const k = new LocalSigner(T.key.seed);
      const pre = buildPreimage(hexToBytes(deniedTx), { publicKey: await k.publicKey(), signerUrl: T.page, signerVersion: info.version, timestamp: computeTimestamp(info.lastUsedOn, Date.now() * 1000), vote: 'approve', delegators: [O.page, W.wPage] });
      const sigObj = buildDelegatedSignatureObject(pre, await k.sign(pre.dataForSignature), deniedTx);
      const res = await raw.submit(buildSubmitEnvelope(p.rawTransaction, sigObj));
      evidence.queries.reversedSubmit = res;
      await sleep(20000);
      const after = await status(deniedTx, O.dataAccount);
      assert('6', 'the reversed order is refused or counts toward nothing (the tx stays pending)', after !== 'delivered', { submit: res, after });
      line(`      submit: ${JSON.stringify(res).slice(0, 300)}`);
    }

    // ── 7. Alice and Bob ────────────────────────────────────────────────────────────────────────────
    if (OPTIONAL) {
      line('\n[7] Bob: Q/id, seated on O/book/1, which becomes 3-of-3…');
      const Q = await createOrg(f, `acc://q${ts}.acme`, 0x74, '200000');
      const WQ = await createWrapperBook(f, Q);
      await admin(healthPort, 'POST', '/v1/admin/wrappers', { wrapper_book: WQ.wBook, subject_id: 'bob', subscriber_book: Q.book });
      const qCreate = await initiate(new core.Transaction({ header: { principal: WQ.wPage }, body: creationBody(Q.book, T.book, WQ.temp) }), WQ.wPage, WQ.temp, 'Q wrapper creation');
      await cosign(Q.key.seed, Q.page, qCreate, WQ.wPage, [], 'Bob as new owner');
      assert('7', "Bob's wrapper creation executes", (await waitStatus(qCreate, WQ.wPage, ['delivered', 'failed', 'expired'], 150)) === 'delivered');
      for (let i = 0; i < 20; i++) { await sleep(3000); if ((await admin(healthPort, 'GET', '/v1/admin/wrappers')).json?.wrappers?.some((e: any) => e.wrapperBook.toLowerCase() === WQ.wBook.toLowerCase() && e.status !== 'enrolling')) break; }
      // Seating Bob needs the page's CURRENT 2-of-2 (K_org + Alice's wrapper) AND Bob's wrapper as new owner.
      const qSeat = await initiate(new core.Transaction({ header: { principal: O.page }, body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: WQ.wBook } }, { type: 'setThreshold', threshold: 3 }] } }), O.page, O.key, 'seat Bob');
      await cosign(P.key.seed, P.page, qSeat, O.page, [W.wPage, O.page], 'Alice approves seating Bob');
      await cosign(Q.key.seed, Q.page, qSeat, O.page, [WQ.wPage], 'Bob as new owner through [Q/id/1]');
      assert('7', 'seating Bob executes (Trust Stamp on two paths: [P/id/1, O/book/1] and [Q/id/1])', (await waitStatus(qSeat, O.page, ['delivered', 'failed', 'expired'], 180)) === 'delivered');
      const both = await writeTx('alice-and-bob');
      evidence.txids.aliceAndBob = `${both}@${O.dataAccount}`;
      await cosign(P.key.seed, P.page, both, O.dataAccount, [W.wPage, O.page], 'Alice');
      await cosign(Q.key.seed, Q.page, both, O.dataAccount, [WQ.wPage, O.page], 'Bob');
      const bothState = await waitStatus(both, O.dataAccount, ['delivered', 'failed', 'expired'], 180);
      const tsVotes = (await keySignaturesAt(both, T.page)).filter((s) => String(s.signer).toLowerCase() === T.page.toLowerCase());
      evidence.queries.aliceAndBobOurVotes = tsVotes;
      const paths = new Set(tsVotes.map((s) => s.hops.join('>').toLowerCase()));
      assert('7', 'one transaction got TWO Trust Stamp votes on two paths', paths.has([W.wPage, O.page].join('>').toLowerCase()) && paths.has([WQ.wPage, O.page].join('>').toLowerCase()), [...paths]);
      assert('7', 'and executed', bothState === 'delivered', bothState);
    }

    if (OPTIONAL) { await bypassStep(f, T); await bypassStep(f, T, true); }
  } finally {
    kill(signer);
    engine.close();
    evidence.finishedAt = new Date().toISOString();
    evidence.signerLogTail = log.join('').split('\n').filter((l) => /wrapper|vote|refus|denied|settle|seat|error/i.test(l)).slice(-200);
    evidence.engineRequests = asked;
    mkdirSync('scripts/verify/out', { recursive: true });
    const out = `scripts/verify/out/wrapper-two-hop-${ts}.json`;
    writeFileSync(out, JSON.stringify(evidence, null, 2) + '\n');
    line(`\n  evidence: ${out}`);
  }

  const required = evidence.assertions.filter((a: any) => ['1', '2', '3', '4', '5'].includes(a.step));
  const failed = evidence.assertions.filter((a: any) => !a.pass);
  line('\n════════════════════════════════════════════════════════════════════');
  line(`  ${required.every((a: any) => a.pass) ? '✅ all required assertions observed' : '❌ a required assertion FAILED'}   (${evidence.assertions.length - failed.length}/${evidence.assertions.length} passed)`);
  line('════════════════════════════════════════════════════════════════════\n');
  process.exit(required.every((a: any) => a.pass) ? 0 : 1);
}

main().catch((e) => { console.error('\n❌ error:', (e as Error).stack ?? (e as Error).message); process.exit(1); });
