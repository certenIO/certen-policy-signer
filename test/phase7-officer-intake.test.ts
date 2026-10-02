/**
 * Phase 7 personal signing: display + tcl-summary/v1, officer authentication, officer intake, proposals,
 * delegate consent, intake-only boot. FICTIONAL Business Transaction Controls lab.
 *
 * Every key here is generated inside the test by WebCrypto as NON-EXTRACTABLE and lives only in memory; no key
 * material is committed. Every party, page and credential string is FICTIONAL.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { createHash, verify as nodeVerify, createPublicKey, webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { p256 } from '@noble/curves/nist.js';
import { tclSummaryV1, buildDisplay, buildProposalDisplay, awaitingGovernanceRequest, withDisplay } from '../src/display.js';
import { createOfficerIntake, OfficerIntake, IntakeChain, PREPARE_TTL_MS } from '../src/officer/intake.js';
import { officerAuthMessage } from '../src/officer/auth.js';
import { createRelayClientsHandler } from '../src/relay-clients.js';
import { createServer } from '../src/server.js';
import { MemoryStore, FileStore, humanRecordId } from '../src/store/store.js';
import { buildSigMetaHash, concatBytes, bytesToHex, hexToBytes } from '../src/accumulate/signing.js';
import { core } from '../src/accumulate/sdk.js';
import { loadConfig, isIntakeOnly } from '../src/config.js';
import { startIntakeOnly } from '../src/intake-only.js';
import type { PageState } from '../src/ops/rotate.js';
import type { KeyPageResult } from '../src/ops/keypage.js';
import type { PolicyRequest } from '../src/types.js';
import { advanceAwaitingHuman } from '../src/officer/landed.js';
import { Orchestrator } from '../src/orchestrator.js';
import { Resolver } from '../src/resolver.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { noKeyKeyring } from '../src/signer/keyring.js';
import type { AccumulateClient } from '../src/accumulate/client.js';

const silent = pino({ level: 'silent' });
const subtle = webcrypto.subtle;
const VECTORS = JSON.parse(readFileSync(new URL('./fixtures/phase7-summary-vectors.json', import.meta.url), 'utf8'));

/* ------------------------------------------------------------------ */
/* §2 display and tcl-summary/v1                                       */
/* ------------------------------------------------------------------ */

describe('tcl-summary/v1', () => {
  for (const v of VECTORS.vectors) {
    it(`matches vector ${v.name}`, () => {
      expect(tclSummaryV1(v.display)).toBe(v.summaryHash);
    });
  }
  it('refuses a malformed pair', () => {
    expect(() => tclSummaryV1([['a'] as unknown as [string, string]])).toThrow();
  });
});

describe('display', () => {
  const REF = '0x' + '89873a08'.repeat(8);
  it('payment: Principal, Body type, then Payer, Payee, Amount with symbol, Instruction hash, Chain, Target', () => {
    const pr: PolicyRequest = {
      requestId: 'r', txHash: 'aa'.repeat(32), account: 'acc://harbor-mfg-tcl1.acme/data', actionSummary: 'x', expiresAt: 'z', bodyType: 'writeData',
      calldataDecoded: [{ legIndex: 0, chainId: 84532, target: '0x2d9e724de974a81e97ee553b3482cafa6d5fe46b', abi: 'FDBUSD', function: 'transferWithReference', signature: 's', args: { to: '0xe66e6f40f1d7a1c06abace493f38c03800ac565a', amount: '300000', paymentRef: REF } }],
      assets: [{ legIndex: 0, chain: 'base-sepolia', chainId: 84532, token: '0x2d9e724de974a81e97ee553b3482cafa6d5fe46b', symbol: 'FDBUSD', decimals: 2 }],
    };
    const d = buildDisplay(pr, { labels: { 'acc://harbor-mfg-tcl1.acme': 'Harbor Manufacturing (FICTIONAL)' } });
    expect(d).toEqual([
      ['Principal', 'acc://harbor-mfg-tcl1.acme/data'],
      ['Body type', 'writeData'],
      ['Payer', 'Harbor Manufacturing (FICTIONAL) (acc://harbor-mfg-tcl1.acme)'],
      ['Payee', '0xe66e6f40f1d7a1c06abace493f38c03800ac565a'],
      ['Amount', '3,000.00 FDBUSD'],
      ['Instruction hash', REF],
      ['Chain', 'base-sepolia'],
      ['Target', '0x2d9e724de974a81e97ee553b3482cafa6d5fe46b FDBUSD.transferWithReference'],
    ]);
    const w = withDisplay(pr);
    expect(w.summaryHash).toBe(tclSummaryV1(w.display!));
  });

  it('acceptance and governance pairs', () => {
    const acc = buildDisplay({ requestId: 'r', txHash: 'x', account: 'acc://c.acme/acceptances', actionSummary: '', expiresAt: '', bodyType: 'writeData', acceptance: { firm: 'acc://northfield-tcl1.acme/book', instructionHash: 'ef'.repeat(32), amount: 4250000, category: 'equipment' } });
    expect(acc.slice(2)).toEqual([['Firm', 'acc://northfield-tcl1.acme/book'], ['Instruction hash', 'ef'.repeat(32)], ['Amount', '4250000'], ['Category', 'equipment']]);
    const gov = buildProposalDisplay('acc://harbor-mfg-tcl1.acme/book/1', [{ op: 'remove-key', keyHash: 'bb'.repeat(32) }, { op: 'set-threshold', threshold: 1 }]);
    expect(gov).toEqual([
      ['Principal', 'acc://harbor-mfg-tcl1.acme/book/1'], ['Body type', 'updateKeyPage'], ['Page', 'acc://harbor-mfg-tcl1.acme/book/1'],
      ['Operation', 'remove'], ['Key hash', 'bb'.repeat(32)], ['Operation', 'setThreshold'], ['Threshold', '1'],
    ]);
  });
});

/* ------------------------------------------------------------------ */
/* fake Accumulate + officers                                          */
/* ------------------------------------------------------------------ */

const HARBOR_P1 = 'acc://harbor-mfg-tcl1.acme/book/1';
const HARBOR_P2 = 'acc://harbor-mfg-tcl1.acme/book/2';
const TREASURY_P1 = 'acc://fdb-treasury-tcl1.acme/book/1';
const ISSUANCE_P1 = 'acc://fdb-issuance-tcl1.acme/book/1';
const BOARD_P1 = 'acc://fdb-board-tcl1.acme/book/1';
const PRINCIPAL = 'acc://harbor-mfg-tcl1.acme/data';
const TX = 'c0ffee00'.repeat(8);

interface Officer { priv: webcrypto.CryptoKey; spki: Uint8Array; keyHash: string }
async function newOfficer(): Promise<Officer> {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
  return { priv: kp.privateKey, spki, keyHash: createHash('sha256').update(spki).digest('hex') };
}
/** WebCrypto: hashes once, returns 64-byte r‖s. */
async function signRaw(o: Officer, msg: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, o.priv, msg));
}
const toDer = (raw: Uint8Array) => p256.Signature.fromBytes(raw, 'compact').toBytes('der');
async function authHeader(o: Officer, method: string, path: string, ts = Date.now(), signer: Officer = o): Promise<string> {
  const sig = await signRaw(signer, officerAuthMessage(method, path, String(ts)));
  return `v1 key=${bytesToHex(o.spki)},ts=${ts},sig=${bytesToHex(toDer(sig))}`;
}

type Entry = { publicKeyHash?: string; delegate?: string };
class FakeChain implements IntakeChain {
  pages = new Map<string, { version: number; threshold: number; keys: Entry[] }>();
  pending = new Map<string, { principal: string; body: any; executed?: boolean }>();
  submitted: any[] = [];
  sigs = new Map<string, Array<{ type: string; publicKeyHash: string; delegators: string[]; signer?: string; vote?: 'approve' | 'reject' | 'abstain' }>>();
  land = true;
  readPage = async (page: string): Promise<PageState> => {
    const p = this.pages.get(page.toLowerCase());
    if (!p) throw new Error('not found');
    const entries = p.keys.map((k) => ({ keyHash: k.publicKeyHash ?? null, delegate: k.delegate ?? null }));
    return { version: p.version, threshold: p.threshold, keyHashes: entries.map((e) => e.keyHash).filter((h): h is string => !!h), entries };
  };
  async getPendingTx(hash: string, principal: string) {
    const t = this.pending.get(hash);
    if (!t || t.principal.toLowerCase() !== principal.toLowerCase()) return { found: false };
    return { found: true, principal: t.principal, body: t.body, rawTransaction: { header: { principal: t.principal }, body: t.body }, executed: t.executed };
  }
  async getSignerInfo(page: string) { return { version: this.pages.get(page.toLowerCase())?.version ?? 1, lastUsedOn: 0 }; }
  async getTxSignatures(hash: string) { return { status: 'pending', delivered: false, signatures: this.sigs.get(hash) ?? [] }; }
  async submit(envelope: any) {
    this.submitted.push(envelope);
    let s = envelope.signatures[0];
    const delegators: string[] = [];
    // Outermost first, as the chain reader (raw-client unwrapDelegation) reports them.
    while (s.type === 'delegated') { delegators.push(String(s.delegator)); s = s.signature; }
    const hash = String(s.transactionHash);
    // A newly originated transaction (a proposal) becomes pending at its principal.
    const t0 = envelope.transaction?.[0];
    if (t0?.header?.initiator && !this.pending.has(hash)) this.pending.set(hash, { principal: String(t0.header.principal), body: t0.body });
    if (this.land) {
      const list = this.sigs.get(hash) ?? [];
      list.push({ type: s.type, publicKeyHash: createHash('sha256').update(Buffer.from(s.publicKey, 'hex')).digest('hex'), delegators, signer: String(s.signer), vote: s.vote === 'reject' || s.vote === 1 ? 'reject' : 'approve' });
      this.sigs.set(hash, list);
    }
    return { ok: true };
  }
}

function listen(s: http.Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as { port: number }).port)));
}
function call(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: unknown) {
  return new Promise<{ status: number; json: any }>((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => resolve({ status: res.statusCode!, json: t ? JSON.parse(t) : null }));
    });
    r.on('error', reject);
    if (body !== undefined) r.write(typeof body === 'string' ? body : JSON.stringify(body));
    r.end();
  });
}

/** The S6 formula, verified with Node's own ECDSA (independent of the code under test's verifier). */
function s6Verifies(sigObj: any, delegators: string[] = []): boolean {
  const sigMd = buildSigMetaHash({
    publicKey: hexToBytes(sigObj.publicKey), signatureType: 'ecdsaSha256', signerUrl: String(sigObj.signer),
    signerVersion: Number(sigObj.signerVersion), timestamp: Number(sigObj.timestamp), vote: sigObj.vote === 'reject' || sigObj.vote === 1 ? 'reject' : 'approve',
    ...(delegators.length ? { delegators } : {}),
  });
  const key = createPublicKey({ key: Buffer.from(sigObj.publicKey, 'hex'), format: 'der', type: 'spki' });
  return nodeVerify('sha256', concatBytes(sigMd, hexToBytes(String(sigObj.transactionHash))), { key, dsaEncoding: 'der' }, Buffer.from(String(sigObj.signature), 'hex'));
}

const GOV_KEY = 'governance-test-key-000000';
const CONSOLE_KEY = 'harbor-console-test-key-00';
const C = { 'x-relay-client': 'harbor-console', 'x-api-key': CONSOLE_KEY };

let chain: FakeChain;
let store: MemoryStore;
let intake: OfficerIntake;
let server: http.Server;
let port = 0;
let alice: Officer, bob: Officer, tess: Officer, mallory: Officer;
const awaitingOps: KeyPageResult[] = [];

beforeAll(async () => {
  [alice, bob, tess, mallory] = await Promise.all([newOfficer(), newOfficer(), newOfficer(), newOfficer()]);
});

beforeEach(async () => {
  server?.close();
  chain = new FakeChain();
  chain.pages.set(HARBOR_P1.toLowerCase(), { version: 3, threshold: 1, keys: [{ publicKeyHash: alice.keyHash }, { publicKeyHash: bob.keyHash }, { publicKeyHash: 'bb'.repeat(32) }] });
  chain.pages.set(HARBOR_P2.toLowerCase(), { version: 1, threshold: 1, keys: [{ publicKeyHash: 'cc'.repeat(32) }] });
  chain.pages.set(TREASURY_P1.toLowerCase(), { version: 2, threshold: 1, keys: [{ publicKeyHash: tess.keyHash }] });
  chain.pages.set(ISSUANCE_P1.toLowerCase(), { version: 5, threshold: 1, keys: [{ publicKeyHash: 'dd'.repeat(32) }, { delegate: 'acc://fdb-treasury-tcl1.acme/book' }] });
  chain.pages.set(BOARD_P1.toLowerCase(), { version: 7, threshold: 2, keys: [{ publicKeyHash: alice.keyHash }, { publicKeyHash: bob.keyHash }, { publicKeyHash: 'bb'.repeat(32) }] });
  chain.pending.set(TX, { principal: PRINCIPAL, body: { type: 'writeData', entry: { type: 'doubleHash', data: ['00'] } } });
  store = new MemoryStore();
  await store.savePolicyRequest(withDisplay({ requestId: 'r1', txHash: TX, account: PRINCIPAL, actionSummary: 'FICTIONAL payment', expiresAt: '2026-09-20T00:00:00Z', bodyType: 'writeData' }));
  intake = createOfficerIntake({
    humanPages: [HARBOR_P1, TREASURY_P1, ISSUANCE_P1, BOARD_P1], chain, readPage: chain.readPage,
    getPolicyRequest: (h) => store.getPolicyRequest(h), saveAwaiting: (pr) => store.savePolicyRequest(pr), landedTimeoutMs: 150, pollIntervalMs: 10, logger: silent,
    onLanded: async (r) => { await advanceAwaitingHuman({ store, getTxSignatures: (h, p) => chain.getTxSignatures(h), readPage: chain.readPage }, r.txHash, r.authority); },
  });
  awaitingOps.length = 0;
  const relayClients = createRelayClientsHandler({
    clients: [{ name: 'harbor-console', key: CONSOLE_KEY, scopes: ['pending', 'tx', 'governance'] }], reservedKeys: [GOV_KEY],
    query: async () => { throw new Error('not found'); }, evm: [], getPolicyRequest: (h) => store.getPolicyRequest(h),
    governanceKey: GOV_KEY, pages: () => [ISSUANCE_P1], readPage: chain.readPage,
    applyKeyPageOp: async (op) => {
      const st = await chain.readPage(ISSUANCE_P1);
      const r: KeyPageResult = { ok: true, op: op.op, submitted: ['ab'.repeat(32)], before: st, after: st, awaitingConsent: true };
      awaitingOps.push(r);
      return r;
    },
    recordAwaiting: async ({ txHash, page, op }) => store.savePolicyRequest(awaitingGovernanceRequest(txHash, page, op)),
    propose: intake.propose, logger: silent,
  });
  server = createServer({ relayClients, officerIntake: intake.handle, orchestrator: {} as any, store, keyring: {} as any, accumulate: {} as any, pause: { paused: false }, logger: silent });
  port = await listen(server);
});
afterAll(() => server?.close());

/* ------------------------------------------------------------------ */
/* §3 officer auth                                                     */
/* ------------------------------------------------------------------ */

describe('officer authentication', () => {
  const path = `/relay/officer/pending/${TX}`;
  it('accepts a fresh signature by a key on a human page', async () => {
    const r = await call(port, 'GET', path, { 'x-officer-auth': await authHeader(alice, 'GET', path) });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ ref: TX, kind: 'transaction', principal: PRINCIPAL, bodyType: 'writeData', status: 'pending' });
    expect(r.json.summaryHash).toBe(tclSummaryV1(r.json.display));
  });

  it('rejects stale ts, wrong key, key not on a page, bad signature, wrong path, and a missing header — all 401 officer_auth_failed', async () => {
    const cases: Array<Record<string, string>> = [
      {},
      { 'x-officer-auth': await authHeader(alice, 'GET', path, Date.now() - 121_000) },
      { 'x-officer-auth': await authHeader(alice, 'GET', path, Date.now() + 121_000) },
      { 'x-officer-auth': await authHeader(alice, 'GET', path, Date.now(), bob) },            // header names alice, bob signed
      { 'x-officer-auth': await authHeader(mallory, 'GET', path) },                            // valid, but not on any human page
      { 'x-officer-auth': (await authHeader(alice, 'GET', path)).replace(/([0-9a-f])$/, (c) => (c === '0' ? '1' : '0')) },   // last signature nibble flipped
      { 'x-officer-auth': await authHeader(alice, 'GET', `/relay/officer/pending/${'ab'.repeat(32)}`) },
      { 'x-officer-auth': await authHeader(alice, 'POST', path) },
      { 'x-officer-auth': 'v1 key=zz,ts=1,sig=00' },
    ];
    for (const h of cases) {
      const r = await call(port, 'GET', path, h);
      expect(r).toEqual({ status: 401, json: { error: 'officer_auth_failed' } });
    }
  });

  it('accepts a raw 64-byte r‖s header signature', async () => {
    const ts = Date.now();
    const raw = await signRaw(bob, officerAuthMessage('GET', path, String(ts)));
    const r = await call(port, 'GET', path, { 'x-officer-auth': `v1 key=${bytesToHex(bob.spki)},ts=${ts},sig=${bytesToHex(raw)}` });
    expect(r.status).toBe(200);
  });
});

/* ------------------------------------------------------------------ */
/* §4 prepare → signature                                              */
/* ------------------------------------------------------------------ */

async function prepare(o: Officer, body: Record<string, unknown>) {
  const p = '/relay/officer-signature/prepare';
  return call(port, 'POST', p, { 'x-officer-auth': await authHeader(o, 'POST', p) }, body);
}
async function signPrepared(o: Officer, prep: any, format: 'raw' | 'der' = 'der') {
  const raw = await signRaw(o, concatBytes(hexToBytes(prep.sigMdHash), hexToBytes(prep.txHash)));
  return bytesToHex(format === 'der' ? toDer(raw) : raw);
}

describe('officer intake: transaction ref', () => {
  it('prepare → signature: submits one ecdsaSha256 signature that verifies with the S6 formula, then reports landed', async () => {
    const prep = await prepare(alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    expect(prep.json).toMatchObject({ txHash: TX, signerVersion: 3, principal: PRINCIPAL });
    expect(prep.json.summaryHash).toBe(tclSummaryV1(prep.json.display));
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json, 'raw') });
    expect(r).toEqual({ status: 200, json: { txHash: TX, status: 'landed', page: HARBOR_P1, keyHash: alice.keyHash } });
    expect(chain.submitted).toHaveLength(1);
    const sig = chain.submitted[0].signatures[0];
    expect(sig).toMatchObject({ type: 'ecdsaSha256', signer: HARBOR_P1, signerVersion: 3, transactionHash: TX, publicKey: bytesToHex(alice.spki) });
    expect(sig.signature.startsWith('30')).toBe(true);
    expect(s6Verifies(sig)).toBe(true);
    // Single use.
    const again = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(again.status).toBe(404);
    expect(chain.submitted).toHaveLength(1);
  });

  it('reports submitted when the signature does not show up before the timeout', async () => {
    chain.land = false;
    const prep = await prepare(bob, { ref: TX, page: HARBOR_P1, vote: 'reject' });
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(bob, prep.json) });
    expect(r.json).toMatchObject({ status: 'submitted', keyHash: bob.keyHash });
    expect(chain.submitted[0].signatures[0].vote).toBe('reject');
    expect(s6Verifies(chain.submitted[0].signatures[0])).toBe(true);
  });

  it('delegated: key on treasury/book/1, delegator issuance/book/1 — wraps the signature and verifies over the delegated sigMdHash', async () => {
    const prep = await prepare(tess, { ref: TX, page: TREASURY_P1, delegators: [ISSUANCE_P1], vote: 'approve' });
    expect(prep.status).toBe(200);
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(tess, prep.json) });
    expect(r.json).toEqual({ txHash: TX, status: 'landed', page: TREASURY_P1, keyHash: tess.keyHash });
    const outer = chain.submitted[0].signatures[0];
    expect(outer.type).toBe('delegated');
    expect(String(outer.delegator)).toBe(ISSUANCE_P1);
    const inner = { ...outer.signature, publicKey: outer.signature.publicKey, signature: outer.signature.signature, transactionHash: outer.signature.transactionHash };
    expect(s6Verifies(inner, [ISSUANCE_P1])).toBe(true);
    expect(s6Verifies(inner)).toBe(false);   // the undelegated sigMdHash is a different message
  });

  it('refuses a delegation the pages do not carry, and a key not on the page', async () => {
    expect((await prepare(tess, { ref: TX, page: TREASURY_P1, delegators: [HARBOR_P1], vote: 'approve' })).json).toEqual({ error: 'delegation_not_on_page' });
    expect((await prepare(alice, { ref: TX, page: TREASURY_P1, vote: 'approve' })).json).toEqual({ error: 'key_not_on_page' });
    expect(chain.submitted).toHaveLength(0);
  });

  it('refuses a transaction that is no longer pending, at prepare and at intake', async () => {
    const prep = await prepare(alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
    chain.pending.get(TX)!.executed = true;
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.status).toBe(409);
    expect((await prepare(alice, { ref: TX, page: HARBOR_P1, vote: 'approve' })).status).toBe(409);
    expect(chain.submitted).toHaveLength(0);
  });

  describe('each tampered field is rejected with 400 signature_invalid and nothing is submitted', () => {
    const tampers: Array<[string, (prep: any) => Promise<Record<string, unknown>>]> = [
      ['signature', async (prep) => {
        const der = hexToBytes(await signPrepared(alice, prep));
        der[der.length - 1] ^= 0x01;
        return { signature: bytesToHex(der) };
      }],
      ['timestamp (signed over another timestamp)', async (prep) => {
        const sigMd = buildSigMetaHash({ publicKey: alice.spki, signatureType: 'ecdsaSha256', signerUrl: HARBOR_P1, signerVersion: prep.signerVersion, timestamp: prep.timestamp + 1, vote: 'approve' });
        return { signature: bytesToHex(toDer(await signRaw(alice, concatBytes(sigMd, hexToBytes(prep.txHash))))) };
      }],
      ['timestamp (echoed)', async (prep) => ({ signature: await signPrepared(alice, prep), timestamp: prep.timestamp + 1 })],
      ['vote (signed as reject)', async (prep) => {
        const sigMd = buildSigMetaHash({ publicKey: alice.spki, signatureType: 'ecdsaSha256', signerUrl: HARBOR_P1, signerVersion: prep.signerVersion, timestamp: prep.timestamp, vote: 'reject' });
        return { signature: bytesToHex(toDer(await signRaw(alice, concatBytes(sigMd, hexToBytes(prep.txHash))))) };
      }],
      ['vote (echoed)', async (prep) => ({ signature: await signPrepared(alice, prep), vote: 'reject' })],
      ['ref (signed another tx)', async (prep) => ({ signature: bytesToHex(toDer(await signRaw(alice, concatBytes(hexToBytes(prep.sigMdHash), hexToBytes('ab'.repeat(32)))))) })],
      ['ref (echoed)', async (prep) => ({ signature: await signPrepared(alice, prep), ref: 'ab'.repeat(32) })],
      ['key (another officer on the same page signed)', async (prep) => ({ signature: await signPrepared(bob, prep) })],
      ['key (echoed)', async (prep) => ({ signature: await signPrepared(alice, prep), keyHash: bob.keyHash })],
      ['signature (not DER, not r‖s)', async () => ({ signature: '3006020101020101ff' })],
    ];
    for (const [name, make] of tampers) {
      it(name, async () => {
        const prep = await prepare(alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
        expect(prep.status).toBe(200);
        const body = { prepareId: prep.json.prepareId, ...(await make(prep.json)) };
        const r = await call(port, 'POST', '/relay/officer-signature', {}, body);
        expect(r).toEqual({ status: 400, json: { error: 'signature_invalid' } });
        expect(chain.submitted).toHaveLength(0);
      });
    }

    it('key removed from the page between prepare and intake', async () => {
      const prep = await prepare(alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
      chain.pages.get(HARBOR_P1.toLowerCase())!.keys = [{ publicKeyHash: bob.keyHash }];
      const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
      expect(r).toEqual({ status: 400, json: { error: 'signature_invalid' } });
      expect(chain.submitted).toHaveLength(0);
    });
  });
});

/* ------------------------------------------------------------------ */
/* §4 proposals                                                        */
/* ------------------------------------------------------------------ */

describe('governance proposal origination', () => {
  const propose = (body: unknown, h: Record<string, string> = { ...C, 'x-governance-key': GOV_KEY }) => call(port, 'POST', '/relay/governance/proposal', h, body);
  const OPS = [{ type: 'remove-key', keyHash: 'bb'.repeat(32) }];

  it('needs the governance scope, the governance key, and a page in a served book; validates ops against the live page', async () => {
    expect((await propose({ page: HARBOR_P1, operations: OPS, proposer: 'ada' }, C)).status).toBe(401);
    expect((await propose({ page: 'acc://other-tcl1.acme/book/1', operations: OPS, proposer: 'ada' })).status).toBe(403);
    expect((await propose({ page: HARBOR_P1, operations: [{ type: 'remove-key', keyHash: 'ee'.repeat(32) }], proposer: 'ada' })).status).toBe(400);
    expect((await propose({ page: HARBOR_P1, operations: OPS })).status).toBe(400);
    expect(intake.proposals()).toHaveLength(0);
  });

  it('creates a proposal; prepare sets header.initiator = sigMdHash; intake submits {transaction, signature} whose hash recomputes', async () => {
    const created = await propose({ page: HARBOR_P2, operations: [{ type: 'remove-key', keyHash: 'cc'.repeat(32) }, { type: 'add-key', keyHash: 'ee'.repeat(32) }], proposer: 'ada (FICTIONAL)' });
    expect(created.status).toBe(200);
    expect(created.json.proposalId).toMatch(/^proposal:[0-9a-f-]{36}$/);
    expect(created.json.summaryHash).toBe(tclSummaryV1(created.json.display));
    expect(chain.submitted).toHaveLength(0);   // nothing signed or submitted

    const view = await call(port, 'GET', `/relay/officer/pending/${created.json.proposalId}`, { 'x-officer-auth': await authHeader(alice, 'GET', `/relay/officer/pending/${created.json.proposalId}`) });
    expect(view.json).toMatchObject({ kind: 'proposal', principal: HARBOR_P2, page: HARBOR_P2, bodyType: 'updateKeyPage', status: 'proposed', summaryHash: created.json.summaryHash });

    // Page 1 humans initiate a change to page 2 of the same book.
    const prep = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    expect(prep.json.principal).toBe(HARBOR_P2);
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.json).toEqual({ txHash: prep.json.txHash, status: 'landed', page: HARBOR_P1, keyHash: alice.keyHash });

    const env = chain.submitted[0];
    expect(env.transaction).toHaveLength(1);
    const txObj = env.transaction[0];
    expect(String(txObj.header.initiator).toLowerCase()).toBe(prep.json.sigMdHash);
    expect(bytesToHex(new core.Transaction(txObj).hash())).toBe(prep.json.txHash);
    expect(txObj.body.type).toBe('updateKeyPage');
    const sig = env.signatures[0];
    expect(bytesToHex(buildSigMetaHash({ publicKey: alice.spki, signatureType: 'ecdsaSha256', signerUrl: HARBOR_P1, signerVersion: 3, timestamp: prep.json.timestamp, vote: 'approve' }))).toBe(prep.json.sigMdHash);
    expect(s6Verifies(sig)).toBe(true);
    expect(intake.proposals()[0]).toMatchObject({ status: 'landed', txHash: prep.json.txHash });
    // A landed proposal cannot be prepared again.
    expect((await prepare(bob, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' })).status).toBe(409);
  });

  it('refuses a proposal signed through a page of another book, or as a reject', async () => {
    const created = await propose({ page: HARBOR_P1, operations: OPS, proposer: 'ada' });
    expect((await prepare(tess, { ref: created.json.proposalId, page: TREASURY_P1, vote: 'approve' })).status).toBe(403);
    expect((await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'reject' })).status).toBe(400);
  });

  it('a tampered proposal intake submits nothing', async () => {
    const created = await propose({ page: HARBOR_P1, operations: OPS, proposer: 'ada' });
    const prep = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json), ref: TX });
    expect(r).toEqual({ status: 400, json: { error: 'signature_invalid' } });
    expect(chain.submitted).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/* delegate consent through officer intake                             */
/* ------------------------------------------------------------------ */

describe('consent path: a governance tx awaiting a delegate signature', () => {
  it('POST /relay/governance add-delegate is recorded; the delegate-page human views, prepares and signs it as a transaction ref', async () => {
    // Before the seat is added it is not on the page. (The shared fixture seats it for the delegated-signing
    // tests; adding a seat the page already holds is a duplicate entry the network, and G-65, refuse.)
    chain.pages.get(ISSUANCE_P1.toLowerCase())!.keys = [{ publicKeyHash: 'dd'.repeat(32) }];
    const g = await call(port, 'POST', '/relay/governance', { ...C, 'x-governance-key': GOV_KEY }, { page: ISSUANCE_P1, operations: [{ type: 'add-delegate', delegate: 'acc://fdb-treasury-tcl1.acme/book' }] });
    expect(g.json).toMatchObject({ status: 'awaiting_consent' });
    const hash = 'ab'.repeat(32);
    chain.pending.set(hash, { principal: ISSUANCE_P1, body: { type: 'updateKeyPage', operation: [{ type: 'add', entry: { delegate: 'acc://fdb-treasury-tcl1.acme/book' } }] } });

    const path = `/relay/officer/pending/${hash}`;
    const view = await call(port, 'GET', path, { 'x-officer-auth': await authHeader(tess, 'GET', path) });
    expect(view.status).toBe(200);
    expect(view.json).toMatchObject({ ref: hash, kind: 'transaction', principal: ISSUANCE_P1, bodyType: 'updateKeyPage', status: 'pending' });
    expect(view.json.display).toEqual([
      ['Principal', ISSUANCE_P1], ['Body type', 'updateKeyPage'], ['Page', ISSUANCE_P1], ['Operation', 'add'], ['Delegate', 'acc://fdb-treasury-tcl1.acme/book'],
    ]);
    expect(view.json.summaryHash).toBe(tclSummaryV1(view.json.display));

    const prep = await prepare(tess, { ref: hash, page: TREASURY_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    expect(prep.json.summaryHash).toBe(view.json.summaryHash);
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(tess, prep.json) });
    expect(r.json).toEqual({ txHash: hash, status: 'landed', page: TREASURY_P1, keyHash: tess.keyHash });
    const sig = chain.submitted[0].signatures[0];
    expect(sig).toMatchObject({ type: 'ecdsaSha256', signer: TREASURY_P1, transactionHash: hash });
    expect(s6Verifies(sig)).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* §4 config: intake-only                                              */
/* ------------------------------------------------------------------ */

describe('intake-only config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'p7-intake-'));
  const yaml = (intake: string) => `
wallet:
  org_id: "harbor-mfg-tcl1 (FICTIONAL)"
  accumulate_endpoints: ["http://127.0.0.1:1/v3"]
admin:
  relay_clients:
    - { name: "harbor-console", key: "env:P7_TEST_RELAY_KEY", scopes: [pending, tx] }
${intake}
health:
  bind: "127.0.0.1:0"
`;
  const write = (name: string, text: string) => { const p = join(dir, name); writeFileSync(p, text); return p; };

  it('boots with officer_intake + relay_clients only: no keys, no poller, no policy engine; serves relay and officer routes', async () => {
    process.env.P7_TEST_RELAY_KEY = 'harbor-console-relay-key-test';
    try {
      const cfg = loadConfig(write('ok.yaml', yaml(`officer_intake:\n  enabled: true\n  human_pages: ["${HARBOR_P1}"]\n  landed_timeout_ms: 1000`)));
      expect(isIntakeOnly(cfg)).toBe(true);
      expect(cfg.policy).toBeUndefined();
      const proc = await startIntakeOnly(cfg, silent, { listen: false });
      const p = await listen(proc.server);
      try {
        expect((await call(p, 'GET', '/healthz')).status).toBe(200);
        expect((await call(p, 'GET', `/relay/officer/pending/${TX}`)).json).toEqual({ error: 'officer_auth_failed' });
        expect((await call(p, 'GET', `/relay/pending/${TX}`, { 'x-relay-client': 'harbor-console', 'x-api-key': 'harbor-console-relay-key-test' })).status).toBe(404);
        expect((await call(p, 'GET', '/v1/admin/pubkey')).status).toBe(403);
      } finally { proc.server.close(); }
    } finally { delete process.env.P7_TEST_RELAY_KEY; }
  });

  it('refuses an empty human_pages, a non-page URL, and a signing mode without a policy block', () => {
    process.env.P7_TEST_RELAY_KEY = 'harbor-console-relay-key-test';
    try {
      expect(() => loadConfig(write('e.yaml', yaml('officer_intake:\n  enabled: true\n  human_pages: []')))).toThrow(/non-empty/);
      expect(() => loadConfig(write('b.yaml', yaml('officer_intake:\n  enabled: true\n  human_pages: ["acc://harbor-mfg-tcl1.acme/book"]')))).toThrow(/key page URL/);
      expect(() => loadConfig(write('n.yaml', yaml('officer_intake:\n  enabled: false')))).toThrow(/policy is required/);
      expect(() => loadConfig(write('t.yaml', yaml('officer_intake:\n  enabled: true\n  human_pages: ["acc://x.acme/book/1"]\n  typo: 1')))).toThrow();
    } finally { delete process.env.P7_TEST_RELAY_KEY; }
  });
});

describe('keypage: a page needing more than one signature', () => {
  it('returns awaitingConsent with the submitted hash instead of waiting for a confirmation that cannot come', async () => {
    const { applyKeyPageOp } = await import('../src/ops/keypage.js');
    const submitted: unknown[] = [];
    const acc = {
      query: async () => ({ account: { version: 4, acceptThreshold: 2, keys: [{ publicKeyHash: 'aa'.repeat(32) }, { publicKeyHash: 'bb'.repeat(32) }] } }),
      getSignerInfo: async () => ({ version: 4, lastUsedOn: 0 }),
      submit: async (env: unknown) => { submitted.push(env); return { ok: true }; },
    } as any;
    // A stub key: the fake network does not verify, and no key material is needed to build the transaction.
    const signer = { signatureType: 'ed25519', publicKey: async () => new Uint8Array(32), sign: async () => new Uint8Array(64) } as any;
    const r = await applyKeyPageOp({ accumulate: acc, signer, logger: silent, page: 'acc://fdb-issuance-tcl1.acme/book/1' }, { op: 'remove-key', keyHash: 'bb'.repeat(32) }, 60_000);
    expect(r).toMatchObject({ ok: true, awaitingConsent: true });
    expect(r.submitted).toHaveLength(1);
    expect(r.submitted[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(submitted).toHaveLength(1);
  });
});

describe('proposal on a threshold-2 page: further officers sign by tx ref', () => {
  it('A initiates (submitted, recorded with the proposal summaryHash); B signs by tx ref; A signing again still verifies', async () => {
    const created = await call(port, 'POST', '/relay/governance/proposal', { ...C, 'x-governance-key': GOV_KEY },
      { page: BOARD_P1, operations: [{ type: 'remove-key', keyHash: 'bb'.repeat(32) }], proposer: 'board secretary (FICTIONAL)' });
    expect(created.status).toBe(200);

    const prepA = await prepare(alice, { ref: created.json.proposalId, page: BOARD_P1, vote: 'approve' });
    expect(prepA.status).toBe(200);
    const rA = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prepA.json.prepareId, signature: await signPrepared(alice, prepA.json) });
    expect(rA.status).toBe(200);
    expect(['landed', 'submitted']).toContain(rA.json.status);
    const txHash = prepA.json.txHash;
    expect(chain.submitted[0].transaction[0].header.initiator).toBeDefined();

    const stored = await store.getPolicyRequest(txHash);
    expect(stored).toMatchObject({ account: BOARD_P1, bodyType: 'updateKeyPage', summaryHash: created.json.summaryHash, display: created.json.display });

    const path = `/relay/officer/pending/${txHash}`;
    const view = await call(port, 'GET', path, { 'x-officer-auth': await authHeader(bob, 'GET', path) });
    expect(view.json).toMatchObject({ ref: txHash, kind: 'transaction', principal: BOARD_P1, bodyType: 'updateKeyPage', status: 'pending', summaryHash: created.json.summaryHash });

    const prepB = await prepare(bob, { ref: txHash, page: BOARD_P1, vote: 'approve' });
    expect(prepB.status).toBe(200);
    expect(prepB.json.summaryHash).toBe(created.json.summaryHash);
    const rB = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prepB.json.prepareId, signature: await signPrepared(bob, prepB.json) });
    expect(rB.json).toEqual({ txHash, status: 'landed', page: BOARD_P1, keyHash: bob.keyHash });
    const envB = chain.submitted[1];
    expect(envB.transaction).toHaveLength(1);
    expect(envB.signatures).toHaveLength(1);
    expect(envB.signatures[0]).toMatchObject({ type: 'ecdsaSha256', signer: BOARD_P1, transactionHash: txHash, publicKey: bytesToHex(bob.spki) });
    expect(s6Verifies(envB.signatures[0])).toBe(true);

    // Double-signing is the network's concern: A may sign again by tx ref and it still verifies.
    const prepA2 = await prepare(alice, { ref: txHash, page: BOARD_P1, vote: 'approve' });
    expect(prepA2.status).toBe(200);
    const rA2 = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prepA2.json.prepareId, signature: await signPrepared(alice, prepA2.json) });
    expect(rA2.status).toBe(200);
    expect(rA2.json).toMatchObject({ txHash, page: BOARD_P1, keyHash: alice.keyHash });
    expect(s6Verifies(chain.submitted[2].signatures[0])).toBe(true);
  });

  it('a threshold-1 page proposal is not recorded as awaiting', async () => {
    const created = await call(port, 'POST', '/relay/governance/proposal', { ...C, 'x-governance-key': GOV_KEY },
      { page: HARBOR_P1, operations: [{ type: 'remove-key', keyHash: 'bb'.repeat(32) }], proposer: 'ada' });
    const prep = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(await store.getPolicyRequest(prep.json.txHash)).toBeUndefined();
  });
});

describe('proposal intake: claim and signing-page threshold', () => {
  const propose = (page: string) => call(port, 'POST', '/relay/governance/proposal', { ...C, 'x-governance-key': GOV_KEY },
    { page, operations: [{ type: 'add-key', keyHash: 'e1'.repeat(32) }], proposer: 'ada (FICTIONAL)' });

  it('two concurrent intakes for one proposal produce exactly one submit; prepare is refused while it is submitting', async () => {
    const created = await propose(HARBOR_P2);
    const pa = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    const pb = await prepare(bob, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    expect([pa.status, pb.status]).toEqual([200, 200]);
    const sa = await signPrepared(alice, pa.json);
    const sb = await signPrepared(bob, pb.json);
    // Hold the first submit open so the second intake runs its checks meanwhile.
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const realSubmit = chain.submit.bind(chain);
    chain.submit = async (env: any) => { await gate; return realSubmit(env); };
    const first = call(port, 'POST', '/relay/officer-signature', {}, { prepareId: pa.json.prepareId, signature: sa });
    const second = call(port, 'POST', '/relay/officer-signature', {}, { prepareId: pb.json.prepareId, signature: sb });
    for (let i = 0; i < 100 && intake.proposals()[0]?.status !== 'submitting'; i++) await new Promise((r) => setTimeout(r, 5));
    expect(intake.proposals()[0].status).toBe('submitting');
    const during = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    expect(during.status).toBe(409);
    const r2 = await second;
    release();
    const r1 = await first;
    expect([r1.status, r2.status].sort()).toEqual([200, 400]);
    expect(chain.submitted).toHaveLength(1);
    expect(intake.proposals()[0].status).toBe('landed');
  });

  it('a refused intake gives the proposal back', async () => {
    const created = await propose(HARBOR_P2);
    const pa = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    const bad = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: pa.json.prepareId, signature: await signPrepared(bob, pa.json) });
    expect(bad.status).toBe(400);
    expect(intake.proposals()[0].status).toBe('proposed');
    expect(chain.submitted).toHaveLength(0);
    expect((await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' })).status).toBe(200);
  });

  it('records by the SIGNING page threshold: signing page 2, proposal page 1 → recorded; the reverse → not', async () => {
    chain.pages.get(HARBOR_P1.toLowerCase())!.threshold = 2;   // signing page
    chain.pages.get(HARBOR_P2.toLowerCase())!.threshold = 1;   // proposal page
    const c1 = await propose(HARBOR_P2);
    const p1 = await prepare(alice, { ref: c1.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: p1.json.prepareId, signature: await signPrepared(alice, p1.json) });
    expect(await store.getPolicyRequest(p1.json.txHash)).toMatchObject({ account: HARBOR_P2, summaryHash: c1.json.summaryHash });

    chain.pages.get(HARBOR_P1.toLowerCase())!.threshold = 1;
    chain.pages.get(HARBOR_P2.toLowerCase())!.keys.push({ publicKeyHash: 'e2'.repeat(32) });
    chain.pages.get(HARBOR_P2.toLowerCase())!.threshold = 2;
    const c2 = await call(port, 'POST', '/relay/governance/proposal', { ...C, 'x-governance-key': GOV_KEY },
      { page: HARBOR_P2, operations: [{ type: 'add-key', keyHash: 'e3'.repeat(32) }], proposer: 'ada (FICTIONAL)' });
    const p2 = await prepare(bob, { ref: c2.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: p2.json.prepareId, signature: await signPrepared(bob, p2.json) });
    expect(await store.getPolicyRequest(p2.json.txHash)).toBeUndefined();
  });

  it('delegated: reads the outermost delegator threshold', async () => {
    const ISSUANCE_P2 = 'acc://fdb-issuance-tcl1.acme/book/2';
    chain.pages.set(ISSUANCE_P2.toLowerCase(), { version: 1, threshold: 1, keys: [{ publicKeyHash: 'f1'.repeat(32) }] });
    chain.pages.get(ISSUANCE_P1.toLowerCase())!.threshold = 2;
    const c = await propose(ISSUANCE_P2);
    expect(c.status).toBe(200);
    const p = await prepare(tess, { ref: c.json.proposalId, page: TREASURY_P1, delegators: [ISSUANCE_P1], vote: 'approve' });
    expect(p.status).toBe(200);
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: p.json.prepareId, signature: await signPrepared(tess, p.json) });
    expect(r.status).toBe(200);
    expect(await store.getPolicyRequest(p.json.txHash)).toMatchObject({ account: ISSUANCE_P2, summaryHash: c.json.summaryHash });
  });
});

/* ------------------------------------------------------------------ */
/* G-65: refuse a key-page change that would brick the page            */
/* ------------------------------------------------------------------ */

describe('G-65: proposals and officer signatures never carry a change that would brick a page', () => {
  const H = { ...C, 'x-governance-key': GOV_KEY };
  const propose = (page: string, operations: unknown[]) => call(port, 'POST', '/relay/governance/proposal', H, { page, operations, proposer: 'ada (FICTIONAL)' });
  const GOV_TX = 'ab12'.repeat(16);
  /** A pending updateKeyPage on HARBOR_P2 (one key, threshold one), viewable by officers. */
  async function pendingGovernance(operation: unknown[], principal = HARBOR_P2) {
    chain.pending.set(GOV_TX, { principal, body: { type: 'updateKeyPage', operation } });
    await store.savePolicyRequest(withDisplay({
      requestId: 'g1', txHash: GOV_TX, account: principal, actionSummary: 'FICTIONAL key-page change', expiresAt: '2026-12-31T00:00:00Z', bodyType: 'updateKeyPage',
    }));
  }

  it('a proposal that would brick the page is refused with the structured reason; an unreadable page is 503', async () => {
    const r = await propose(HARBOR_P2, [{ type: 'set-threshold', threshold: 2 }]);
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ reason: 'threshold_exceeds_entries', refusal: { reason: 'threshold_exceeds_entries', threshold: 2, entries: 1, page: HARBOR_P2 } });
    expect((await propose(HARBOR_P2, [{ type: 'remove-key', keyHash: 'cc'.repeat(32) }])).json).toMatchObject({ reason: 'no_entries' });
    const unreadable = await propose('acc://harbor-mfg-tcl1.acme/book/3', [{ type: 'add-key', keyHash: 'ee'.repeat(32) }]);
    expect(unreadable.status).toBe(503);
    expect(unreadable.json).toMatchObject({ reason: 'page_unreadable' });
    expect(intake.proposals()).toHaveLength(0);
  });

  it('a proposal is measured again at prepare: a page that changed since is refused', async () => {
    const created = await propose(HARBOR_P2, [{ type: 'add-key', keyHash: 'ee'.repeat(32) }, { type: 'set-threshold', threshold: 2 }]);
    expect(created.status).toBe(200);
    chain.pages.get(HARBOR_P2.toLowerCase())!.keys.push({ publicKeyHash: 'ee'.repeat(32) });   // somebody else added it meanwhile
    const prep = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(400);
    expect(prep.json).toMatchObject({ error: 'duplicate_entry', refusal: { reason: 'duplicate_entry', page: HARBOR_P2 } });
  });

  it('a proposal is measured again at intake, right before submit: refused, nothing submitted, proposal reopened', async () => {
    const created = await propose(HARBOR_P2, [{ type: 'add-key', keyHash: 'ee'.repeat(32) }, { type: 'set-threshold', threshold: 2 }]);
    const prep = await prepare(alice, { ref: created.json.proposalId, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    chain.pages.get(HARBOR_P2.toLowerCase())!.keys = [];   // the page lost its key meanwhile
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: 'threshold_exceeds_entries', refusal: { threshold: 2, entries: 1 } });
    expect(chain.submitted).toHaveLength(0);
    expect(intake.proposals()[0].status).toBe('proposed');
  });

  it('an approve on a pending updateKeyPage that would brick the page is refused at prepare; a reject is allowed', async () => {
    await pendingGovernance([{ type: 'setThreshold', threshold: 3 }]);
    const prep = await prepare(alice, { ref: GOV_TX, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(400);
    expect(prep.json).toMatchObject({ error: 'threshold_exceeds_entries', refusal: { threshold: 3, entries: 1, page: HARBOR_P2 } });

    // Rejecting a bricking change is exactly what a human should be able to do.
    const rej = await prepare(alice, { ref: GOV_TX, page: HARBOR_P1, vote: 'reject' });
    expect(rej.status).toBe(200);
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: rej.json.prepareId, signature: await signPrepared(alice, rej.json) });
    expect(r.status).toBe(200);
    expect(chain.submitted).toHaveLength(1);
    expect(chain.submitted[0].signatures[0].vote).toBe('reject');
  });

  it('an approve is measured again at intake against the chain body and a fresh page read', async () => {
    await pendingGovernance([{ type: 'add', entry: { keyHash: 'ee'.repeat(32) } }]);
    const prep = await prepare(alice, { ref: GOV_TX, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    chain.pages.get(HARBOR_P2.toLowerCase())!.keys.push({ publicKeyHash: 'ee'.repeat(32) });
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.status).toBe(400);
    expect(r.json).toMatchObject({ error: 'duplicate_entry' });
    expect(chain.submitted).toHaveLength(0);
  });

  it('an approve on a change to a page that cannot be read is refused 503 page_unreadable', async () => {
    const P3 = 'acc://harbor-mfg-tcl1.acme/book/3';
    await pendingGovernance([{ type: 'add', entry: { keyHash: 'ee'.repeat(32) } }], P3);
    const prep = await prepare(alice, { ref: GOV_TX, page: HARBOR_P1, vote: 'approve', principal: P3 });
    expect(prep.status).toBe(503);
    expect(prep.json).toMatchObject({ error: 'page_unreadable' });
    expect(chain.submitted).toHaveLength(0);
  });

  it('a valid change is still signed and submitted', async () => {
    await pendingGovernance([{ type: 'add', entry: { keyHash: 'ee'.repeat(32) } }, { type: 'setThreshold', threshold: 2 }]);
    const prep = await prepare(alice, { ref: GOV_TX, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.status).toBe(200);
    expect(chain.submitted).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ */
/* G-69: a human-only seat, signed by its people through officer intake */
/* ------------------------------------------------------------------ */

describe('G-69: officer intake on a request stored by a human-only seat', () => {
  const HTX = '7e'.repeat(32);
  /** The orchestrator's view of the fake chain: it asks by signer page, the fake answers by principal. */
  const orchChain = (): AccumulateClient => ({
    getPendingTx: async (h: string) => { const t = chain.pending.get(h); return t ? chain.getPendingTx(h, t.principal) : { found: false }; },
    getSignerInfo: (page: string) => chain.getSignerInfo(page),
    listPendingForSigner: async () => [],
    listPendingViaSignatureChain: async () => [],
    submit: (env: unknown) => chain.submit(env),
  }) as unknown as AccumulateClient;
  /** HARBOR_P1 as a HUMAN-ONLY seat: no key anywhere in this process. */
  async function decide(decision: 'approve' | 'deny', body: unknown = { type: 'writeData', entry: { type: 'doubleHash', data: ['00'] } }, principal = PRINCIPAL) {
    chain.pending.set(HTX, { principal, body });
    const acc = orchChain();
    const o = new Orchestrator({
      accumulate: acc, keyring: noKeyKeyring('human-only signer'), policy: new MockPolicyClient({ decision, reason: 'FICTIONAL seat rule' }),
      store, resolver: new Resolver(acc), logger: silent, humanOnlyPages: [HARBOR_P1], readPage: chain.readPage, options: { submitRejectVote: true },
    });
    return o.handle({ txHash: HTX, signerUrl: HARBOR_P1 });
  }

  it('approve: awaiting_human; the person prepares and signs the stored request; the landing ends it as signed', async () => {
    expect((await decide('approve')).status).toBe('awaiting_human');
    expect(chain.submitted).toHaveLength(0);
    const stored = await store.getPolicyRequest(HTX);
    const prep = await prepare(alice, { ref: HTX, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(200);
    expect(prep.json).toMatchObject({ txHash: HTX, principal: PRINCIPAL, summaryHash: stored!.summaryHash });
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.json).toMatchObject({ txHash: HTX, status: 'landed', page: HARBOR_P1, keyHash: alice.keyHash });
    expect(chain.submitted).toHaveLength(1);   // the person's signature, and nothing from this signer
    expect(chain.submitted[0].signatures[0]).toMatchObject({ type: 'ecdsaSha256', signer: HARBOR_P1 });
    expect((await store.get(humanRecordId(HTX, HARBOR_P1)))?.status).toBe('signed');
    expect(await store.getReceipt(humanRecordId(HTX, HARBOR_P1))).toMatchObject({ decision: 'approve', vote: 'approve', signedBy: { page: HARBOR_P1, publicKeyHash: alice.keyHash } });
  });

  it('deny: the person casts the reject; the landing ends it as rejected', async () => {
    expect((await decide('deny')).status).toBe('awaiting_human');
    const prep = await prepare(bob, { ref: HTX, page: HARBOR_P1, vote: 'reject' });
    expect(prep.status).toBe(200);
    await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(bob, prep.json) });
    expect(chain.submitted[0].signatures[0].vote).toBe('reject');
    expect((await store.get(humanRecordId(HTX, HARBOR_P1)))?.status).toBe('rejected');
  });

  it('a signature that does not land leaves the request awaiting_human', async () => {
    chain.land = false;
    await decide('approve');
    const prep = await prepare(alice, { ref: HTX, page: HARBOR_P1, vote: 'approve' });
    const r = await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: prep.json.prepareId, signature: await signPrepared(alice, prep.json) });
    expect(r.json.status).toBe('submitted');
    expect((await store.get(humanRecordId(HTX, HARBOR_P1)))?.status).toBe('awaiting_human');
  });

  it('G-65 on this path: an approved key-page change that has since become a brick is refused at the prepare of the person', async () => {
    const body = { type: 'updateKeyPage', operation: [{ type: 'add', entry: { keyHash: 'e9'.repeat(32) } }] };
    expect((await decide('approve', body, HARBOR_P2)).status).toBe('awaiting_human');
    chain.pages.get(HARBOR_P2.toLowerCase())!.keys.push({ publicKeyHash: 'e9'.repeat(32) });   // added meanwhile
    const prep = await prepare(alice, { ref: HTX, page: HARBOR_P1, vote: 'approve' });
    expect(prep.status).toBe(400);
    expect(prep.json).toMatchObject({ error: 'duplicate_entry' });
    expect(chain.submitted).toHaveLength(0);
    expect((await store.get(humanRecordId(HTX, HARBOR_P1)))?.status).toBe('awaiting_human');
  });
});

/* ------------------------------------------------------------------ */
/* G-39: prepares and proposals survive a restart                      */
/* ------------------------------------------------------------------ */

describe('G-39: open prepares and proposals are persisted and restored', () => {
  const PREP = '/relay/officer-signature/prepare';
  let open: http.Server[] = [];
  afterEach(() => { for (const s of open) s.close(); open = []; });

  /** One signer process: a FileStore at `path`, an intake restored from it, and its own listener. */
  async function boot(path: string, o: { now?: () => number; chainOverride?: Partial<IntakeChain> } = {}) {
    const st = new FileStore(path);
    const c: IntakeChain = Object.assign(Object.create(Object.getPrototypeOf(chain)), chain, o.chainOverride ?? {});
    const it = createOfficerIntake({
      humanPages: [HARBOR_P1, TREASURY_P1, ISSUANCE_P1, BOARD_P1], chain: c, readPage: chain.readPage,
      getPolicyRequest: (h) => store.getPolicyRequest(h), landedTimeoutMs: 150, pollIntervalMs: 10, logger: silent,
      state: st, ...(o.now ? { now: o.now } : {}),
    });
    await it.restore();
    const srv = createServer({ officerIntake: it.handle, orchestrator: {} as any, store: st, keyring: {} as any, accumulate: {} as any, pause: { paused: false }, logger: silent });
    open.push(srv);
    return { intake: it, store: st, port: await listen(srv) };
  }
  const prep = async (p: number, o: Officer, body: Record<string, unknown>) => call(p, 'POST', PREP, { 'x-officer-auth': await authHeader(o, 'POST', PREP) }, body);
  const sign = async (p: number, o: Officer, pr: any) => call(p, 'POST', '/relay/officer-signature', {}, { prepareId: pr.prepareId, signature: await signPrepared(o, pr) });
  const dir = () => join(mkdtempSync(join(tmpdir(), 'g39-')), 'state.json');

  it('a proposal survives a restart and can still be prepared, signed and submitted', async () => {
    const path = dir();
    const a = await boot(path);
    const c = await a.intake.propose(HARBOR_P2, [{ op: 'add-key', keyHash: 'e1'.repeat(32) }], 'ada (FICTIONAL)');
    expect(c.status).toBe(200);
    const id = (c.body as { proposalId: string }).proposalId;

    const b = await boot(path);   // restart
    expect(b.intake.proposals().map((x) => [`proposal:${x.id}`, x.status])).toEqual([[id, 'proposed']]);
    const pr = await prep(b.port, alice, { ref: id, page: HARBOR_P1, vote: 'approve' });
    expect(pr.status).toBe(200);
    expect((await sign(b.port, alice, pr.json)).json).toMatchObject({ status: 'landed' });
    expect(chain.submitted).toHaveLength(1);
    // The landed state is persisted too.
    expect((await boot(path)).intake.proposals()[0]).toMatchObject({ status: 'landed', txHash: pr.json.txHash });
  });

  it('a prepare survives a restart and is single use across restarts', async () => {
    const path = dir();
    const a = await boot(path);
    const pr = await prep(a.port, alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
    expect(pr.status).toBe(200);

    const b = await boot(path);   // restart before the signature arrives
    expect((await sign(b.port, alice, pr.json)).status).toBe(200);
    expect(chain.submitted).toHaveLength(1);

    const c2 = await boot(path);  // restart after it was used: still used
    expect((await sign(c2.port, alice, pr.json)).status).toBe(404);
    expect(chain.submitted).toHaveLength(1);
  });

  it('an expired prepare is refused after a restart, and dropped from the store', async () => {
    const path = dir();
    let t = Date.now();
    const a = await boot(path, { now: () => t });
    const pr = await prep(a.port, alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
    expect(pr.status).toBe(200);
    t += PREPARE_TTL_MS + 1;
    const b = await boot(path, { now: () => t });
    expect((await sign(b.port, alice, pr.json)).status).toBe(404);
    expect(chain.submitted).toHaveLength(0);
    expect(await b.store.listIntakeRecords('prepare')).toEqual([]);
  });

  it('a submit that throws after the network accepted the proposal leaves it submitted/landed, never proposed', async () => {
    const path = dir();
    const a = await boot(path, { chainOverride: { submit: async (env: unknown) => { await chain.submit(env); throw new Error('FICTIONAL socket hang up'); } } });
    const c = await a.intake.propose(HARBOR_P2, [{ op: 'add-key', keyHash: 'e2'.repeat(32) }], 'ada (FICTIONAL)');
    const id = (c.body as { proposalId: string }).proposalId;
    const pr = await prep(a.port, alice, { ref: id, page: HARBOR_P1, vote: 'approve' });
    const r = await sign(a.port, alice, pr.json);
    expect(r.status).toBe(200);
    expect(r.json.status).toBe('landed');
    expect(a.intake.proposals()[0]).toMatchObject({ status: 'landed', txHash: pr.json.txHash });
    expect((await boot(path)).intake.proposals()[0]!.status).toBe('landed');
  });

  it('a submit that throws and did NOT reach the chain gives the proposal back', async () => {
    const path = dir();
    const a = await boot(path, { chainOverride: { submit: async () => { throw new Error('FICTIONAL connection refused'); } } });
    const c = await a.intake.propose(HARBOR_P2, [{ op: 'add-key', keyHash: 'e3'.repeat(32) }], 'ada (FICTIONAL)');
    const pr = await prep(a.port, alice, { ref: (c.body as { proposalId: string }).proposalId, page: HARBOR_P1, vote: 'approve' });
    expect((await sign(a.port, alice, pr.json)).status).toBe(502);
    expect(a.intake.proposals()[0]!.status).toBe('proposed');
    expect((await boot(path)).intake.proposals()[0]!.status).toBe('proposed');
  });

  it('a submit whose fate cannot be read stays submitting, and a restart settles it against the chain', async () => {
    const path = dir();
    let accepted: unknown;
    const a = await boot(path, {
      chainOverride: {
        submit: async (env: unknown) => { accepted = env; throw new Error('FICTIONAL timeout'); },
        getPendingTx: async () => ({ found: false, unavailable: true }),
      },
    });
    const c = await a.intake.propose(HARBOR_P2, [{ op: 'add-key', keyHash: 'e4'.repeat(32) }], 'ada (FICTIONAL)');
    const id = (c.body as { proposalId: string }).proposalId;
    const pr = await prep(a.port, alice, { ref: id, page: HARBOR_P1, vote: 'approve' });
    const r = await sign(a.port, alice, pr.json);
    expect(r.status).toBe(502);
    expect(r.json.onChain).toBe('unknown');
    expect(a.intake.proposals()[0]).toMatchObject({ status: 'submitting', pendingTxHash: pr.json.txHash });
    // Nothing may prepare it while its fate is unknown.
    expect((await prep(a.port, bob, { ref: id, page: HARBOR_P1, vote: 'approve' })).status).toBe(409);

    // The network had in fact accepted it.
    await chain.submit(accepted);
    const b = await boot(path);
    expect(b.intake.proposals()[0]).toMatchObject({ status: 'submitted', txHash: pr.json.txHash });
  });

  it('nothing secret is persisted: a prepare holds a public key, hashes and a display', async () => {
    const path = dir();
    const a = await boot(path);
    const pr = await prep(a.port, alice, { ref: TX, page: HARBOR_P1, vote: 'approve' });
    const recs = await a.store.listIntakeRecords('prepare');
    expect(recs).toHaveLength(1);
    expect(Object.keys(recs[0]!).sort()).toEqual([
      'delegators', 'display', 'expiresAt', 'keyHash', 'kind', 'page', 'prepareId', 'principal', 'ref', 'sigMdHash',
      'signerVersion', 'spki', 'summaryHash', 'timestamp', 'txHash', 'vote',
    ]);
    expect(recs[0]!.spki).toBe(bytesToHex(alice.spki));   // the PUBLIC key
    expect(readFileSync(path, 'utf8')).not.toContain('"signature"');
    expect(pr.status).toBe(200);
  });
});

describe('G-69 review #2: a human-only page with an accept threshold of 2 needs two people', () => {
  const BTX = '7f'.repeat(32);
  it('alice landing leaves it awaiting_human with her on the record; bob landing ends it as signed', async () => {
    chain.pending.set(BTX, { principal: PRINCIPAL, body: { type: 'writeData', entry: { type: 'doubleHash', data: ['00'] } } });
    const acc = {
      getPendingTx: async (h: string) => { const t = chain.pending.get(h); return t ? chain.getPendingTx(h, t.principal) : { found: false }; },
      getSignerInfo: (page: string) => chain.getSignerInfo(page),
      getTxSignatures: (h: string) => chain.getTxSignatures(h),
      listPendingForSigner: async () => [], listPendingViaSignatureChain: async () => [], submit: (env: unknown) => chain.submit(env),
    } as unknown as AccumulateClient;
    const o = new Orchestrator({
      accumulate: acc, keyring: noKeyKeyring('human-only signer'), policy: new MockPolicyClient({ decision: 'approve' }),
      store, resolver: new Resolver(acc), logger: silent, humanOnlyPages: [BOARD_P1], readPage: chain.readPage,
    });
    const KEY = humanRecordId(BTX, BOARD_P1);
    expect((await o.handle({ txHash: BTX, signerUrl: BOARD_P1 })).status).toBe('awaiting_human');

    const p1 = await prepare(alice, { ref: BTX, page: BOARD_P1, vote: 'approve' });
    expect((await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: p1.json.prepareId, signature: await signPrepared(alice, p1.json) })).json.status).toBe('landed');
    expect(await store.get(KEY)).toMatchObject({ status: 'awaiting_human', humanSignatures: [{ seat: `key:${alice.keyHash}`, vote: 'approve' }] });

    const p2 = await prepare(bob, { ref: BTX, page: BOARD_P1, vote: 'approve' });
    await call(port, 'POST', '/relay/officer-signature', {}, { prepareId: p2.json.prepareId, signature: await signPrepared(bob, p2.json) });
    const done = await store.get(KEY);
    expect(done?.status).toBe('signed');
    expect(done?.humanSignatures?.map((s) => s.publicKeyHash).sort()).toEqual([alice.keyHash, bob.keyHash].sort());
  });
});
