/**
 * Phase 7 personal signing: display + tcl-summary/v1, officer authentication, officer intake, proposals,
 * delegate consent, intake-only boot. FICTIONAL Business Transaction Controls lab.
 *
 * Every key here is generated inside the test by WebCrypto as NON-EXTRACTABLE and lives only in memory; no key
 * material is committed. Every party, page and credential string is FICTIONAL.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import { createHash, verify as nodeVerify, createPublicKey, webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { p256 } from '@noble/curves/nist.js';
import { tclSummaryV1, buildDisplay, buildProposalDisplay, awaitingGovernanceRequest, withDisplay } from '../src/display.js';
import { createOfficerIntake, OfficerIntake, IntakeChain } from '../src/officer/intake.js';
import { officerAuthMessage } from '../src/officer/auth.js';
import { createRelayClientsHandler } from '../src/relay-clients.js';
import { createServer } from '../src/server.js';
import { MemoryStore } from '../src/store/store.js';
import { buildSigMetaHash, concatBytes, bytesToHex, hexToBytes } from '../src/accumulate/signing.js';
import { core } from '../src/accumulate/sdk.js';
import { loadConfig, isIntakeOnly } from '../src/config.js';
import { startIntakeOnly } from '../src/intake-only.js';
import type { PageState } from '../src/ops/rotate.js';
import type { KeyPageResult } from '../src/ops/keypage.js';
import type { PolicyRequest } from '../src/types.js';

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
  sigs = new Map<string, Array<{ type: string; publicKeyHash: string; delegators: string[]; signer?: string }>>();
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
    while (s.type === 'delegated') { delegators.unshift(String(s.delegator)); s = s.signature; }
    const hash = String(s.transactionHash);
    if (this.land) {
      const list = this.sigs.get(hash) ?? [];
      list.push({ type: s.type, publicKeyHash: createHash('sha256').update(Buffer.from(s.publicKey, 'hex')).digest('hex'), delegators, signer: String(s.signer) });
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
  chain.pending.set(TX, { principal: PRINCIPAL, body: { type: 'writeData', entry: { type: 'doubleHash', data: ['00'] } } });
  store = new MemoryStore();
  await store.savePolicyRequest(withDisplay({ requestId: 'r1', txHash: TX, account: PRINCIPAL, actionSummary: 'FICTIONAL payment', expiresAt: '2026-09-20T00:00:00Z', bodyType: 'writeData' }));
  intake = createOfficerIntake({
    humanPages: [HARBOR_P1, TREASURY_P1, ISSUANCE_P1], chain, readPage: chain.readPage,
    getPolicyRequest: (h) => store.getPolicyRequest(h), landedTimeoutMs: 150, pollIntervalMs: 10, logger: silent,
  });
  awaitingOps.length = 0;
  const relayClients = createRelayClientsHandler({
    clients: [{ name: 'harbor-console', key: CONSOLE_KEY, scopes: ['pending', 'tx', 'governance'] }], reservedKeys: [GOV_KEY],
    query: async () => { throw new Error('not found'); }, evm: [], getPolicyRequest: (h) => store.getPolicyRequest(h),
    governanceKey: GOV_KEY, pages: () => [ISSUANCE_P1],
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
