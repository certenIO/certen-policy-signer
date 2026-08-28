/**
 * The console must be able to see the authority that actually governs.
 *
 * Runbook F Phase F1 asks the approval console to render the live key page — threshold, membership,
 * delegates, version — instead of the number in its own deployment config. The console has no chain
 * code and must never acquire any (F-1), so everything it renders has to arrive over this admin API.
 *
 * Two things were missing and this file holds both:
 *
 *   readPage() read the version and the key hashes and threw the rest away. The threshold and the
 *   delegate entries were in the record it already had.
 *
 *   Nothing exposed it over HTTP at all. `readPage` is an in-process function; the admin surface had
 *   `/v1/admin/pubkey`, which answers "which key do we sign with", not "what will the network enforce".
 *
 * The case that decides the shape is the unreadable one. A page the signer cannot read must produce NO
 * numbers rather than zeroes: a threshold of 0 and an entry count of 0 are both plausible-looking
 * values, and a screen rendering them would state, in the console's own voice, that the chain requires
 * nobody's approval. Absent with a reason is the only honest answer, and it is what F-6 means here.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import pino from 'pino';
import { createServer, PauseController } from '../src/server.js';
import { readPage, PageState } from '../src/ops/rotate.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MockPolicyClient } from '../src/policy/policy.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner, LocalEcdsaP256Signer } from '../src/signer/signer.js';
import { MapKeyring, bookOf } from '../src/signer/keyring.js';

const silent = pino({ level: 'silent' });
const ADMIN_KEY = 'admin-secret-123';
const ADMIN = { 'x-api-key': ADMIN_KEY };
const ED_PAGE = 'acc://demo-org.acme/book/1';
const P256_PAGE = 'acc://demo-org.acme/roster/1';

/** A P-256 private key in PKCS#8 DER, so a second scope can sign with something that is not Ed25519. */
function p256Signer(): LocalEcdsaP256Signer {
  const { generateKeyPairSync } = require('node:crypto');
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return new LocalEcdsaP256Signer(privateKey.export({ type: 'pkcs8', format: 'der' }));
}

/** What `acc.query(page)` answers for a key page: the v3 record, as the network returns it. */
function pageRecord(o: { version?: number; acceptThreshold?: number; keys?: unknown[] }) {
  return { account: { type: 'keyPage', url: ED_PAGE, version: o.version ?? 1, acceptThreshold: o.acceptThreshold, keys: o.keys ?? [] } };
}

function build(pageState?: (page: string) => Promise<PageState>) {
  const acc = new MockAccumulateClient();
  const scopes = [
    { page: ED_PAGE, book: bookOf(ED_PAGE), signer: new LocalSigner(new Uint8Array(32).fill(9)) },
    { page: P256_PAGE, book: bookOf(P256_PAGE), signer: p256Signer() },
  ];
  const keyring = new MapKeyring(scopes);
  const store = new MemoryStore();
  const pause: PauseController = { paused: false };
  const orchestrator = new Orchestrator({
    accumulate: acc, keyring, policy: new MockPolicyClient({ decision: 'approve' }),
    store, resolver: new Resolver(acc), logger: silent, options: { isPaused: () => pause.paused },
  });
  return createServer({ orchestrator, store, keyring, accumulate: acc, pause, logger: silent, adminApiKey: ADMIN_KEY, pageState });
}

function get(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method: 'GET', path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const t = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode!, json: t ? JSON.parse(t) : undefined });
      });
    });
    r.on('error', reject);
    r.end();
  });
}

describe('readPage keeps what the page actually says', () => {
  const acc = (rec: unknown) => ({ query: async () => rec }) as any;

  it('reads the accept threshold, not just the version and the key hashes', async () => {
    const state = await readPage(acc(pageRecord({
      version: 7,
      acceptThreshold: 2,
      keys: [{ publicKeyHash: 'AA'.repeat(32) }, { publicKeyHash: 'BB'.repeat(32) }, { publicKeyHash: 'CC'.repeat(32) }],
    })), ED_PAGE);

    expect(state.version).toBe(7);
    expect(state.threshold).toBe(2);
    expect(state.keyHashes).toHaveLength(3);
    expect(state.entries).toHaveLength(3);
  });

  /**
   * The trap, and the reason this is asserted rather than assumed. `acceptThreshold` is `omitempty` in
   * the Go struct, so a page requiring one signature does not carry the field at all — and
   * protocol/authority.go `GetSignatureThreshold` reads a zero as ONE. Passing the raw value through
   * would put "threshold 0" on a screen: a page that needs nobody, which no page ever is.
   */
  it('reports a threshold of 1 where the chain omits the field, because that is what the protocol means by it', async () => {
    const absent = await readPage(acc(pageRecord({ keys: [{ publicKeyHash: 'AA'.repeat(32) }] })), ED_PAGE);
    expect(absent.threshold).toBe(1);

    const zero = await readPage(acc(pageRecord({ acceptThreshold: 0, keys: [{ publicKeyHash: 'AA'.repeat(32) }] })), ED_PAGE);
    expect(zero.threshold).toBe(1);
  });

  /**
   * A delegate entry is a seat filled by another key book, and it is the entry an employee's
   * certificate occupies under §0.4. It has no key hash of its own, so a reader that only collects
   * `publicKeyHash` sees a page with fewer entries than it has — and a threshold of 2 over what looks
   * like one entry reads as a misconfiguration rather than as a roster.
   */
  it('keeps delegate entries, which carry no key hash', async () => {
    const state = await readPage(acc(pageRecord({
      acceptThreshold: 2,
      keys: [
        { publicKeyHash: 'AA'.repeat(32) },
        { delegate: 'acc://demo-org.acme/alice/book' },
      ],
    })), ED_PAGE);

    expect(state.entries).toHaveLength(2);
    expect(state.entries[1]!.delegate).toBe('acc://demo-org.acme/alice/book');
    expect(state.entries[1]!.keyHash).toBeNull();
    expect(state.keyHashes).toEqual(['aa'.repeat(32)]);
  });
});

describe('GET /v1/admin/page', () => {
  let server: http.Server;
  let port: number;
  const start = (s: http.Server) => new Promise<void>((r) => { server = s; s.listen(0, '127.0.0.1', () => { port = (s.address() as AddressInfo).port; r(); }); });
  afterEach(() => new Promise<void>((r) => server.close(() => r())));

  const readable = async (page: string): Promise<PageState> => ({
    version: 4,
    threshold: 2,
    keyHashes: ['aa'.repeat(32)],
    entries: [{ keyHash: 'aa'.repeat(32), delegate: null }, { keyHash: null, delegate: `${page}-delegate` }],
  });

  it('reports the live threshold, membership, delegates and version for every scope', async () => {
    await start(build(readable));
    const { status, json } = await get(port, '/v1/admin/page', ADMIN);

    expect(status).toBe(200);
    expect(json.pages).toHaveLength(2);

    const ed = json.pages.find((p: any) => p.page === ED_PAGE);
    expect(ed.state.threshold).toBe(2);
    expect(ed.state.entry_count).toBe(2);
    expect(ed.state.version).toBe(4);
    expect(ed.state.entries[1].delegate).toBe(`${ED_PAGE}-delegate`);
    expect(ed.error).toBeUndefined();
  });

  /**
   * The signature type is on this route because the console must not infer it. A screen reading a
   * 64-character public key and printing "Ed25519" would be asserting something the signer never told
   * it — F-4 — and since F0 a scope's key may be a P-256 certificate whose public key is 91 bytes.
   */
  it('names each scope’s signature type rather than leaving it to be guessed from the key length', async () => {
    await start(build(readable));
    const { json } = await get(port, '/v1/admin/page', ADMIN);

    expect(json.pages.find((p: any) => p.page === ED_PAGE).signature_type).toBe('ed25519');
    expect(json.pages.find((p: any) => p.page === P256_PAGE).signature_type).toBe('ecdsaSha256');
  });

  /**
   * The case the shape exists for. An unreadable page yields a reason and NO numbers — never a
   * threshold of 0, which reads as a page requiring nobody.
   */
  it('says a page could not be read, and states no numbers about it', async () => {
    await start(build(async (page) => {
      if (page === P256_PAGE) throw new Error('connection refused');
      return readable(page);
    }));
    const { status, json } = await get(port, '/v1/admin/page', ADMIN);

    expect(status).toBe(200);
    const broken = json.pages.find((p: any) => p.page === P256_PAGE);
    expect(broken.state).toBeUndefined();
    expect(broken.error).toContain('connection refused');
    expect(JSON.stringify(broken)).not.toMatch(/\b0\b/);

    // The reachable scope still answers. One unreadable page is not an outage of the route.
    expect(json.pages.find((p: any) => p.page === ED_PAGE).state.threshold).toBe(2);
  });

  it('is an admin route: no key, no answer', async () => {
    await start(build(readable));
    expect((await get(port, '/v1/admin/page')).status).toBe(401);
    expect((await get(port, '/v1/admin/page', { 'x-api-key': 'wrong' })).status).toBe(401);
  });

  /**
   * A deployment whose signer has no chain client wired for reads gets a refusal that says so. The
   * alternative — an empty `pages` list — is indistinguishable at the console from a signer holding no
   * scopes, and would render as "this signer governs nothing".
   */
  it('refuses rather than answering emptily when no page reader is configured', async () => {
    await start(build(undefined));
    const { status, json } = await get(port, '/v1/admin/page', ADMIN);
    expect(status).toBe(403);
    expect(json.error).toMatch(/page state unavailable/i);
  });
});

describe('GET /v1/admin/pubkey', () => {
  let server: http.Server;
  let port: number;
  afterEach(() => new Promise<void>((r) => server.close(() => r())));

  it('names the signature type beside each key, and keeps the fields it already had', async () => {
    server = build(async () => ({ version: 1, threshold: 1, keyHashes: [], entries: [] }));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => { port = (server.address() as AddressInfo).port; r(); }));
    const { json } = await get(port, '/v1/admin/pubkey', ADMIN);

    const ed = json.signers.find((s: any) => s.page === ED_PAGE);
    expect(ed.signature_type).toBe('ed25519');
    expect(ed.public_key).toMatch(/^[a-f0-9]{64}$/);
    expect(ed.key_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(json.public_key).toBe(json.signers[0].public_key);

    // A P-256 public key is PKIX DER — 91 bytes, not 32. The length is exactly what a screen must not
    // read an algorithm out of, which is why the field above exists.
    const p256 = json.signers.find((s: any) => s.page === P256_PAGE);
    expect(p256.signature_type).toBe('ecdsaSha256');
    expect(p256.public_key.length).toBe(182);
  });
});
