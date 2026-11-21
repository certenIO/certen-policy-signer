/**
 * AGT-F117 (lead 2026-11-21): the AGT lab's officers are DELEGATES - their own books are entries on the principal's officers page (the human page),
 * and each officer's ed25519 key sits on a page of their own book. Officer auth accepted only a key hash listed DIRECTLY on a human page, so every
 * delegated officer was refused (key_not_on_human_page) although the intake's prepare walks delegation. The header may now name where the key sits and
 * the delegation path (as the prepare body does); auth then requires the key on that page, each hop a delegate entry, and the outermost a human page.
 * FICTIONAL parties.
 */
import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign as nodeSign, createHash } from 'node:crypto';
import pino from 'pino';
import { createOfficerAuthenticator, officerAuthMessage, parseOfficerAuthHeader, OFFICER_AUTH_HEADER } from '../src/officer/auth.js';
import type { PageState } from '../src/ops/rotate.js';

const silent = pino({ level: 'silent' });
const OFFICERS = 'acc://fict-principal-1.acme/book/3';
const OFFICER_PAGE = 'acc://fict-officer-1.acme/book/1';
const OTHER_PAGE = 'acc://fict-outsider.acme/book/1';

function officer() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  return { raw, hash: createHash('sha256').update(raw).digest('hex'), sign: (m: Uint8Array) => nodeSign(null, m, privateKey) };
}
const page = (keyHashes: string[], delegates: string[] = []): PageState => ({
  version: 1, threshold: 1, keyHashes, entries: [...keyHashes.map((k) => ({ keyHash: k, delegate: null })), ...delegates.map((d) => ({ keyHash: null, delegate: d }))],
} as unknown as PageState);

function header(o: ReturnType<typeof officer>, method: string, path: string, extra = '', ts = String(Date.now())) {
  const sig = o.sign(officerAuthMessage(method, path, ts));
  return `v1 key=${o.raw.toString('hex')},ts=${ts},sig=${Buffer.from(sig).toString('hex')}${extra}`;
}
const req = (h: string, method = 'POST', url = '/relay/officer-signature/prepare') => ({ headers: { [OFFICER_AUTH_HEADER]: h }, method, url }) as never;

describe('AGT-F117: a delegated officer authenticates through the delegation path, and only through it', () => {
  const o = officer();
  const pages: Record<string, PageState> = {
    [OFFICERS]: page([], ['acc://fict-officer-1.acme/book']),
    [OFFICER_PAGE]: page([o.hash]),
    [OTHER_PAGE]: page([o.hash]),
  };
  const auth = createOfficerAuthenticator({ humanPages: [OFFICERS], readPage: async (p) => { const s = pages[p]; if (!s) throw new Error('no such page'); return s; }, logger: silent });

  it('without the path, a key that sits only on the officer\'s own page is refused (unchanged direct check)', async () => {
    expect(await auth(req(header(o, 'POST', '/relay/officer-signature/prepare')))).toBeUndefined();
  });

  it('with page + delegators: accepted, and the human page reached is the officers page', async () => {
    const a = await auth(req(header(o, 'POST', '/relay/officer-signature/prepare', `,page=${OFFICER_PAGE},delegators=${OFFICERS}`)));
    expect(a?.pages).toEqual([OFFICERS]);
    expect(a?.key.type).toBe('ed25519');
  });

  it('refused: the key not on the named page, a book that is not a delegate there, an outermost page that is not a human page, a path with no page', async () => {
    const stranger = officer();
    expect(await auth(req(header(stranger, 'POST', '/x', `,page=${OFFICER_PAGE},delegators=${OFFICERS}`), 'POST', '/x'))).toBeUndefined();
    expect(await auth(req(header(o, 'POST', '/x', `,page=${OTHER_PAGE},delegators=${OFFICERS}`), 'POST', '/x'))).toBeUndefined();
    expect(await auth(req(header(o, 'POST', '/x', `,page=${OFFICER_PAGE}`), 'POST', '/x'))).toBeUndefined();
    expect(parseOfficerAuthHeader(header(o, 'POST', '/x', `,delegators=${OFFICERS}`))).toBeUndefined();
  });

  it('the hints do not weaken the signature: a header signed for another path, or stale, is refused', async () => {
    expect(await auth(req(header(o, 'POST', '/other', `,page=${OFFICER_PAGE},delegators=${OFFICERS}`)))).toBeUndefined();
    expect(await auth(req(header(o, 'POST', '/relay/officer-signature/prepare', `,page=${OFFICER_PAGE},delegators=${OFFICERS}`, String(Date.now() - 10 * 60_000))))).toBeUndefined();
  });

  it('an unreadable page on the path is a refusal, never a pass', async () => {
    const flaky = createOfficerAuthenticator({ humanPages: [OFFICERS], readPage: async (p) => { if (p === OFFICERS) throw new Error('503'); return pages[p]!; }, logger: silent });
    expect(await flaky(req(header(o, 'POST', '/relay/officer-signature/prepare', `,page=${OFFICER_PAGE},delegators=${OFFICERS}`)))).toBeUndefined();
  });

  it('at most four delegators; anything else in the header is refused', () => {
    const five = Array.from({ length: 5 }, (_, i) => `acc://fict-d${i}.acme/book/1`).join(';');
    expect(parseOfficerAuthHeader(header(o, 'POST', '/x', `,page=${OFFICER_PAGE},delegators=${five}`))).toBeUndefined();
    expect(parseOfficerAuthHeader(header(o, 'POST', '/x', `,page=not-a-url`))).toBeUndefined();
  });
});
