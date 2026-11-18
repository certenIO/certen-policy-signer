/**
 * AGT-3: the Console's person-held AGENT pause reaches the signer's persisted pause through the relay (scope `pause`), and the signer
 * reads that pause before EVERY signature, a reject vote included (orchestrator pausedFor -> PauseStore.check -> core
 * checkSigningFromText). A subject pause needs a named seat and a reason (the core's rules); a resume of one scope does not lift
 * another; a client without the scope gets 403. FICTIONAL parties.
 */
import { afterEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import pino from 'pino';
import { createRelayClientsHandler } from '../src/relay-clients.js';
import { memoryPauseStore } from '../src/binding/pause-store.js';

const AGENT = 'acc://agent-7.harbor-mfg.acme';
const SEAT = 'seat:harbor-treasury';
const KEY = 'console-client-key-0123456789';
const CHAIN_ONLY = 'chain-only-client-key-0123456789';
const servers: http.Server[] = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });

async function start() {
  const pause = memoryPauseStore([SEAT]);
  const handler = createRelayClientsHandler({
    clients: [{ name: 'console', key: KEY, scopes: ['chain', 'pause'] }, { name: 'reader', key: CHAIN_ONLY, scopes: ['chain'] }],
    reservedKeys: [], query: async () => ({}), evm: [], getPolicyRequest: async () => undefined, pages: () => [], logger: pino({ level: 'silent' }), pause,
  });
  const server = http.createServer((req, res) => { void handler(req, res, new URL(req.url ?? '/', 'http://localhost')); });
  servers.push(server);
  const base = await new Promise<string>((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  const call = async (path: string, body?: unknown, client = 'console', key = KEY) => {
    const r = await fetch(base + path, { method: body === undefined ? 'GET' : 'POST', headers: { 'x-relay-client': client, 'x-api-key': key, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: r.status, json: (await r.json()) as any };
  };
  return { pause, call };
}
const op = (over: Record<string, unknown> = {}) => ({ scope: 'subject', id: AGENT, by: 'seat:harbor-supervisor', reason: 'Agent sent an odd vendor list; holding it.', ...over });

describe('the agent pause through the relay, enforced before every signature', () => {
  it('a subject pause set through the relay stops the signer signing for that agent, a reject vote included; resume restores it', async () => {
    const { pause, call } = await start();
    expect(pause.check({ seat: SEAT, subject: AGENT, vote: 'approve' })).toEqual({ ok: true });
    const set = await call('/relay/pause', op());
    expect(set.status).toBe(200);
    expect(set.json.pauses).toMatchObject([{ scope: 'subject', id: AGENT, by: 'seat:harbor-supervisor' }]);
    expect(pause.check({ seat: SEAT, subject: AGENT, vote: 'approve' })).toMatchObject({ ok: false, reason: 'paused', scope: 'subject', id: AGENT });
    expect(pause.check({ seat: SEAT, subject: AGENT, vote: 'reject' })).toMatchObject({ ok: false, reason: 'paused' });
    expect(pause.check({ seat: SEAT, subject: 'acc://agent-8.harbor-mfg.acme', vote: 'approve' })).toEqual({ ok: true }); // another agent is not paused
    expect((await call('/relay/pause')).json.pauses).toHaveLength(1);
    const back = await call('/relay/resume', op({ reason: 'Vendor list checked with procurement.' }));
    expect(back.status).toBe(200);
    expect(pause.check({ seat: SEAT, subject: AGENT, vote: 'approve' })).toEqual({ ok: true });
  });
  it('the core\'s rules: no named seat, a short reason, a resume of what is not paused, a seat scope, an extra member: refused by name, nothing set', async () => {
    const { pause, call } = await start();
    expect((await call('/relay/pause', op({ by: 'harbor-supervisor' }))).status).toBe(400);
    expect((await call('/relay/pause', op({ reason: 'short' }))).status).toBe(400);
    expect((await call('/relay/resume', op())).status).toBe(409);
    expect((await call('/relay/pause', op({ scope: 'seat', id: SEAT }))).status).toBe(400);
    expect((await call('/relay/pause', { ...op(), extra: 1 })).status).toBe(400);
    expect(pause.snapshot().pauses).toEqual([]);
  });
  it('a subject resume does not lift a seat pause (DE-27); a client without scope pause is 403', async () => {
    const { pause, call } = await start();
    await pause.set({ scope: 'seat', id: SEAT, by: 'seat:harbor-admin', reason: 'Seat-wide hold for the audit.' });
    await call('/relay/pause', op());
    await call('/relay/resume', op({ reason: 'Vendor list checked with procurement.' }));
    expect(pause.check({ seat: SEAT, subject: AGENT, vote: 'approve' })).toMatchObject({ ok: false, scope: 'seat' });
    expect((await call('/relay/pause', op(), 'reader', CHAIN_ONLY)).status).toBe(403);
    expect((await call('/relay/pause', undefined, 'reader', CHAIN_ONLY)).status).toBe(403);
  });
});
