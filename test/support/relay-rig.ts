/**
 * A real HTTP relay (the signer's createRelayClientsHandler with scope `chain`) over a ReadCache on any ChainQuery, for the tests that look at what
 * a relay route ANSWERS on the wire. Loopback only, closed by `closeRelays()`.
 */
import http from 'node:http';
import { AddressInfo } from 'node:net';
import pino from 'pino';
import { ReadCache, type ReadCacheOptions } from '../../src/binding/read-cache.js';
import type { ChainQuery } from '../../src/binding/node-source.js';
import { createRelayClientsHandler } from '../../src/relay-clients.js';

const silent = pino({ level: 'silent' });
const KEY = 'console-client-key-0123456789';
const servers: http.Server[] = [];

export function closeRelays(): void {
  for (const s of servers.splice(0)) s.close();
}

export async function serveRelay(query: ChainQuery, opts: ReadCacheOptions = {}) {
  const cache = new ReadCache(query, opts);
  const handler = createRelayClientsHandler({
    reservedKeys: [], query: async () => ({}), evm: [], getPolicyRequest: async () => undefined, pages: () => [], logger: silent,
    clients: [{ name: 'console', key: KEY, scopes: ['chain'] }], chainReader: () => cache.evaluation(),
  });
  const server = http.createServer((req, res) => { void handler(req, res, new URL(req.url ?? '/', 'http://localhost')); });
  servers.push(server);
  const base = await new Promise<string>((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  /** GET one route; the body is the parsed JSON exactly as the Console's client would parse it */
  const get = async (path: string): Promise<{ status: number; body: unknown; headers: Headers }> => {
    const r = await fetch(base + path, { headers: { 'x-relay-client': 'console', 'x-api-key': KEY } });
    return { status: r.status, body: await r.json(), headers: r.headers };
  };
  return { cache, get };
}

export const enc = (u: string): string => encodeURIComponent(u);
