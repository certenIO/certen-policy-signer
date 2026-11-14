/**
 * READ-ONLY live precheck of the signer's chain reader against a running Accumulate v3 node (DAX-4S round 3; prepares the DAX-4 live smoke).
 *
 * It runs the production chain world (the same code the decision binding and the Console relay use: node source, read cache, core reader) on
 * the accounts of one grant scene and answers: does the world resolve the Grant head and the subject on the real node, and what does an
 * evaluation cost the node, cold and in steady state. It then serves each relay route once from the SAME cache and runs the Console's strict
 * parsers (test/support/console-relay-parsers.ts) over the answers.
 *
 * READ ONLY: no signature, no transaction, no key, no write. About thirty polite queries (bounded concurrency 4, no loop, no retry, no
 * transaction-by-id query). Run it ONCE; it refuses to run without the confirmation flag. The output is one JSON document on stdout.
 * test/binding-live-precheck.test.ts runs the same code offline over recorded answers.
 *
 *   npx tsx scripts/verify/reader-live-precheck.ts --confirm-read-only-once \
 *     --endpoint https://kermit.accumulatenetwork.io/v3 --grantor-adi acc://<adi> --grantor-book acc://<adi>/<book> \
 *     --grant-id <id> --subject acc://<adi>
 */
import pino from 'pino';
import { RawAccumulateClient } from '../../src/accumulate/raw-client.js';
import { createChainWorld } from '../../src/binding/chain-world.js';
import { ReadCache } from '../../src/binding/read-cache.js';
import { relayAccountRoute, type AccountRoute } from '../../src/binding/relay-routes.js';
import { parseAuthorities, parseChainLen, parseDataEntries, parseHistory, parseKeybook } from '../../test/support/console-relay-parsers.js';

export interface PrecheckParams { endpoint: string; grantorAdi: string; grantorBook: string; grantId: string; subject: string; nowSeconds?: () => number }

/** the whole precheck over any ChainQuery (the live script passes the node client; the unit test passes recorded answers) */
export async function runPrecheck(rawQuery: (scope: string, q?: unknown) => Promise<any>, p: PrecheckParams) {
  const { grantorAdi, grantorBook, grantId, subject } = p;
  const log: Array<{ n: number; scope: string; queryType: string; detail: string; ms: number; ok: boolean }> = [];
  const query = async (scope: string, q?: unknown): Promise<any> => {
    const qq = (q ?? { queryType: 'default' }) as { queryType: string; name?: string; minor?: number; range?: { start: number; count: number } };
    const t0 = Date.now();
    const detail = qq.minor !== undefined ? `minor ${qq.minor}` : qq.range ? `${qq.name} ${qq.range.start}+${qq.range.count}` : '';
    const entry = { n: log.length + 1, scope, queryType: qq.queryType, detail, ms: 0, ok: false };
    log.push(entry);
    try {
      const r = await rawQuery(scope, q);
      entry.ok = true;
      return r;
    } finally {
      entry.ms = Date.now() - t0;
    }
  };

  const cache = new ReadCache(query);
  const world = createChainWorld({ evaluation: () => cache.evaluation(), nowSeconds: p.nowSeconds ?? (() => Math.floor(Date.now() / 1000)) });
  const evaluate = () => world.establish({ grantorAdi, grantorBook, grantId, asserted: { adi: subject, assertedBy: grantorAdi } });
  const summary = (r: Awaited<ReturnType<typeof evaluate>>) => ({
    head: r.head.ok ? { ok: true, hash: r.head.value.hash, grant: r.head.value.grant } : { ok: false, detail: r.head.detail },
    subject: r.subject === null ? null : r.subject.ok ? { ok: true, ...r.subject.value } : { ok: false, detail: r.subject.detail },
    stats: r.stats,
  });

  const mark0 = log.length;
  const cold = await evaluate();
  const mark1 = log.length;
  const steady = await evaluate();
  const mark2 = log.length;

  // each relay route once, from the same cache, and the Console's strict parser over what it answered
  const grants = `${grantorAdi}/certen-grants`;
  const routes: Array<[AccountRoute, string, (v: unknown) => unknown]> = [
    ['data', grants, parseDataEntries], ['history', grants, parseHistory], ['authorities', grants, parseAuthorities], ['chainlen', grants, parseChainLen], ['keybook', grantorBook, parseKeybook],
  ];
  const relay: Array<{ route: string; account: string; status: number; consoleParses: boolean; body: unknown; queries: string }> = [];
  for (const [route, account, parser] of routes) {
    const a = await relayAccountRoute(cache.evaluation(), route, encodeURIComponent(account));
    const entries = route === 'data' && a.status === 200
      ? (a.body as { entries: Array<{ txId: string; time?: number }> }).entries.map((e) => ({ txId: e.txId, time: e.time ?? null, iso: e.time === undefined ? null : new Date(e.time * 1000).toISOString() }))
      : undefined;
    relay.push({ route, account, status: a.status, consoleParses: a.status === 200 && parser(a.body) !== null, body: entries === undefined ? a.body : { entries }, queries: a.headers['x-reader-queries'] ?? '' });
  }

  const slice = (a: number, b: number) => log.slice(a, b).map(({ n, scope, queryType, detail, ms, ok }) => ({ n, scope, queryType, detail, ms, ok }));
  return {
    endpoint: p.endpoint,
    at: new Date().toISOString(),
    readOnly: true,
    cold: { ...summary(cold), nodeQueries: mark1 - mark0, queries: slice(mark0, mark1) },
    steadyState: { ...summary(steady), nodeQueries: mark2 - mark1, queries: slice(mark1, mark2) },
    relay,
    totalNodeQueries: log.length,
    cacheTotals: cache.totals(),
  };
}

const arg = (name: string): string | undefined => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? undefined : process.argv[i + 1];
};

async function main(): Promise<void> {
  if (!process.argv.includes('--confirm-read-only-once')) throw new Error('pass --confirm-read-only-once: this reads a live node (about thirty queries) and is meant to run once');
  const endpoint = arg('endpoint');
  const grantorAdi = arg('grantor-adi');
  const grantorBook = arg('grantor-book');
  const grantId = arg('grant-id');
  const subject = arg('subject');
  if (!endpoint || !grantorAdi || !grantorBook || !grantId || !subject) throw new Error('--endpoint, --grantor-adi, --grantor-book, --grant-id and --subject are required');
  const client = new RawAccumulateClient(endpoint, pino({ level: 'silent' }), 20_000);
  const out = await runPrecheck((scope, q) => client.query(scope, q), { endpoint, grantorAdi, grantorBook, grantId, subject });
  console.log(JSON.stringify(out, null, 1));
}

// run only as a script, never when the test imports runPrecheck
if (/reader-live-precheck\.[tj]s$/.test(process.argv[1] ?? '')) {
  main().catch((e) => { console.error('precheck failed:', e instanceof Error ? e.message : String(e)); process.exit(1); });
}
