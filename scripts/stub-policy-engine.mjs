/**
 * Stub policy engine for local testing .
 * Returns approve by default; set DECISION=deny to test the deny path.
 *   node scripts/stub-policy-engine.mjs           # approve on :9099
 *   DECISION=deny PORT=9099 node scripts/...
 */
import http from 'node:http';
const PORT = Number(process.env.PORT ?? 9099);
const DECISION = process.env.DECISION ?? 'approve';

http.createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return; }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    let summary = '(unparsed)';
    try { summary = JSON.parse(body).actionSummary; } catch {}
    console.log(`[stub-policy] ${DECISION.toUpperCase()} <- ${summary}`);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: DECISION, reason: `stub:${DECISION}`, evidence: { stub: true } }));
  });
}).listen(PORT, () => console.log(`[stub-policy] listening on :${PORT}, always ${DECISION}`));
