/**
 * Submit a signature produced by the BROWSER EXTENSION and drive the transaction to a terminal state.
 *
 * Companion to certen-kv-browser.ts. That script provisions a header-authority fixture the extension
 * can sign; the page then calls `window.certen.signHash({hash: dataForSignature, address, keyType})`
 * — the same call `certen-web-app/src/services/keyvault.service.ts` makes — and returns a detached
 * signature. This assembles it into a signature-only envelope and submits it.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-kv-submit.ts <signatureHex> [vote]
 *
 * Reads $KV_STATE (default ./kv-browser-state.json) for txHash, signer, signerVersion, timestamp and
 * the public key — every one of which must match what the preimage was built from. A mismatch in any
 * of them yields a signature that is valid over nothing.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync } from 'node:fs';
import { raw, sleep, core, msg, txState } from './_lib.js';

const STATE_PATH = process.env.KV_STATE ?? 'kv-browser-state.json';
const state: any = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
const bytes = (h: string) => new Uint8Array(Buffer.from(h.replace(/^0x/, ''), 'hex'));

const signature = (process.argv[2] ?? '').replace(/^0x/, '').toLowerCase();
const vote = process.argv[3] ?? 'approve';
if (!/^[0-9a-f]{128}$/.test(signature)) throw new Error('usage: certen-kv-submit.ts <signatureHex128> [vote]');

const { transactionHash, signer, signerVersion, timestamp } = state.signArgs ?? {};
if (!transactionHash) throw new Error('no signArgs in state — run certen-kv-browser.ts first');

async function main() {
  console.log('tx       :', transactionHash);
  console.log('signer   :', signer, 'v' + signerVersion);
  console.log('timestamp:', timestamp);

  // Rebuild the signature exactly as the preimage was built. The extension signed a bare hash, so
  // every other field here is ours to restate correctly — and any drift makes the signature verify
  // against a preimage nobody computed.
  const sig = new (core as any).ED25519Signature({
    publicKey: bytes(state.pubKey),
    signature: bytes(signature),
    signer,
    signerVersion: Number(signerVersion),
    timestamp: Number(timestamp),
    transactionHash: bytes(transactionHash),
    // Accept is vote 0 and is omitted by marshaling — setting it explicitly is byte-identical to
    // leaving it out, but omitting keeps this identical to what the signer produced.
    ...(vote === 'approve' ? {} : { vote }),
  });

  const env = new msg.Envelope({ signatures: [sig], txHash: bytes(transactionHash) });
  const r: any = await raw.submit(env.asObject());
  console.log('\nsubmit ->', JSON.stringify(r).slice(0, 600));

  // A signature-only envelope normalises into TWO messages: the signature, and a RemoteTransaction
  // placeholder. They carry INDEPENDENT codes, and `notFound` on the placeholder means the vote was
  // silently dropped — the submit still looks successful.
  const results = r?.result ?? [];
  const dropped = results.filter((x: any) => x?.status?.code && !['ok', 'delivered', 'pending'].includes(x.status.code));
  if (dropped.length) {
    console.log('\nDROPPED:', JSON.stringify(dropped).slice(0, 400));
    throw new Error('the vote did not land');
  }

  const want = vote === 'reject' ? 'rejected' : 'delivered';
  for (let i = 0; i < 40; i++) {
    const st = await txState(transactionHash, state.fixture.principal);
    console.log(`  [${i}] ${transactionHash.slice(0, 12)} state=${st}`);
    if (st === want) { console.log(`\nBROWSER EXTENSION SIGNING PASS - transaction ${st}`); return; }
    if (['delivered', 'rejected', 'expired'].includes(st)) throw new Error(`terminal ${st}, wanted ${want}`);
    await sleep(8000);
  }
  throw new Error('never reached a terminal state');
}

main().catch((e) => { console.error('\nFAILED:', e?.message ?? e); process.exit(1); });
