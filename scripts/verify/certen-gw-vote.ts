/**
 * Cast a vote on a pending transaction with a locally held key — the fixture-side counterpart to
 * the gateway's signing path, used to move test fixtures along.
 *
 *   node node_modules/tsx/dist/cli.mjs scripts/verify/certen-gw-vote.ts <who> <txHash> [vote]
 *
 * who: a | c  (ADI-A or ADI-C from $PHASE0_STATE)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { readFileSync, existsSync } from 'node:fs';
import nacl from 'tweetnacl';
import { raw, query, sleep, core, S, msg, nextTs } from './_lib.js';

const STATE_PATH = process.env.PHASE0_STATE ?? 'phase0-state.json';
const state: any = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};

function keyFromSeed(seedHex: string) {
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(seedHex, 'hex')));
  return S.ED25519Key.from ? S.ED25519Key.from(kp.secretKey) : new S.ED25519Key(kp.secretKey);
}

async function main() {
  const who = String(process.argv[2] ?? 'c').toLowerCase();
  const txHash = String(process.argv[3] ?? '').replace(/^acc:\/\//, '').split('@')[0];
  const vote = String(process.argv[4] ?? 'accept');
  const src = who === 'a' ? state.adiA : state.adiC;
  if (!src) throw new Error(`no ADI-${who.toUpperCase()} in state`);

  const key = keyFromSeed(src.seedHex);
  const version = (await raw.getSignerInfo(src.page)).version;

  // Do not vote before the transaction resolves on this signer's partition: the signature would be
  // valid and would attach to nothing.
  for (let i = 0; i < 25; i++) {
    if (await query(`acc://${txHash}@${src.page.replace(/^acc:\/\//, '')}`).catch(() => undefined)) break;
    if (i === 24) throw new Error(`${txHash} never resolved on ${src.page}`);
    await sleep(5000);
  }

  const sig = await S.Signer.forPage(src.page, key).withVersion(version).sign(
    { hash: () => Buffer.from(txHash, 'hex') } as any,
    { timestamp: nextTs(), vote: vote === 'reject' ? core.VoteType.Reject : core.VoteType.Accept },
  );
  const r: any = await raw.submit(
    new msg.Envelope({ signatures: [sig], txHash: Buffer.from(txHash, 'hex') }).asObject(),
  );
  console.log('submit ok:', r.ok);
  // The per-message statuses are the only place a dropped vote shows up; v2/v3 execute reports
  // success regardless.
  console.log(JSON.stringify(r.result ?? r).slice(0, 800));
}

main().catch((e) => { console.error('FAILED:', e?.message ?? e); process.exit(1); });
