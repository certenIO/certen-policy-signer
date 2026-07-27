/**
 * Smoke test: drive accumulate.js signing primitives exactly as api-bridge does,
 * and prove the produced Ed25519 signature is valid + deterministic.
 * Run: npx tsx scripts/smoke-signing.ts
 */
import coreNs from 'accumulate.js/core';
import commonNs from 'accumulate.js/common';
import encodingNs from 'accumulate.js/encoding';
import addressNs from 'accumulate.js/address';
import nacl from 'tweetnacl';

const core: any = (coreNs as any).default ?? coreNs;
const common: any = (commonNs as any).default ?? commonNs;
const encoding: any = (encodingNs as any).default ?? encodingNs;
const address: any = (addressNs as any).default ?? addressNs;

const { ED25519Signature, VoteType } = core;
const { sha256 } = common;
const { encode } = encoding;
const { URL: AccURL } = address;

console.log('VoteType =', VoteType ? JSON.stringify(VoteType) : '(none — vote is a raw number)');

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const concat = (...a: Uint8Array[]) => {
  const total = a.reduce((n, x) => n + x.length, 0);
  const out = new Uint8Array(total);
  let o = 0; for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};

// 1. deterministic keypair (fixed seed so the run is reproducible)
const seed = new Uint8Array(32).fill(7);
const kp = nacl.sign.keyPair.fromSeed(seed);
const publicKey = kp.publicKey;         // 32 bytes
const secretKey = kp.secretKey;         // 64 bytes

// 2. inputs
const signerUrl = 'acc://demo-org.acme/book/1';
const signerVersion = 3;
const timestamp = 1751630000000000;     // fixed microseconds
const txHash = new Uint8Array(32).fill(0xab);   // stand-in pending tx hash

// 3. build the ED25519Signature metadata object (approve => no explicit vote / default accept)
function buildSigMd(voteCode?: number) {
  const fields: any = {
    type: 'ed25519',
    publicKey,
    signer: AccURL.parse(signerUrl),
    signerVersion,
    timestamp,
  };
  if (voteCode !== undefined && voteCode !== 0) fields.vote = voteCode;
  const sig = new ED25519Signature(fields);
  const enc = encode(sig);
  return sha256(enc);
}

function sign(voteCode?: number) {
  const sigMdHash = buildSigMd(voteCode);                 // sha256(encode(sigMd))
  const dataForSignature = sha256(concat(sigMdHash, txHash));
  const signature = nacl.sign.detached(dataForSignature, secretKey);
  const ok = nacl.sign.detached.verify(dataForSignature, signature, publicKey);
  return { sigMdHash, dataForSignature, signature, ok };
}

// APPROVE path
const a1 = sign(0);
const a2 = sign(0);   // determinism check (same inputs)
console.log('\n--- APPROVE ---');
console.log('publicKey    ', hex(publicKey), `(len ${publicKey.length})`);
console.log('sigMdHash    ', hex(a1.sigMdHash));
console.log('dataForSig   ', hex(a1.dataForSignature), `(len ${a1.dataForSignature.length})`);
console.log('signature    ', hex(a1.signature), `(len ${a1.signature.length} bytes / ${hex(a1.signature).length} hex)`);
console.log('verify ok?   ', a1.ok);
console.log('deterministic?', hex(a1.dataForSignature) === hex(a2.dataForSignature) && hex(a1.signature) === hex(a2.signature));

// REJECT path (vote code differs -> different preimage)
const r1 = sign(1);
console.log('\n--- REJECT ---');
console.log('dataForSig   ', hex(r1.dataForSignature));
console.log('verify ok?   ', r1.ok);
console.log('reject != approve preimage?', hex(r1.dataForSignature) !== hex(a1.dataForSignature));

// assertions
const pass =
  a1.ok && a2.ok && r1.ok &&
  a1.signature.length === 64 &&
  a1.dataForSignature.length === 32 &&
  hex(a1.signature) === hex(a2.signature) &&
  hex(r1.dataForSignature) !== hex(a1.dataForSignature);

console.log('\n=== SMOKE', pass ? 'PASS ✅' : 'FAIL ❌', '===');
if (!pass) process.exit(1);
