/**
 * DAX-F177 open item (b), lead decision 2026-11-24: the Console replays a transaction from its OBSERVED signatures, the machine's INITIATING signature included. The relay's
 * GET /relay/tx/:hash/signatures therefore marks the initiating signature (the one whose outermost signature-metadata hash is header.initiator, as Accumulate records it) and
 * returns each signature's signer version. The fixtures are REAL Kermit records (FICTIONAL lab parties), copied from transaction-controls scenarios/reports/lib/fixtures.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { normalizeTxRecord, relaySignatureView, signatureMetadataHash } from '../src/accumulate/raw-client.js';

const here = dirname(fileURLToPath(import.meta.url));
/** The recorded transaction as the v3 query answers it (message.transaction, the signature messages under signatures). */
function v3(name: string, edit?: (header: Record<string, unknown>) => void): unknown {
  const r = JSON.parse(readFileSync(join(here, 'fixtures', `initiator-${name}.json`), 'utf8'));
  const transaction = JSON.parse(JSON.stringify(r.transaction));
  edit?.(transaction.header);
  return { id: r.txid, status: r.status, message: { type: 'transaction', transaction }, signatures: { records: r.signatures.map((s: { signature: unknown }) => ({ message: { type: 'signature', signature: s.signature } })) } };
}

describe('DAX-F177 (b): the initiating signature and the signer versions', () => {
  it('the metadata hash of the initiating signature is header.initiator (the encoding Accumulate hashes)', () => {
    const r = JSON.parse(readFileSync(join(here, 'fixtures', 'initiator-kermit-s6-ecdsa-header-authority.json'), 'utf8'));
    expect(signatureMetadataHash(r.signatures[0].signature)).toBe(r.transaction.header.initiator);
    expect(signatureMetadataHash(r.signatures[1].signature)).not.toBe(r.transaction.header.initiator);
  });

  it('marks exactly the initiating signature (a key page of the principal\'s book here) and carries every keyed signature\'s signer version', () => {
    const n = normalizeTxRecord(v3('kermit-s6-ecdsa-header-authority'));
    expect(n.header.initiator).toBe('f9c2d323da7dbdf9b09c39bfec8e1fb6c65c6108e1638108b032d888e290e185');
    expect(n.signatures.filter((s) => s.initiator).map((s) => s.signer)).toEqual(['acc://spk-6-cust-tcl1.acme/book/1']);
    for (const s of n.signatures.filter((x) => x.keyHash)) expect(Number.isInteger(s.signerVersion)).toBe(true);
  });

  it('marks the initiating signature when it is a separate initiator page (the erp pattern), and no other', () => {
    const n = normalizeTxRecord(v3('kermit-sp02-tier-a'));
    expect(n.signatures.filter((s) => s.initiator).map((s) => s.signer)).toEqual(['acc://harbor-mfg-erp-tcl1.acme/book/1']);
    expect(n.signatures.filter((s) => !s.initiator)).toHaveLength(3);
  });

  it('a header with no initiator, or one no signature matches, marks none (never guessed)', () => {
    expect(normalizeTxRecord(v3('kermit-sp02-tier-a', (h) => { delete h['initiator']; })).signatures.some((s) => s.initiator)).toBe(false);
    expect(normalizeTxRecord(v3('kermit-sp02-tier-a', (h) => { h['initiator'] = 'ab'.repeat(32); })).signatures.some((s) => s.initiator)).toBe(false);
  });

  it('the relay view of a signature carries initiator and signerVersion when they are known, and nothing else new', () => {
    const n = normalizeTxRecord(v3('kermit-s6-ecdsa-header-authority'));
    const views = n.signatures.map(relaySignatureView);
    expect(views.find((v) => v.initiator === true)).toMatchObject({ signer: 'acc://spk-6-cust-tcl1.acme/book/1', initiator: true, signerVersion: expect.any(Number) });
    expect(views.filter((v) => 'initiator' in v)).toHaveLength(1);
    expect(Object.keys(views.find((v) => !v.initiator)!).sort()).toEqual(['book', 'delegators', 'keyHash', 'signer', 'signerVersion', 'vote']);
  });
});
