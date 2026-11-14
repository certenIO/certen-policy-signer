/**
 * DAX-4-A17 (DE-64): the validator operation id is RECOMPUTED from the four blobs of a pending transaction's own data entry
 * and equals the validator's value on the recorded fixture; a request built from the blob-0 intent_id or from the blob-3
 * intent_hash in that field is refused as a request mismatch.
 *
 * The fixture is test/fixtures/validator-operation-id.json: 10 FICTIONAL intents as the real api-bridge code published them
 * (DAX-3B), with the validator's own id computed in Go (the validator pipeline, ComputeCanonical4BlobHash copied from the
 * validator) and the Go-verified canonical text of every blob. See its _provenance member.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalBlob, OperationIdError, validatorOperationId } from '../src/binding/operation-id.js';
import { buildPresentedRequest } from '../src/binding/request.js';
import { bindDecision } from '../src/core/decision-binding.js';
import { hashRequest } from '../src/core/hashes.js';
import { APPROVER, POLICY, SEAT, H, record } from './support/binding-fixtures.js';

interface Vec { site: string; case: string; raw: string[]; tsCanonical: string[]; bridgeIntentHash: string; bridgeRecomputedId: string; validatorOperationId: string }
const fixture = JSON.parse(readFileSync(new URL('./fixtures/validator-operation-id.json', import.meta.url), 'utf8')) as { vectors: Vec[] };
const bytes = (v: Vec): Uint8Array[] => v.raw.map((t) => new Uint8Array(Buffer.from(t, 'utf8')));
const utf8 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'utf8'));
const canon = (s: string): string => Buffer.from(canonicalBlob(utf8(s))).toString('utf8');
// test text is built from code points: this tool chain decodes backslash-u escapes and halves backslash runs
const BS = String.fromCharCode(92);
const cp = (n: number): string => String.fromCodePoint(n);

describe('the validator operation id, recomputed from the four blobs (DAX-4-A17)', () => {
  it('has the recorded fixture the Go value of the DAX-3B record belongs to', () => {
    const first = fixture.vectors.find((v) => v.site === 'S1.builder' && v.case === 'plain')!;
    // run-output.txt of go-same-bytes: "validator OperationID over the blobs as published 0xf857e50f...48ff"
    expect(first.validatorOperationId).toBe('0xf857e50f8400b91650f65de4e1614999b0ce7f1d92f6c2d295c831008ad048ff');
    expect(fixture.vectors.length).toBe(10);
  });

  it('equals the validator value on every recorded fixture', () => {
    for (const v of fixture.vectors) expect(validatorOperationId(bytes(v)), `${v.site}/${v.case}`).toBe(v.validatorOperationId);
  });

  it('canonicalises every blob to the bytes Go proved equal (tsCanonical)', () => {
    for (const v of fixture.vectors) bytes(v).forEach((b, i) => expect(Buffer.from(canonicalBlob(b)).toString('utf8'), `${v.site}/${v.case} blob ${i}`).toBe(v.tsCanonical[i]));
  });

  it('is NOT the bridge intent_hash of blob 3, and with that field blanked it IS (the finding DAX3B-F2)', () => {
    for (const v of fixture.vectors) {
      expect(validatorOperationId(bytes(v))).not.toBe(v.bridgeIntentHash);
      const blanked = bytes(v);
      blanked[3] = utf8(JSON.stringify({ ...JSON.parse(v.raw[3]!), intent_hash: '' }));
      expect(validatorOperationId(blanked), `${v.site}/${v.case}`).toBe(v.bridgeRecomputedId);
    }
  });

  it('moves with any member of any blob (a changed member changes the id)', () => {
    const v = fixture.vectors[0]!;
    const base = validatorOperationId(bytes(v));
    for (let i = 0; i < 4; i++) {
      const changed = bytes(v);
      changed[i] = utf8(JSON.stringify({ ...JSON.parse(v.raw[i]!), zzz: 1 }));
      expect(validatorOperationId(changed)).not.toBe(base);
    }
  });

  it('refuses what Go refuses or what it would read differently, by name', () => {
    const ok = bytes(fixture.vectors[0]!);
    expect(() => validatorOperationId(ok.slice(0, 3))).toThrow(OperationIdError);
    expect(() => canonicalBlob(new Uint8Array([0xff, 0xfe]))).toThrow(/blob_not_utf8/);
    expect(() => canonicalBlob(utf8('{"a":'))).toThrow(/blob_not_json/);
    expect(() => canonicalBlob(utf8('{"a":1e999}'))).toThrow(/blob_number_overflow/);
  });

  it('reproduces the Go encoder on the edge cases: key order by UTF-8 bytes, HTML escapes, -0, exponent form', () => {
    const e = cp(0xe9), ffe0 = cp(0xffe0), emoji = cp(0x1f600);
    // UTF-8 byte order puts U+FFE0 before the emoji; UTF-16 code unit order (the JavaScript default) would not
    expect(canon(`{"b":1,"a":2,"${emoji}":4,"${ffe0}":5,"${e}":3}`)).toBe(`{"a":2,"b":1,"${e}":3,"${ffe0}":5,"${emoji}":4}`);
    expect(canon(`{"x":"<a&b>${cp(0x2028)}"}`)).toBe(`{"x":"${BS}u003ca${BS}u0026b${BS}u003e${BS}u2028"}`);
    expect(canon('[-0,0,1e21,1e-7,0.1,123456789012345680000]')).toBe('[-0,0,1e+21,1e-7,0.1,123456789012345680000]');
    // control characters, DEL, a lone surrogate escape and an escaped slash: the output of go1.25.1 on the same input (evidence go-edge-out.json)
    expect(canon('{"c":"a' + BS + 'u0008b' + BS + 'u000cc' + BS + 'u0001d' + BS + 'u007fe' + BS + 'ud800f' + BS + '/g"}')).toBe('{"c":"a' + BS + 'bb' + BS + 'fc' + BS + 'u0001d' + cp(0x7f) + 'e' + cp(0xfffd) + 'f/g"}');
  });
});

describe('a request built from another id is refused as a request mismatch (DE-64)', () => {
  const NOW = 1_800_000_000;
  const vec = fixture.vectors.find((x) => x.site === 'S1.builder' && x.case === 'plain')!;
  const body = { type: 'writeData', entry: { type: 'doubleHash', data: vec.raw.map((t) => Buffer.from(t, 'utf8').toString('hex')) } };

  it('binds the validator id: a request built with that id passes, built with any other id is request_mismatch', () => {
    const built = buildPresentedRequest({ txHash: H('tx-a').slice(2), rawTransaction: { body }, summary: { action: 'x' } });
    if (!built.ok) throw new Error(built.detail);
    expect(built.value.operationId).toBe(vec.validatorOperationId);
    expect(built.value.request['operationId']).toBe(vec.validatorOperationId);

    const intentId = JSON.parse(vec.raw[0]!).intent_id as string;
    const state = { requireGrant: false, grantHeadHash: null, grantHeadSubject: null, expectedPolicyHash: POLICY, authorizedApprovers: [APPROVER], consumed: [], maxWindowSeconds: 86400 };
    // the decision is about a request whose `operationId` is the given value; the signer presents the request it built from the blobs
    const run = (operationId: string): unknown =>
      bindDecision({
        state, now: NOW,
        decision: record({ requestHash: hashRequest({ ...built.value.request, operationId }), issuedAt: NOW - 1, nonce: H('n-' + operationId) }),
        presented: { request: built.value.request, grantRefHash: null, seat: SEAT, subject: null },
      });
    expect(run(vec.validatorOperationId)).toMatchObject({ ok: true });
    // the blob-3 intent_hash the bridge published, and a 32-byte value derived from the blob-0 intent_id UUID
    expect(run(vec.bridgeIntentHash)).toMatchObject({ ok: false, reason: 'request_mismatch' });
    expect(run('0x' + createHash('sha256').update(intentId).digest('hex'))).toMatchObject({ ok: false, reason: 'request_mismatch' });
    expect(run(H('anything else'))).toMatchObject({ ok: false, reason: 'request_mismatch' });
    // the bare UUID cannot even be hashed as a request member
    expect(() => hashRequest({ ...built.value.request, operationId: intentId })).toThrow();
  });
});
