/**
 * The field the PRODUCER writes and the field this CONSUMER reads must be the same field.
 *
 * Two repos, two languages on the hashing side, and one key name holding them together. Nothing in
 * either repo's own suite notices if one side renames it: the producer keeps writing a valid blob, the
 * decoder keeps returning a valid summary with no subject on it, every test stays green, and the only
 * symptom is that a policy engine silently stops being told who a transaction is about — which looks
 * exactly like the absence case that is a legitimate, documented state. That is the worst shape of bug
 * available here, so it gets a test rather than an eye.
 *
 * Two assertions, deliberately different in kind:
 *
 *  1. BEHAVIOURAL, over the shared artifact. `certen-contracts/test/vectors/operation_id_test_vectors.json`
 *     already holds a subject-bearing blob 0 that BOTH the TypeScript producer's vector suite and the Go
 *     validator's hash against one pinned operationId. Feeding that same blob 0 through this repo's
 *     decoder makes it a three-way contract: the bytes the producer commits to are the bytes this
 *     consumer reads a subject out of.
 *
 *  2. NAME PARITY, over the producer's source. The members are optional, so a renamed `keyBook` would
 *     simply vanish rather than fail anything above. Reading `api-bridge`'s normalizer catches that.
 *     Skipped when the sibling repo is not checked out — the same convention the approval console's
 *     contract-drift test uses for the signer.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { decodeSummary } from '../src/resolver.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VECTORS = join(ROOT, '..', 'certen-contracts', 'test', 'vectors', 'operation_id_test_vectors.json');
const PRODUCER = join(ROOT, '..', 'api-bridge', 'src', 'CertenIntentService.ts');

/** The one vector both language suites pin, by its description. */
function subjectVector(): { blob0: Record<string, unknown>; blob1: unknown; blob2: unknown; blob3: unknown } {
  const all = JSON.parse(readFileSync(VECTORS, 'utf8')) as Array<Record<string, any>>;
  const v = all.find((x) => /subject/i.test(String(x.description)));
  if (!v) throw new Error('the shared vector file has no subject-bearing vector');
  return v as never;
}

describe('the shared golden vector decodes through this consumer', () => {
  it.runIf(existsSync(VECTORS))(
    'reads a subject out of the exact blob 0 that Go and TypeScript hash to one pinned operationId',
    () => {
      const v = subjectVector();
      const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
      const body = {
        type: 'writeData',
        entry: { type: 'doubleHash', data: [v.blob0, v.blob1, v.blob2, v.blob3].map(toHex) },
      };

      const { summary } = decodeSummary(body, 'acc://acme-bank.acme/data');

      // The producer's own vector says who this is about; the consumer must agree, member for member.
      const written = v.blob0.subject as Record<string, string>;
      expect(summary.subject).toEqual({
        adi: written.adi,
        keyBook: written.keyBook,
        id: written.id,
        assertedBy: written.assertedBy,
      });
    },
  );

  it.runIf(existsSync(VECTORS))('carries the vector as a real intent, not merely as a subject', () => {
    const v = subjectVector();
    const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
    const { summary, operationId } = decodeSummary(
      { type: 'writeData', entry: { type: 'doubleHash', data: [v.blob0, v.blob1, v.blob2, v.blob3].map(toHex) } },
      'acc://acme-bank.acme/data',
    );
    // If this stopped decoding as an intent the subject assertion above would be vacuous.
    expect(summary.values).toEqual(['1500']);
    expect(operationId).toBe(v.blob0.intent_id);
  });
});

/**
 * The repo's OWN producer — `scripts/verify/_lib.ts` — round-tripped through its own decoder.
 *
 * `intentBlobs` is what the live Kermit verification scripts and the customer demo both write, so it is
 * the producer this repo can actually execute. The absence case matters more than the presence one: every
 * existing caller passes two arguments, and blob 0 for those must be byte-identical to what it has
 * always been, or a fleet of verification scripts starts producing intents with a shape nobody expects.
 */
describe('the demo and verification producer round-trips through the decoder', () => {
  // `_lib.ts` pulls in the whole Accumulate SDK, which is slow to transform but does no I/O at import
  // time — only a client is constructed. Loaded once, with a timeout that reflects the transform cost.
  let intentBlobs: (amountWei: string, legs?: any[], subject?: { adi: string; keyBook?: string }) => string[];
  beforeAll(async () => {
    ({ intentBlobs } = await import('../scripts/verify/_lib.js'));
  }, 60_000);

  it('writes a subject the decoder reads back, member for member', () => {
    const claim = { adi: 'acc://alice.acme', keyBook: 'acc://alice.acme/book' };
    const body = { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs('1000', undefined, claim) } };
    const { summary } = decodeSummary(body, 'acc://a.acme/data');
    expect(summary.subject).toEqual(claim);
  });

  it('emits blob 0 byte-identical to today for every existing two-argument caller', () => {
    const blob0 = Buffer.from(intentBlobs('1')[0], 'hex').toString('utf8');
    // Pinned as a literal. A spread that leaked `"subject":null`, or any reordering, changes these bytes
    // and therefore changes the operationId of every intent these scripts have ever written.
    expect(blob0).toBe('{"kind":"CERTEN_INTENT","version":"2.0","intent_id":"i-1","description":"Transfer 1 wei"}');
    const { summary } = decodeSummary(
      { type: 'writeData', entry: { type: 'doubleHash', data: intentBlobs('1') } },
      'acc://a.acme/data',
    );
    expect('subject' in summary).toBe(false);
  });
});

describe('producer and consumer name the same members', () => {
  it.runIf(existsSync(PRODUCER))('api-bridge writes exactly the members this repo reads', () => {
    const producer = readFileSync(PRODUCER, 'utf8');

    // The producer's normalizer is the single place blob 0's subject shape is decided.
    const normalizer = producer.split('export function normalizeSubject')[1]?.split('\n}')[0];
    expect(normalizer, 'api-bridge has no exported normalizeSubject').toBeTruthy();

    for (const member of ['adi', 'keyBook', 'id', 'assertedBy']) {
      expect(normalizer, `the producer no longer writes \`${member}\``).toContain(member);
    }

    // And the key itself. A renamed key is the failure this whole file exists for.
    expect(producer, 'api-bridge no longer writes the `subject` key into blob 0').toMatch(/\{ "?subject"?: subject \}/);

    const consumer = readFileSync(join(ROOT, 'src', 'decode', 'decoders', 'certen-intent.ts'), 'utf8');
    expect(consumer, 'this repo no longer reads `intent.subject` out of blob 0').toContain('intent?.intent?.subject');
  });
});
