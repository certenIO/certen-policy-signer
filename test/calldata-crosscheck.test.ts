/**
 * DAX7A-F2, the CROSS-CHECK: two readers of the same bytes can disagree. The 50 golden calldata cases of the strict core decoder
 * (transaction-controls pl/dax-7a-core-decoder head fc1a901444038cc53654ac0c85b1f001cc0e4c8a, packages/core/fixtures/calldata-golden.json,
 * copied byte for byte to test/fixtures/calldata-golden-dax7a-fc1a901.json; FICTIONAL parties and tokens) are run through BOTH
 * calldata readings the signer has:
 *   MAPPING  the request builder that DECIDES what a signature binds (src/binding/request.ts, from a one-leg intent), and
 *   READER   the calldata reading that DESCRIBES the transaction to a policy engine (decodeErc20Calldata, certen-intent.ts).
 * Every disagreement with the strict decoder is recorded below by id with its direction; the strict decoder is NOT changed here.
 *   SAFE-SIDE: the strict decoder understands more than the signer, which refuses (an approval needs a decoder, never a guess).
 *   UNSAFE-SIDE: the signer accepts what the strict decoder refuses as malformed; the test pins each one so a change is seen.
 *   SCOPE: the signer binds raw base units and addresses and has no token registry, so a case the strict decoder leaves `token_unknown`
 *          is bound as written (the display units are the Console's and DAX-7's business, not the binding's).
 * The test fails when the set of disagreements changes in either direction.
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decodeErc20Calldata } from '../src/decode/decoders/certen-intent.js';
import { buildPresentedRequest } from '../src/binding/request.js';
import { H, genuineCommitment } from './support/binding-fixtures.js';

const raw = readFileSync(new URL('./fixtures/calldata-golden-dax7a-fc1a901.json', import.meta.url));
interface Golden { id: string; title: string; input: any; expect: Record<string, any> }
const golden = JSON.parse(raw.toString('utf8')) as { cases: Golden[] };

const hex = (o: unknown): string => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
/** a one-leg intent whose leg is the golden execution input */
function mapping(input: any): { ok: true; request: Record<string, string | number> } | { ok: false; detail: string } | { notAnExecution: true } {
  if (typeof input !== 'object' || input === null || Array.isArray(input) || typeof input.source !== 'string' || typeof input.target !== 'string' || input.chainId === undefined) return { notAnExecution: true };
  const leg = { legId: 'leg-1', from: input.source, to: input.target, amountWei: input.value, executionPayload: { target: input.target, value: input.value, callData: input.calldata, chainId: input.chainId, executionCommitment: genuineCommitment({ target: input.target, value: input.value, callData: input.calldata, chainId: input.chainId }) ?? H('commit') } };
  const data = [{ kind: 'CERTEN_INTENT', intent_id: 'i' }, { protocol: 'CERTEN', legs: [leg] }, { authorization: {} }, { nonce: 'n' }].map(hex);
  const r = buildPresentedRequest({ txHash: 'ab'.repeat(32), rawTransaction: { body: { type: 'writeData', entry: { data } } }, summary: { action: 'x' } });
  return r.ok ? { ok: true, request: r.value.request } : { ok: false, detail: r.detail };
}

type Verdict = 'agree' | 'safe_side' | 'unsafe_side' | 'scope' | 'input_shape';
/** the strict reasons that are about the calldata itself: the only ones the calldata READER is compared on */
const CALLDATA_REASONS = new Set(['calldata_prefix_invalid', 'calldata_too_large', 'calldata_hex_invalid', 'calldata_odd_length', 'calldata_selector_missing', 'selector_unknown', 'proxy_not_named', 'calldata_too_short', 'calldata_trailing_bytes', 'address_pad_dirty', 'offset_noncanonical', 'padding_dirty', 'proxy_nested', 'proxy_inner_unsupported']);
const INPUT_SHAPE_REASONS = new Set(['input_malformed', 'policy_invalid', 'registry_invalid']);
function judge(g: Golden): { mapping: Verdict; reader: Verdict; note: string } {
  const e = g.expect;
  const m = mapping(g.input);
  const strictDecoded = e['status'] === 'decoded';
  // MAPPING
  let mv: Verdict;
  let note = '';
  if ('notAnExecution' in m) mv = 'agree';
  else if (strictDecoded) {
    if (!m.ok) mv = 'safe_side';
    else {
      const same = m.request['kind'] === e['kind'] && m.request['source'] === e['source'] && m.request['target'] === e['target'] && m.request['beneficiary'] === e['beneficiary'] && m.request['asset'] === e['asset'] && m.request['amount'] === e['amount'] && m.request['chainId'] === e['chainId'];
      mv = same ? 'agree' : 'unsafe_side';
      if (!same) note = JSON.stringify({ mine: m.request, strict: { kind: e['kind'], beneficiary: e['beneficiary'], asset: e['asset'], amount: e['amount'] } });
    }
  } else if (!m.ok) mv = 'agree';
  else mv = e['reason'] === 'token_unknown' ? 'scope' : INPUT_SHAPE_REASONS.has(e['reason']) ? 'input_shape' : 'unsafe_side';
  // READER (the calldata description only)
  const cd = g.input?.calldata;
  const r = typeof cd === 'string' && cd !== '0x' ? decodeErc20Calldata(cd) : undefined;
  let rv: Verdict;
  if (typeof cd !== 'string' || cd === '0x') rv = 'agree'; // no calldata to read: native
  else if (strictDecoded) rv = r === undefined ? 'safe_side' : r.fn === 'transfer' && e['kind'] === 'erc20.transfer' && r.args['to'] === e['beneficiary'] && r.amount === e['amount'] ? 'agree' : r.fn === 'approve' && e['kind'] === 'erc20.approve' && r.args['spender'] === e['beneficiary'] && r.amount === e['amount'] ? 'agree' : 'unsafe_side';
  else if (r === undefined) rv = 'agree';
  else if (e['reason'] === 'token_unknown') rv = 'scope';
  else rv = CALLDATA_REASONS.has(e['reason']) ? 'unsafe_side' : 'agree'; // a reason that is not about the calldata is not the reader's to see
  return { mapping: mv, reader: rv, note };
}

/**
 * The recorded disagreements, by id. SAFE-SIDE: g17 and g18 (a wrapper `execute(address,uint256,bytes)` the registry names: the strict
 * decoder looks through it, the signer refuses the call: an approval of a wrapped call needs the strict decoder first).
 * The MAPPING (what a signature binds) was TIGHTENED in this round to the strict decoder's reading, so it agrees on u08 and u31 (a
 * dirty address word), u11 (no 0x prefix) and u17 (a checksum-case address): the signer's mapping refuses them by name. What remains:
 * SCOPE: u01, u02, u03 (`token_unknown`: the signer binds raw units and addresses and has no registry).
 * INPUT SHAPE: u25 (a display policy the signer has no use for) and u27 (an extra member in the execution input: an intent leg
 * legitimately carries many members).
 * READER (the calldata DESCRIPTION shown to a policy engine, `decodeErc20Calldata`, not changed): UNSAFE-SIDE u08, u31 (dirty padding
 * read as the low 20 bytes), u11 (no prefix), u15 and u19 (it decodes transferFrom, which the strict lane leaves undecoded).
 */
const KNOWN: Record<string, { mapping: Verdict; reader: Verdict }> = {
  g17: { mapping: 'safe_side', reader: 'safe_side' },
  g18: { mapping: 'safe_side', reader: 'safe_side' },
  u01: { mapping: 'scope', reader: 'scope' },
  u02: { mapping: 'scope', reader: 'scope' },
  u03: { mapping: 'scope', reader: 'agree' },
  u08: { mapping: 'agree', reader: 'unsafe_side' },
  u31: { mapping: 'agree', reader: 'unsafe_side' },
  u11: { mapping: 'agree', reader: 'unsafe_side' },
  u15: { mapping: 'agree', reader: 'unsafe_side' },
  u19: { mapping: 'agree', reader: 'unsafe_side' },
  u25: { mapping: 'input_shape', reader: 'agree' },
  u27: { mapping: 'input_shape', reader: 'agree' },
};

describe('cross-check against the 50 golden calldata cases of the strict core decoder (DAX7A-F2)', () => {
  it('is the byte-identical fixture of pl/dax-7a-core-decoder fc1a901 (50 cases)', () => {
    expect(createHash('sha256').update(raw).digest('hex')).toBe('cbf7721b15c9662e1cb8dcdcabdd8decb4aea284f7bd596e5eeb8e0b65abad17');
    expect(golden.cases).toHaveLength(50);
  });

  it('the signer agrees with the strict decoder on every case except the recorded disagreements, and on those it does what is recorded', () => {
    const found: Record<string, { mapping: Verdict; reader: Verdict }> = {};
    const notes: Record<string, string> = {};
    for (const g of golden.cases) {
      const j = judge(g);
      if (j.mapping !== 'agree' || j.reader !== 'agree') found[g.id] = { mapping: j.mapping, reader: j.reader };
      if (j.note) notes[g.id] = j.note;
    }
    console.log('DAX7A-F2 cross-check disagreements:', JSON.stringify(found), JSON.stringify(notes));
    expect(found).toEqual(KNOWN);
  });

  it('the cases the signer maps agree field for field (kind, chain, source, target, beneficiary, asset, amount): 18 of the 20 decoded cases', () => {
    let agree = 0;
    for (const g of golden.cases.filter((c) => c.expect['status'] === 'decoded')) if (judge(g).mapping === 'agree') agree++;
    expect(agree).toBe(18); // 20 decoded (g01 to g18, u30, u32): g17 and g18 (wrapper) are safe-side refusals
  });
});
