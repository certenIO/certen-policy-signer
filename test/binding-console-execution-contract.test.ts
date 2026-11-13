/**
 * The contract with the Console's decoded review (DAX-7C, finding DAX7C-F1: sign what you see). The bound request carries no raw calldata and
 * no native value, so the Console cannot decode what executes from `binding` alone; it reads a SIBLING member `request.execution` =
 * {chainId, source, target, value, calldata}, recomputes the core's single-call commitment over it and compares it with the bound
 * `binding.executionCommitment` (`request_execution_mismatch`), and an absent member is UNDECODED (`execution_absent`) and cannot be approved.
 *
 * test/support/console-display-model.ts is the Console's `reviewModel` copied as a fixture (pinned to its commit, no import across repos).
 * Every test here runs the request the REAL orchestrator sends through it, with the token registry of the DAX-7A golden fixture that the
 * Console's own golden test uses (test/fixtures/calldata-golden-dax7a-fc1a901.json, byte identical to the Console's pinned copy).
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseTokenRegistryText } from '../src/core/calldata-registry.js';
import type { Decision, PolicyRequest } from '../src/types.js';
import { ADDR, H, genuineCommitment, intentBody, leg } from './support/binding-fixtures.js';
import { approveFor, requestHashOf, rig, type Body } from './support/binding-rig.js';
import { reviewModel, type DisplayConfig } from './support/console-display-model.js';

interface GoldenCase { id: string; title: string; policy: { allowRaw: unknown }; input: any; expect: Record<string, any> }
const golden = JSON.parse(readFileSync(new URL('./fixtures/calldata-golden-dax7a-fc1a901.json', import.meta.url), 'utf8')) as { registry: unknown; cases: GoldenCase[] };
const parsed = parseTokenRegistryText(JSON.stringify(golden.registry));
if (!parsed.ok) throw new Error('the golden registry does not validate: ' + parsed.reason);
const cfg = (allowRaw: boolean): DisplayConfig => ({ registry: parsed.registry, allowRaw });
const byId = (id: string): GoldenCase => golden.cases.find((c) => c.id === id)!;
const firstDecoded = (kind: string): GoldenCase => golden.cases.find((c) => c.expect['status'] === 'decoded' && c.expect['kind'] === kind)!;

/** a one-leg intent whose leg is exactly the golden execution input */
function intentOf(input: { chainId: number; source: string; target: string; value: string; calldata: string }): Body {
  const payload = { target: input.target, value: input.value, callData: input.calldata, chainId: input.chainId };
  const l = { legId: 'leg-1', chain: 'fic', chainId: input.chainId, from: input.source, to: input.target, amountWei: input.value, asset: { symbol: 'FICUSD' }, executionPayload: { ...payload, executionCommitment: genuineCommitment(payload) ?? H('no-commitment') } };
  return intentBody({ legs: [l] });
}

/** the request the real orchestrator hands to the decision service for a pending transaction on a seat that requires binding */
async function sentFor(body: Body): Promise<PolicyRequest> {
  let seen: PolicyRequest | undefined;
  const r = rig({ body, reply: (req) => { seen = req; return { decision: 'pending', reason: 'FICTIONAL: waiting for officers' } as Decision; } });
  await r.handle();
  if (seen === undefined) throw new Error('the orchestrator never asked the decision service');
  return seen;
}
const tamper = (req: PolicyRequest, over: Record<string, unknown>): PolicyRequest => ({ ...req, execution: { ...req.execution!, ...over } }) as PolicyRequest;
const flipLastByte = (hex: string): string => hex.slice(0, -2) + (hex.endsWith('00') ? '01' : '00');

describe('the three actions the signer binds: the Console decodes the execution the signer sends, exactly as the golden says', () => {
  for (const kind of ['erc20.transfer', 'erc20.approve', 'native.transfer']) {
    it(`${kind}: execution is the golden input, the Console model is decoded and equals the golden decode, and the request hash is the signer's`, async () => {
      const c = firstDecoded(kind);
      const body = intentOf(c.input);
      const req = await sentFor(body);
      expect(req.execution).toEqual({ chainId: c.input.chainId, source: c.input.source, target: c.input.target, value: c.input.value, calldata: c.input.calldata });
      const m = reviewModel(req, cfg(c.policy.allowRaw === true));
      expect(m.state).toBe('decoded');
      if (m.state !== 'decoded') return;
      expect(m.approvable).toBe(true);
      expect(m.decode).toEqual(c.expect);
      expect(m.requestHash).toBe(requestHashOf(body));
    });
  }
});

describe('every golden case: when the signer sends an execution the Console reads the golden, and it never reads a disagreement', () => {
  const rows: Array<{ id: string; sent: boolean; state: string; reason?: string }> = [];

  it('runs all 50 cases through the real orchestrator and the Console model', async () => {
    for (const c of golden.cases) {
      if (typeof c.input !== 'object' || c.input === null || typeof c.input.source !== 'string' || typeof c.input.target !== 'string' || c.input.chainId === undefined) continue;
      if (c.policy.allowRaw !== true && c.policy.allowRaw !== false) continue;
      const req = await sentFor(intentOf(c.input));
      const m = reviewModel(req, cfg(c.policy.allowRaw === true));
      const sent = req.execution !== undefined;
      rows.push({ id: c.id, sent, state: m.state, ...('reason' in m ? { reason: m.reason } : {}) });
      if (!sent) {
        // nothing is sent when the signer cannot map the leg to the ten members: no binding, no execution, UNDECODED and unapprovable
        expect(req.binding, c.id).toBeUndefined();
        expect(m, c.id).toMatchObject({ state: 'undecoded', approvable: false, reason: 'execution_absent' });
        continue;
      }
      // what the signer sent is what the golden decoded: never a request_execution_mismatch, never a request_decode_mismatch
      expect(m.state, c.id).not.toBe('unverified');
      expect(m.state, c.id).not.toBe('unbound');
      // a golden case about the SHAPE of the input or of the policy (an extra member, a policy that is not {allowRaw}) judges what the Console is
      // handed; the signer never forwards an extra member, it sends its own clean execution, so only the clean reading above applies
      if (['input_malformed', 'policy_invalid', 'registry_invalid'].includes(c.expect['reason'])) continue;
      if (c.expect['status'] === 'decoded') {
        expect(m.state, c.id).toBe('decoded');
        if (m.state === 'decoded') expect(m.decode, c.id).toEqual(c.expect);
      } else {
        // the signer has no token registry: a token the golden registry does not know is mapped by the signer and UNDECODED by the Console
        expect(m.state, c.id).toBe('undecoded');
        if (m.state === 'undecoded') expect(m.reason, c.id).toBe(c.expect['reason']);
      }
    }
    expect(rows.length).toBe(48); // the 50 golden cases less two the test cannot present (an input that is not an execution object, a policy that is not a boolean)
    // the signer sends an execution for 22 of them; the Console reads 19 as decoded (the 18 golden decoded cases the signer maps plus u27, whose extra
    // member the signer never forwards) and 3 as undecoded token_unknown (the signer has no token registry); it sends nothing for the other 26
    expect(rows.filter((r) => r.sent).length).toBe(22);
    expect(rows.filter((r) => r.state === 'decoded').length).toBe(19);
    expect(rows.filter((r) => r.sent && r.state === 'undecoded').map((r) => `${r.id}:${r.reason}`)).toEqual(['u01:token_unknown', 'u02:token_unknown', 'u03:token_unknown']);
    // the golden decoded cases the signer does NOT map are the two named wrappers (execute around transfer / approve): safe side, UNDECODED in the Console (DAX7A-F2, F23)
    expect(golden.cases.filter((c) => c.expect['status'] === 'decoded' && !rows.some((r) => r.id === c.id && r.sent)).map((c) => c.id)).toEqual(['g17', 'g18']);
  });
});

describe('what the signer cannot bind carries no execution, and the Console then cannot approve it', () => {
  it('an unknown selector (the raw golden case) and a calldata the strict reading refuses: no binding, no execution, `execution_absent`', async () => {
    const raw = golden.cases.find((c) => c.expect['approval'] === 'raw_only')!;
    const req = await sentFor(intentOf(raw.input));
    expect(req.binding).toBeUndefined();
    expect('execution' in req).toBe(false);
    expect(reviewModel(req, cfg(true))).toMatchObject({ state: 'undecoded', approvable: false, reason: 'execution_absent' });
  });

  it('a several-leg intent carries its binding (legCount 2) and NO execution: omitted, never null', async () => {
    const req = await sentFor(intentBody({ legs: [leg(), leg({ to: ADDR.vendorB })] }));
    expect(req.binding).toMatchObject({ legCount: 2 });
    expect('execution' in req).toBe(false);
    expect(reviewModel(req, cfg(false))).toMatchObject({ state: 'undecoded', approvable: false, reason: 'execution_absent' });
  });

  it('a legacy seat (no binding block) is not sent an execution either', async () => {
    let seen: PolicyRequest | undefined;
    const r = rig({ body: intentBody(), rules: null, reply: (req) => { seen = req; return { decision: 'approve' }; } });
    await r.handle();
    expect(seen).toBeDefined();
    expect('execution' in seen!).toBe(false);
    expect('binding' in seen!).toBe(false);
  });
});

describe('a request whose execution was changed on the way is refused by the Console by name (request_execution_mismatch)', () => {
  it('one calldata byte and the source are request_execution_mismatch; another target, chain or value is refused by the decoder first, and cannot be approved either', async () => {
    const c = firstDecoded('erc20.transfer');
    const req = await sentFor(intentOf(c.input));
    expect(reviewModel(req, cfg(false)).state).toBe('decoded'); // the untouched request is fine
    const tries: Array<[string, Record<string, unknown>, string]> = [
      ['the last calldata byte (the amount)', { calldata: flipLastByte(req.execution!.calldata) }, 'executionCommitment'],
      ['the source', { source: ADDR.other }, 'source'],
    ];
    for (const [name, over, member] of tries) {
      const m = reviewModel(tamper(req, over), cfg(false));
      expect(m, name).toMatchObject({ state: 'unverified', approvable: false, refusal: 'request_execution_mismatch', member });
    }
    // another target, another chain, a value sent with a token call: the decoder refuses first (an unknown token, a call that sends value: UNDECODED), the
    // approval is refused all the same
    for (const over of [{ target: '0x' + '66'.repeat(20) }, { chainId: req.execution!.chainId + 1 }, { value: '1' }]) {
      const m = reviewModel(tamper(req, over), cfg(false));
      expect(m.approvable).toBe(false);
      expect(['undecoded', 'unverified']).toContain(m.state);
    }
  });

  it('a tampered byte of a native-value fixture and of an approve fixture too', async () => {
    for (const kind of ['native.transfer', 'erc20.approve']) {
      const c = firstDecoded(kind);
      const req = await sentFor(intentOf(c.input));
      const over = kind === 'native.transfer' ? { value: String(BigInt(req.execution!.value) + 1n) } : { calldata: flipLastByte(req.execution!.calldata) };
      expect(reviewModel(tamper(req, over), cfg(false)), kind).toMatchObject({ state: 'unverified', refusal: 'request_execution_mismatch' });
    }
  });
});

describe('the signer authenticates the execution BEFORE it sends anything: a leg whose stated commitment is not the one of its bytes is never sent to a seat', () => {
  it('no binding and no execution are sent, a decision for it is refused presented_malformed, nothing is signed', async () => {
    const lying = intentBody({ legs: [leg({ commitment: H('a-commitment-of-other-bytes') })] });
    let seen: PolicyRequest | undefined;
    const r = rig({ body: lying, reply: (req) => { seen = req; return approveFor(intentBody())(); } }); // a record for some other, valid request
    const row = await r.handle();
    expect(seen).toBeDefined();
    expect('binding' in seen!).toBe(false);
    expect('execution' in seen!).toBe(false);
    expect(row.lastError).toBe('binding: presented_malformed');
    expect(r.acc.submissions).toHaveLength(0);
    expect(r.nonces.list()).toEqual([]);
    // the Console, handed what the signer sent, cannot decode or approve it either
    expect(reviewModel(seen!, cfg(false))).toMatchObject({ state: 'undecoded', approvable: false, reason: 'execution_absent' });
  });
});
