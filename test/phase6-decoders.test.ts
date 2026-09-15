/**
 * Phase 6.1 / 6.2 decoders (FICTIONAL Business Transaction Controls lab): ABI pins, business summary,
 * selfCall / targetKnown, the acceptance fact and typed governance operations, and that all of it reaches
 * the PolicyRequest (with bodyType and configVersion) and the Receipt. All parties are FICTIONAL.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { keccak256Hex, buildSelectorTable, decodeCalldata } from '../src/decode/abi.js';
import { createCertenIntentDecoder, formatUnits, type AbiPin } from '../src/decode/decoders/certen-intent.js';
import { extractAcceptance, extractGovernance, parseAcceptanceContent } from '../src/decode/facts.js';
import { buildRegistry } from '../src/decode/registry.js';
import { Orchestrator } from '../src/orchestrator.js';
import { MockAccumulateClient } from '../src/accumulate/client.js';
import { MemoryStore } from '../src/store/store.js';
import { Resolver } from '../src/resolver.js';
import { LocalSigner } from '../src/signer/signer.js';
import { singleKeyring } from '../src/signer/keyring.js';
import type { PolicyClient } from '../src/policy/policy.js';
import type { LegCall, PolicyRequest } from '../src/types.js';

const silent = pino({ level: 'silent' });
const FDBUSD = '0x2d9e724de974a81e97ee553b3482cafa6d5fe46b';
const PROBE = '0x1ce874b24954dadca0e027ae562e7ce62c0c794c';
const ANCHOR = '0xd5736be4a9adbec11f8b365bb0624c0c946bca15';
const DEPLOYER = '0x00000000000000000000000000000000c2eade01';
const DELTA = '0xe66e6f40f1d7a1c06abace493f38c03800ac565a';
const V7 = '0x1551c29a7349dec67f2928462e45e86d8df21f6e';
const REF = '9f1c2b3a' + '11'.repeat(28);

const fn = (name: string, inputs: Array<[string, string]>) => ({ type: 'function', name, inputs: inputs.map(([n, t]) => ({ name: n, type: t })), outputs: [], stateMutability: 'nonpayable' });
const FDBUSD_ABI = [
  fn('transferWithReference', [['to', 'address'], ['amount', 'uint256'], ['paymentRef', 'bytes32']]),
  fn('transfer', [['to', 'address'], ['amount', 'uint256']]),
  fn('holderStatus', [['holder', 'address']]),
  fn('setHolderStatus', [['holder', 'address'], ['status', 'uint8']]),
];
const PROBE_ABI = [fn('ping', [['ref', 'bytes32']])];
const ANCHOR_ABI = [fn('anchor', [['instructionHash', 'bytes32']])];
const DEPLOYER_ABI = [fn('deploy', [['value', 'uint256'], ['salt', 'bytes32'], ['code', 'bytes']])];

const pin = (address: string, name: string, abi: unknown[], asset?: { symbol: string; decimals: number }): AbiPin =>
  ({ chainId: 84532, address, name, table: buildSelectorTable(abi), ...(asset ? { asset } : {}) });
const PINS = [
  pin(FDBUSD, 'FDBUSD', FDBUSD_ABI, { symbol: 'FDBUSD', decimals: 2 }),
  pin(PROBE, 'EventProbe', PROBE_ABI),
  pin(ANCHOR, 'AuthorizationAnchor', ANCHOR_ABI),
  pin(DEPLOYER, 'Create2Deployer', DEPLOYER_ABI),
];
const LABELS = { [DELTA]: 'Delta Equipment (FICTIONAL)' };

const word = (n: bigint | number) => BigInt(n).toString(16).padStart(64, '0');
const addr = (a: string) => a.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const sel = (sig: string) => keccak256Hex(sig).slice(0, 8);
const twr = (to: string, amount: bigint, ref = REF) => '0x' + sel('transferWithReference(address,uint256,bytes32)') + addr(to) + word(amount) + ref;

const toHex = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('hex');
const intentBody = (legs: Array<Record<string, unknown>>) => ({
  type: 'writeData',
  entry: { type: 'doubleHash', data: [{ kind: 'CERTEN_INTENT', intent_id: 'int-p6', description: 'FICTIONAL payment' }, { legs }, {}, {}].map(toHex) },
});
const callLeg = (target: string, callData: string, o: Record<string, unknown> = {}) => ({
  legId: 'l0', chain: 'base-sepolia', from: V7, to: target, amountWei: '0',
  executionPayload: { chainId: 84532, target, value: '0', callData }, ...o,
});
const CTX = { principal: 'acc://fictional-customer-tcl1.acme/intents' };
const decoder = createCertenIntentDecoder({ pins: PINS, labels: LABELS });

describe('keccak-256 and selectors', () => {
  it('matches a reference implementation, including multi-block input', () => {
    for (const s of ['', 'transfer(address,uint256)', 'x'.repeat(135), 'y'.repeat(136), 'z'.repeat(500)]) {
      expect(keccak256Hex(s)).toBe(Buffer.from(keccak_256(Buffer.from(s))).toString('hex'));
    }
  });
  it('computes the real selectors of the pinned contracts', () => {
    expect(sel('transfer(address,uint256)')).toBe('a9059cbb');
    expect(buildSelectorTable(PROBE_ABI).get(sel('ping(bytes32)'))?.signature).toBe('ping(bytes32)');
    expect(buildSelectorTable(ANCHOR_ABI).get(sel('anchor(bytes32)'))?.signature).toBe('anchor(bytes32)');
    expect([...buildSelectorTable(DEPLOYER_ABI).values()][0].signature).toBe('deploy(uint256,bytes32,bytes)');
    expect(buildSelectorTable({ abi: FDBUSD_ABI }).size).toBe(4);   // artifact form
  });
});

describe('ABI decoding', () => {
  it('decodes FDBUSD transferWithReference, EventProbe ping and AuthorizationAnchor anchor', () => {
    const t = decodeCalldata(buildSelectorTable(FDBUSD_ABI), twr(DELTA, 4_250_000n))!;
    expect(t.fn.name).toBe('transferWithReference');
    expect(t.args).toEqual({ to: DELTA, amount: '4250000', paymentRef: '0x' + REF });
    expect(decodeCalldata(buildSelectorTable(PROBE_ABI), '0x' + sel('ping(bytes32)') + REF)!.args).toEqual({ ref: '0x' + REF });
    expect(decodeCalldata(buildSelectorTable(ANCHOR_ABI), '0x' + sel('anchor(bytes32)') + REF)!.args).toEqual({ instructionHash: '0x' + REF });
  });

  it('decodes dynamic bytes (Create2Deployer deploy)', () => {
    const code = 'deadbeefcafe';
    const cd = '0x' + sel('deploy(uint256,bytes32,bytes)') + word(0) + REF + word(96) + word(6) + code.padEnd(64, '0');
    expect(decodeCalldata(buildSelectorTable(DEPLOYER_ABI), cd)!.args).toEqual({ value: '0', salt: '0x' + REF, code: '0x' + code });
  });

  it('refuses non-canonical encodings rather than guessing', () => {
    const t = buildSelectorTable(FDBUSD_ABI);
    const good = twr(DELTA, 1n);
    expect(decodeCalldata(t, good)).toBeDefined();
    expect(decodeCalldata(t, good + '00'.repeat(32))).toBeUndefined();                 // trailing word
    expect(decodeCalldata(t, good.slice(0, -64))).toBeUndefined();                     // short
    expect(decodeCalldata(t, '0x' + good.slice(2, 10) + 'ff' + addr(DELTA).slice(2) + word(1) + REF)).toBeUndefined(); // dirty address padding
    const u8 = '0x' + sel('setHolderStatus(address,uint8)') + addr(DELTA) + word(256);
    expect(decodeCalldata(t, u8)).toBeUndefined();                                     // uint8 overflow
    const dt = buildSelectorTable(DEPLOYER_ABI);
    const bad = '0x' + sel('deploy(uint256,bytes32,bytes)') + word(0) + REF + word(4096) + word(0);
    expect(decodeCalldata(dt, bad)).toBeUndefined();                                   // offset out of bounds
    expect(decodeCalldata(t, '0x12345678' + word(1))).toBeUndefined();                // unknown selector
  });
});

describe('evm-abi decoding of CERTEN intents', () => {
  it('formats amounts with the asset decimals', () => {
    expect(formatUnits('4250000', 2)).toBe('42,500.00');
    expect(formatUnits('5', 2)).toBe('0.05');
    expect(formatUnits('1234567890', 0)).toBe('1,234,567,890');
  });

  it('pinned FDBUSD transferWithReference: business summary, calldataDecoded, assets, values, targetKnown', () => {
    const out = decoder.decode(intentBody([callLeg(FDBUSD, twr(DELTA, 4_250_000n))]), CTX)!;
    expect(out.summary.action).toBe('Pay $42,500.00 FDBUSD to Delta Equipment (FICTIONAL) — ref 0x9f1c2b3a…');
    expect(out.summary.calldataDecoded).toEqual([{
      legIndex: 0, chainId: 84532, target: FDBUSD, abi: 'FDBUSD', function: 'transferWithReference',
      signature: 'transferWithReference(address,uint256,bytes32)', args: { to: DELTA, amount: '4250000', paymentRef: '0x' + REF },
    } satisfies LegCall]);
    expect(out.summary.assets).toEqual([{ legIndex: 0, chain: 'base-sepolia', chainId: 84532, token: FDBUSD, symbol: 'FDBUSD', decimals: 2 }]);
    expect(out.summary.values).toEqual(['4250000']);
    expect(out.summary.targetKnown).toBe(true);
    expect(out.summary.selfCall).toBe(false);
    expect(out.summary.raw?.opaqueCallLegs).toBeUndefined();
  });

  it('an unlabelled payee is shown by address; a non-asset pin is summarised as a call', () => {
    const other = '0x' + 'ab'.repeat(20);
    expect(decoder.decode(intentBody([callLeg(FDBUSD, twr(other, 100n))]), CTX)!.summary.action).toContain(`Pay $1.00 FDBUSD to ${other}`);
    const a = decoder.decode(intentBody([callLeg(ANCHOR, '0x' + sel('anchor(bytes32)') + REF)]), CTX)!;
    expect(a.summary.action).toBe(`AuthorizationAnchor.anchor(instructionHash=0x${REF})`);
    expect(a.summary.targetKnown).toBe(true);
    expect(a.summary.assets).toBeUndefined();
  });

  it('an unpinned target is still read generically but targetKnown is false', () => {
    const stranger = '0x' + '77'.repeat(20);
    const out = decoder.decode(intentBody([
      callLeg(PROBE, '0x' + sel('ping(bytes32)') + REF),
      callLeg(stranger, '0x' + sel('transfer(address,uint256)') + addr(DELTA) + word(9), { legId: 'l1' }),
    ]), CTX)!;
    expect(out.summary.targetKnown).toBe(false);
    expect((out.summary.calldataDecoded as LegCall[])[1]).toEqual({
      legIndex: 1, chainId: 84532, target: stranger, abi: '', function: 'transfer', signature: 'transfer(address,uint256)', args: { to: DELTA, amount: '9' },
    });
    // The same address on another chain is not the pinned contract.
    const wrongChain = decoder.decode(intentBody([callLeg(FDBUSD, twr(DELTA, 1n), { executionPayload: { chainId: 1, target: FDBUSD, callData: twr(DELTA, 1n) } })]), CTX)!;
    expect(wrongChain.summary.targetKnown).toBe(false);
  });

  it('a pinned target with calldata its ABI cannot decode stays opaque', () => {
    const out = decoder.decode(intentBody([callLeg(PROBE, '0xdeadbeef' + word(1))]), CTX)!;
    expect((out.summary.calldataDecoded as LegCall[])[0]).toMatchObject({ abi: 'EventProbe', function: '', signature: '0xdeadbeef', args: {} });
    expect(out.summary.targetKnown).toBe(true);
    expect(out.summary.raw?.opaqueCallLegs).toBe(1);
  });

  it('selfCall: a V7 calling itself', () => {
    const out = decoder.decode(intentBody([callLeg(V7, '0x' + sel('ping(bytes32)') + REF)]), CTX)!;
    expect(out.summary.selfCall).toBe(true);
    expect(out.summary.targetKnown).toBe(false);
  });

  it('no contract-call legs: targetKnown is vacuously true and calldataDecoded absent', () => {
    const out = decoder.decode(intentBody([{ legId: 'l0', chain: 'base-sepolia', from: V7, to: DELTA, amountWei: '10', executionPayload: { target: DELTA, callData: '0x' } }]), CTX)!;
    expect(out.summary.targetKnown).toBe(true);
    expect(out.summary.calldataDecoded).toBeUndefined();
  });

  it('is resolvable as evm-abi, but not listed twice', () => {
    expect(buildRegistry(['evm-abi'], [], undefined, { certenIntent: decoder }).names()).toEqual(['certen-intent', 'fallback']);
    expect(() => buildRegistry(['evm-abi', 'certen-intent'], [], undefined, { certenIntent: decoder })).toThrow(/same decoder/);
  });
});

describe('acceptance fact', () => {
  const HASH = 'ab'.repeat(32);
  const canonical = `{"amount":4250000,"category":"equipment","firm":"acc://northfield-inspection-tcl1.acme/book","instructionHash":"${HASH}"}`;
  const wd = (...els: string[]) => ({ type: 'writeData', entry: { type: 'doubleHash', data: els.map((e) => Buffer.from(e, 'utf8').toString('hex')) } });
  const P = 'acc://fictional-customer-tcl1.acme/acceptances';

  it('parses the canonical acceptance content', () => {
    expect(extractAcceptance(wd(canonical), P)).toEqual({
      instructionHash: HASH, category: 'equipment', amount: 4250000, firm: 'acc://northfield-inspection-tcl1.acme/book',
    });
  });

  it('refuses anything that is not exactly canonical, or not on an acceptances account', () => {
    expect(extractAcceptance(wd(canonical), 'acc://fictional-customer-tcl1.acme/data')).toBeUndefined();
    expect(extractAcceptance(wd(canonical, canonical), P)).toBeUndefined();                 // two elements
    expect(extractAcceptance({ type: 'sendTokens' } as any, P)).toBeUndefined();
    const bad = [
      canonical.replace('{"amount"', '{ "amount"'),                                          // whitespace
      `{"category":"equipment","amount":4250000,"firm":"acc://f.acme/book","instructionHash":"${HASH}"}`, // unsorted
      canonical.replace('4250000', '"4250000"'),                                             // string amount
      canonical.replace('4250000', '42.5'),                                                  // fractional
      canonical.replace(HASH, HASH.toUpperCase()),                                           // not lowercase hex
      canonical.replace(HASH, HASH.slice(2)),                                                // 62 hex
      canonical.replace('}', ',"extra":1}'),                                                 // extra key
      'not json',
    ];
    for (const b of bad) expect(parseAcceptanceContent(b), b).toBeUndefined();
  });
});

describe('governance operations', () => {
  const KH = 'cd'.repeat(32);
  it('types updateKeyPage operations', () => {
    const g = extractGovernance({
      type: 'updateKeyPage',
      operation: [
        { type: 'add', entry: { keyHash: KH } },
        { type: 'remove', entry: { delegate: 'acc://fictional-officer.acme/book' } },
        { type: 'update', oldEntry: { keyHash: KH }, newEntry: { keyHash: 'ef'.repeat(32) } },
        { type: 'setThreshold', threshold: 2 },
        { type: 'updateAllowed', allow: ['sendTokens'], deny: [] },
        { type: 'somethingNew', x: 1 },
      ],
    }, 'acc://fictional-bank-tcl1.acme/book/2')!;
    expect(g).toEqual({
      kind: 'updateKeyPage', principal: 'acc://fictional-bank-tcl1.acme/book/2',
      operations: [
        { type: 'add', keyHash: KH },
        { type: 'remove', delegate: 'acc://fictional-officer.acme/book' },
        { type: 'update', oldKeyHash: KH, newKeyHash: 'ef'.repeat(32) },
        { type: 'setThreshold', threshold: 2 },
        { type: 'updateAllowed', allow: ['sendTokens'], deny: [] },
        { type: 'somethingNew', unrecognized: true },
      ],
    });
  });

  it('types updateAccountAuth operations and ignores other bodies', () => {
    expect(extractGovernance({
      type: 'updateAccountAuth',
      operations: [{ type: 'addAuthority', authority: 'acc://fictional-firm.acme/book' }, { type: 'disable', authority: 'acc://x.acme/book' }, { type: 'addAuthority' }],
    }, 'acc://fictional-customer-tcl1.acme/data')!.operations).toEqual([
      { type: 'addAuthority', authority: 'acc://fictional-firm.acme/book' },
      { type: 'disable', authority: 'acc://x.acme/book' },
      { type: 'addAuthority', unrecognized: true },
    ]);
    expect(extractGovernance({ type: 'writeData' }, 'acc://x.acme/data')).toBeUndefined();
  });
});

describe('the PolicyRequest and Receipt carry the Phase 6 fields', () => {
  const TX = 'f6'.repeat(32);
  const PAGE = 'acc://fictional-bank-tcl1.acme/book/2';
  const VERSION = 'sha256:' + '0'.repeat(64);

  async function run(body: { type: string; [k: string]: unknown }, principal: string) {
    const acc = new MockAccumulateClient();
    acc.addPending(TX, { body, principal });
    const seen: PolicyRequest[] = [];
    const policy = { decide: async (r: PolicyRequest) => { seen.push(r); return { decision: 'deny', reason: 'FICTIONAL test' }; } } as unknown as PolicyClient;
    const store = new MemoryStore();
    const orchestrator = new Orchestrator({
      accumulate: acc, keyring: singleKeyring(new LocalSigner(new Uint8Array(32).fill(7)), PAGE), policy, store,
      resolver: new Resolver(acc, buildRegistry(undefined, [], undefined, { certenIntent: decoder })),
      logger: silent, configVersion: VERSION, options: { submitRejectVote: false },
    });
    await orchestrator.handle({ txHash: TX, signerUrl: PAGE });
    return { req: seen[0], store };
  }

  it('an intent: bodyType, configVersion, assets, calldataDecoded, selfCall, targetKnown; stored for /relay/pending', async () => {
    const { req, store } = await run(intentBody([callLeg(FDBUSD, twr(DELTA, 4_250_000n))]), 'acc://fictional-customer-tcl1.acme/intents');
    expect(req).toMatchObject({ bodyType: 'writeData', configVersion: VERSION, selfCall: false, targetKnown: true });
    expect(req.assets).toHaveLength(1);
    expect((req.calldataDecoded as LegCall[])[0].args.paymentRef).toBe('0x' + REF);
    expect(req.governance).toBeUndefined();
    expect(req.acceptance).toBeUndefined();
    expect(await store.getPolicyRequest(TX)).toEqual(req);
    expect((await store.getReceipt(TX))?.configVersion).toBe(VERSION);
  });

  it('a governance body carries typed operations', async () => {
    const { req } = await run({ type: 'updateKeyPage', operation: [{ type: 'setThreshold', threshold: 2 }] }, PAGE);
    expect(req.bodyType).toBe('updateKeyPage');
    expect(req.governance).toEqual({ kind: 'updateKeyPage', principal: PAGE, operations: [{ type: 'setThreshold', threshold: 2 }] });
    expect(req.actionSummary).toBe(`updateKeyPage on ${PAGE}: setThreshold threshold=2`);
  });

  it('an acceptance WriteData carries the acceptance', async () => {
    const content = `{"amount":1,"category":"equipment","firm":"acc://f.acme/book","instructionHash":"${'12'.repeat(32)}"}`;
    const { req } = await run({ type: 'writeData', entry: { type: 'doubleHash', data: [Buffer.from(content).toString('hex')] } }, 'acc://fictional-customer-tcl1.acme/acceptances');
    expect(req.acceptance).toEqual({ instructionHash: '12'.repeat(32), category: 'equipment', amount: 1, firm: 'acc://f.acme/book' });
  });
});
