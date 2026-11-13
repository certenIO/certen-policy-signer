/**
 * THE CONSOLE'S DECODED-REVIEW MODEL, COPIED AS A FIXTURE (no import across repos). Source: src/display/model.ts of branch pl/dax-7c-decoded-review
 * of the Console (transaction-controls) at commit 3aff5846dfaf4447ad4e8d734f5ae3c2e5835397; sha256 of that file with LF line endings 23267d9cb59d8bfcb6a47a0fa6785bc58b4d61ed2fcf0b0d985586f332442824.
 * The file below is that file's text; only its five import lines differ (the signer's own copies of the core, of the PolicyRequest type, of the
 * Console's request parser fixture) and the Console's DisplayConfig import is replaced by the two members the model reads. Its own header
 * comment is kept. `reviewModel(request, cfg)` is what the Console's review screen decides from the request the signer sends: it reads the
 * SIBLING member `request.execution` (DAX7C-F1), recomputes the commitment over it and refuses a mismatch (`request_execution_mismatch`).
 * test/binding-console-execution-contract.test.ts runs the REAL orchestrator's request through it. When the Console changes this file,
 * re-copy it and the test says what the signer must now send.
 */
/**
 * What the review screen shows for a request, decided on the SERVER from the BOUND transaction (DAX-7C, DESIGN.md section 3;
 * DAX-7 work package 1; DECISION.md DE-53). Pure: it imports the core copies, the DAX-4C reader of the bound request and types.
 * It performs no I/O, reads no clock and never throws: a request that cannot be read is a named state, never a guess.
 *
 * Inputs. The bound request (`request.binding`, the ten members of the request hash, read by `bindingOf` exactly as the decision
 * path reads it) and the execution it commits to (`request.execution` = chainId, source, target, value, calldata: finding
 * DAX7C-F1, a sibling of `binding`). The execution is AUTHENTICATED by the bound `executionCommitment`: the core recomputes
 * keccak(chainid, target, value, keccak(calldata)) and refuses a mismatch, so a signer or a relay that sends other bytes than the
 * ones the validators committed to is refused (`request_execution_mismatch`), never believed. The decoded members of the request
 * (kind, beneficiary, asset, amount) are compared with what the decoder reads from the bytes and a disagreement is refused.
 *
 * States (the DESIGN.md table): `decoded` and `raw` can be approved; `undecoded`, `unbound` and `unverified` cannot, and each
 * carries the NAME the approval is refused with. Unknown, malformed, proxy-style and unregistered-token calldata is `undecoded`
 * with the decoder's reason and is never shown as if understood; with policy.allowRaw it is `raw`, and the text says RAW and
 * carries the keccak-256 of the calldata.
 */
import type { PolicyRequest } from '../../src/types.js';
import { bindingOf } from './console-binding-parser.js';
import { decode, type DecodedCall, type UndecodedCall } from '../../src/core/calldata.js';
import { expectedDisplay, type DecodedDisplaySet, type RawDisplaySet } from '../../src/core/calldata-display.js';
import type { TokenRegistry } from '../../src/core/calldata-registry.js';

/** the two members of the Console's DisplayConfig (src/display/config.ts) that the model reads */
export interface DisplayConfig {
  registry: TokenRegistry;
  allowRaw: boolean;
}

export type DisplaySet = DecodedDisplaySet | RawDisplaySet;

/** The bound transaction as the core's display check takes it: the ten request members and the execution. */
export interface BoundTransaction {
  request: Record<string, unknown>;
  execution: unknown;
}

export type ReviewModel =
  | { state: 'decoded'; approvable: true; set: DecodedDisplaySet; decode: DecodedCall; requestHash: string; bound: BoundTransaction }
  | { state: 'raw'; approvable: true; set: RawDisplaySet; decode: UndecodedCall; unverified: string[]; requestHash: string; bound: BoundTransaction }
  | { state: 'undecoded'; approvable: false; refusal: 'decode_required'; reason: string; detail?: string; decode?: UndecodedCall }
  | { state: 'unbound'; approvable: false; refusal: 'request_unbound'; reason: string; detail?: string }
  | { state: 'unverified'; approvable: false; refusal: string; reason: string; member?: string; detail?: string };

function undecodedState(reason: string, decodeResult?: UndecodedCall, detail?: string): ReviewModel {
  const d = detail ?? decodeResult?.detail;
  return {
    state: 'undecoded',
    approvable: false,
    refusal: 'decode_required',
    reason,
    ...(d === undefined ? {} : { detail: d }),
    ...(decodeResult === undefined ? {} : { decode: decodeResult }),
  };
}

function build(request: PolicyRequest, cfg: DisplayConfig): ReviewModel {
  const execution = (request as unknown as { execution?: unknown }).execution;
  // nothing to read: the signer did not send the execution the commitment commits to (DAX7C-F1)
  if (execution === undefined) return undecodedState('execution_absent');
  const policy = { allowRaw: cfg.allowRaw };
  const dec = decode(execution, cfg.registry, policy);
  if (dec.status === 'undecoded' && dec.approval !== 'raw_only') return undecodedState(dec.reason, dec);

  const b = bindingOf(request);
  if (!b.ok) return { state: 'unbound', approvable: false, refusal: 'request_unbound', reason: b.reason, ...(b.detail === undefined ? {} : { detail: b.detail }) };

  const bound: BoundTransaction = { request: b.coreRequest, execution };
  const e = expectedDisplay(bound, cfg.registry, policy);
  if (!e.ok) {
    return { state: 'unverified', approvable: false, refusal: e.reason, reason: e.reason, ...(e.member === undefined ? {} : { member: e.member }), ...(e.detail === undefined ? {} : { detail: e.detail }) };
  }
  if (e.mode === 'raw' && dec.status === 'undecoded') {
    return { state: 'raw', approvable: true, set: e.expected, decode: dec, unverified: e.unverified, requestHash: b.requestHash, bound };
  }
  if (e.mode === 'decoded' && dec.status === 'decoded') {
    return { state: 'decoded', approvable: true, set: e.expected, decode: dec, requestHash: b.requestHash, bound };
  }
  // the display check and the decoder disagree about the mode: never an approval
  return { state: 'unverified', approvable: false, refusal: 'bound_malformed', reason: 'bound_malformed', detail: 'mode' };
}

/** What the screen shows and what an approval is judged against, from the stored request. Never throws. */
export function reviewModel(request: PolicyRequest, cfg: DisplayConfig): ReviewModel {
  try {
    return build(request, cfg);
  } catch {
    return { state: 'unverified', approvable: false, refusal: 'bound_malformed', reason: 'bound_malformed', detail: 'unreadable' };
  }
}
