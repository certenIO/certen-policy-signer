/**
 * The human display of an item and its `tcl-summary/v1` hash. FICTIONAL Business Transaction Controls lab, Phase 7.
 * Contract: transaction-controls docs/interfaces/phase7-personal-signing-contract.md §2.
 *
 * A display is an ordered list of `[label, value]` string pairs built ONLY from facts this signer decoded
 * off the transaction (or, for a proposal, from the typed operations it will itself build into the
 * transaction). Nothing a submitter wrote as prose (memo, description) is shown, and nothing is guessed:
 * a fact the decoders did not produce is an absent pair, never a placeholder.
 *
 * The transaction hash and the vote are deliberately NOT in the hash; the signature binds the transaction
 * hash, and the vote is carried separately.
 */
import { createHash } from 'node:crypto';
import { formatUnits } from './decode/decoders/certen-intent.js';
import type { KeyPageOp } from './ops/keypage.js';
import type { AcceptanceFact, GovernanceFact, LegAsset, LegCall, PolicyRequest } from './types.js';

export type DisplayPair = [string, string];

/** `sha256("tcl-summary/v1\n" + for each pair: len(label) ":" label "=" len(value) ":" value "\n")`, lowercase hex. */
export function tclSummaryV1(display: ReadonlyArray<readonly [string, string]>): string {
  const h = createHash('sha256');
  h.update('tcl-summary/v1\n', 'utf8');
  for (const pair of display) {
    if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string' || typeof pair[1] !== 'string') {
      throw new Error('tcl-summary/v1: every display entry must be a [string, string] pair');
    }
    const [label, value] = pair;
    h.update(`${Buffer.byteLength(label, 'utf8')}:`, 'utf8');
    h.update(label, 'utf8');
    h.update(`=${Buffer.byteLength(value, 'utf8')}:`, 'utf8');
    h.update(value, 'utf8');
    h.update('\n', 'utf8');
  }
  return h.digest('hex');
}

export interface DisplayOptions {
  /** `decoders.labels`: lowercase address or acc:// URL → name. A label is shown BESIDE the value, never instead. */
  labels?: Record<string, string>;
}

const adiOf = (u: string): string => {
  const m = /^acc:\/\/([^/]+)/i.exec(u);
  return m ? `acc://${m[1]}` : u;
};

function labeller(opts: DisplayOptions) {
  const labels = Object.fromEntries(Object.entries(opts.labels ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
  return (v: string): string => {
    const l = labels[v.toLowerCase()];
    return l ? `${l} (${v})` : v;
  };
}

const AMOUNT_ARGS = ['amount', 'value', 'wad'];

/** Payment pairs for one decoded contract-call leg. `prefix` distinguishes legs after the first. */
function paymentPairs(call: LegCall, asset: LegAsset | undefined, pr: PolicyRequest, label: (v: string) => string, prefix: string): DisplayPair[] {
  const out: DisplayPair[] = [];
  const to = call.args['to'];
  const amount = AMOUNT_ARGS.map((k) => call.args[k]).find((v) => v !== undefined);
  const ref = call.args['paymentRef'] ?? call.args['ref'];
  // The payer is the account the intent was written under: the one field on a request nobody can forge.
  if (!prefix) out.push(['Payer', label(adiOf(pr.account))]);
  if (to) out.push([`${prefix}Payee`, label(to)]);
  if (amount !== undefined) {
    out.push([`${prefix}Amount`, asset && /^\d+$/.test(amount) ? `${formatUnits(amount, asset.decimals)} ${asset.symbol}` : `${amount} (base units, asset unknown)`]);
  }
  if (ref !== undefined) out.push([`${prefix}Instruction hash`, ref]);
  const chain = asset?.chain ?? (call.chainId !== undefined ? String(call.chainId) : pr.chain);
  if (chain) out.push([`${prefix}Chain`, chain]);
  if (call.target) {
    const fn = call.function ? ` ${call.abi ? `${call.abi}.` : ''}${call.function}` : ' (calldata not decoded)';
    out.push([`${prefix}Target`, `${label(call.target)}${fn}`]);
  }
  return out;
}

function acceptancePairs(a: AcceptanceFact, label: (v: string) => string): DisplayPair[] {
  return [
    ['Firm', label(a.firm)],
    ['Instruction hash', a.instructionHash],
    ['Amount', String(a.amount)],
    ['Category', a.category],
  ];
}

/** Governance pairs from the typed operations the chain record (or the proposal) carries. */
function governancePairs(g: GovernanceFact, label: (v: string) => string): DisplayPair[] {
  const out: DisplayPair[] = [['Page', g.principal]];
  for (const op of g.operations) {
    out.push(['Operation', String(op.type) + (op.unrecognized ? ' (unrecognized)' : '')]);
    for (const [k, name] of [['keyHash', 'Key hash'], ['oldKeyHash', 'Old key hash'], ['newKeyHash', 'New key hash']] as const) {
      if (typeof op[k] === 'string') out.push([name, op[k] as string]);
    }
    for (const [k, name] of [['delegate', 'Delegate'], ['oldDelegate', 'Old delegate'], ['newDelegate', 'New delegate'], ['authority', 'Authority']] as const) {
      if (typeof op[k] === 'string') out.push([name, label(op[k] as string)]);
    }
    if (typeof op.threshold === 'number') out.push(['Threshold', String(op.threshold)]);
  }
  return out;
}

/** The display for a PolicyRequest, from its decoded facts only. Always starts with Principal and Body type. */
export function buildDisplay(pr: PolicyRequest, opts: DisplayOptions = {}): DisplayPair[] {
  const label = labeller(opts);
  const out: DisplayPair[] = [
    ['Principal', pr.account],
    ['Body type', pr.bodyType ?? 'unknown'],
  ];
  if (pr.governance) out.push(...governancePairs(pr.governance, label));
  if (pr.acceptance) out.push(...acceptancePairs(pr.acceptance, label));
  if (Array.isArray(pr.calldataDecoded)) {
    pr.calldataDecoded.forEach((call, i) => {
      const asset = pr.assets?.find((a) => a.legIndex === call.legIndex);
      out.push(...paymentPairs(call, asset, pr, label, i === 0 ? '' : `Leg ${call.legIndex + 1} `));
    });
  } else if (!pr.governance && !pr.acceptance && (pr.values?.length || pr.target)) {
    // A value-moving body with no decoded call (a native leg, a token send): show what was decoded.
    out.push(['Payer', label(adiOf(pr.account))]);
    if (pr.target) out.push(['Payee', label(pr.target)]);
    if (pr.values?.length) out.push(['Amount', `${pr.values.join(', ')} (base units)`]);
    if (pr.chain) out.push(['Chain', pr.chain]);
  }
  if (pr.unpricedLegs) out.push(['Unpriced legs', String(pr.unpricedLegs)]);
  return out;
}

/** The typed `updateKeyPage` operations a proposal's KeyPageOps build into (the same wire shape keypage.ts uses). */
export function proposalOperations(ops: KeyPageOp[]): Array<Record<string, unknown>> {
  return ops.map((o) => {
    switch (o.op) {
      case 'add-key': return { type: 'add', entry: { keyHash: o.keyHash } };
      case 'remove-key': return { type: 'remove', entry: { keyHash: o.keyHash } };
      case 'set-threshold': return { type: 'setThreshold', threshold: o.threshold };
      case 'add-delegate': return { type: 'add', entry: { delegate: o.delegate } };
      case 'remove-delegate': return { type: 'remove', entry: { delegate: o.delegate } };
      default: throw new Error(`operation ${(o as { op: string }).op} cannot be proposed`);
    }
  });
}

/** The display for a governance proposal on `page`: identical to what the resulting chain record decodes to. */
export function buildProposalDisplay(page: string, ops: KeyPageOp[], opts: DisplayOptions = {}): DisplayPair[] {
  const label = labeller(opts);
  const operations = proposalOperations(ops).map((o) => {
    const entry = (o.entry ?? {}) as Record<string, string>;
    return { type: String(o.type), ...entry, ...(o.threshold !== undefined ? { threshold: o.threshold } : {}) };
  });
  return [
    ['Principal', page],
    ['Body type', 'updateKeyPage'],
    ...governancePairs({ kind: 'updateKeyPage', principal: page, operations }, label),
  ];
}

/** Attach `display` and `summaryHash` to a request (returns a new object). */
export function withDisplay(pr: PolicyRequest, opts: DisplayOptions = {}): PolicyRequest {
  const display = buildDisplay(pr, opts);
  return { ...pr, display, summaryHash: tclSummaryV1(display) };
}

/**
 * The stored request for a governance transaction this signer submitted that still awaits another signature
 * (a delegate's consent, a threshold above one). Built from the typed op this signer itself built into the
 * transaction, so `GET /relay/officer/pending/<txHash>` and officer intake serve it as a transaction ref.
 */
export function awaitingGovernanceRequest(txHash: string, page: string, op: KeyPageOp, opts: DisplayOptions & { now?: number; ttlMs?: number } = {}): PolicyRequest {
  const display = buildProposalDisplay(page, [op], opts);
  const operations = proposalOperations([op]).map((o) => ({ type: String(o.type), ...((o.entry ?? {}) as Record<string, string>), ...(o.threshold !== undefined ? { threshold: o.threshold } : {}) }));
  const at = opts.now ?? Date.now();
  return {
    requestId: `governance:${txHash}`,
    txHash,
    signerUrl: page,
    account: page,
    actionSummary: `updateKeyPage on ${page}: ${op.op} (awaiting further signatures)`,
    bodyType: 'updateKeyPage',
    governance: { kind: 'updateKeyPage', principal: page, operations },
    header: { principal: page },
    display,
    summaryHash: tclSummaryV1(display),
    expiresAt: new Date(at + (opts.ttlMs ?? 24 * 60 * 60_000)).toISOString(),
  };
}
