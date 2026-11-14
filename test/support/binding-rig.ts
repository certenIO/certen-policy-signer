/** The rig of the DAX-4S integration tests: a real Orchestrator over a real journal and pause state in a temp directory. FICTIONAL. */
import { afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { MockAccumulateClient } from '../../src/accumulate/client.js';
import { DecisionJournal } from '../../src/binding/journal.js';
import { NonceStore } from '../../src/binding/nonces.js';
import { PauseStore } from '../../src/binding/pause-store.js';
import { PinStore } from '../../src/binding/pin-store.js';
import { RefusalReceipts } from '../../src/binding/refusals.js';
import { buildPresentedRequest } from '../../src/binding/request.js';
import { DECISION_RECORD_MEMBER, type BindingRules } from '../../src/binding/verify.js';
import { hashRequest } from '../../src/core/hashes.js';
import { Orchestrator } from '../../src/orchestrator.js';
import { MockPolicyClient } from '../../src/policy/policy.js';
import { Resolver } from '../../src/resolver.js';
import { LocalSigner } from '../../src/signer/signer.js';
import { singleKeyring, type Keyring } from '../../src/signer/keyring.js';
import { MemoryStore } from '../../src/store/store.js';
import type { Decision, PolicyRequest } from '../../src/types.js';
import { APPROVER, POLICY, PRINCIPAL, SEAT, H, intentBody, record } from './binding-fixtures.js';
import type { BindingWorld } from '../../src/binding/world.js';

export const silent = pino({ level: 'silent' });
export const SIGNER = 'acc://o.acme/book/1';
export const TX = 'ab'.repeat(32);
export const NOW_S = 1_800_000_000;
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
export const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'dax4s-o-')); dirs.push(d); return d; };

export type Body = ReturnType<typeof intentBody>;
export const requestHashOf = (body: Body, tx = TX): string => {
  const b = buildPresentedRequest({ txHash: tx, rawTransaction: { body }, summary: { action: 'x' } });
  if (!b.ok) throw new Error(b.detail);
  return hashRequest(b.value.request);
};

export const RULES: BindingRules = { seat: SEAT, authorizedApprovers: [APPROVER], maxWindowSeconds: 7200, policyHash: POLICY, requireGrant: false };

export interface RigOpts {
  dir?: string;
  body: Body;
  /** the decision the engine returns for every ask */
  reply: (req: PolicyRequest) => Decision;
  rules?: Partial<BindingRules> | null; // null: no binding on this seat (legacy)
  world?: BindingWorld;
  submitRejectVote?: boolean;
  tx?: string;
  votes?: ConstructorParameters<typeof Orchestrator>[0]['votes'];
  /** the seat id and page of this service (default: the shared SEAT and SIGNER) */
  seat?: string;
  page?: string;
  keyring?: Keyring;
  /** the page is a human-only seat (G-69): decided here, never signed here */
  humanOnly?: boolean;
  store?: MemoryStore;
  /** pin the loaded hash (`rules.policyHash`) before the first request, as the operator's pin step does (default true); false leaves the seat `pin_pending` */
  pinned?: boolean;
  /** a hash that was pinned under an EARLIER rule set: the seat then loads `rules.policyHash`, which differs, and is `pin_stale` */
  stalePin?: string;
  /** the transaction header deadline (`header.expire.atTime`), RFC 3339 */
  header?: string;
}
export const PIN_BY = 'seat:fic-operator';
export const PIN_WHY = 'FICTIONAL: the rule set was reviewed by two officers';
/** a pin store over the journal for the seats, with each seat's loaded hash pinned (the operator's step already taken) unless `pinned` is false */
export function pinStoreFor(journal: DecisionJournal, seats: Array<{ seat: string; loadedHash: string }>, pinned = true): PinStore {
  const pins = new PinStore({ journal, seats, nowSeconds: () => NOW_S });
  if (pinned) for (const s of seats) { const r = pins.pinNow({ seat: s.seat, hash: s.loadedHash, by: PIN_BY, reason: PIN_WHY }); if (!r.ok) throw new Error('rig pin: ' + r.reason); }
  return pins;
}
export function rig(o: RigOpts) {
  const dir = o.dir ?? tmp();
  const journal = new DecisionJournal({ path: join(dir, 'decision-journal.jsonl'), logId: 'fic-signer' });
  const nonces = new NonceStore(journal, () => NOW_S);
  const seat = o.seat ?? SEAT;
  const page = o.page ?? SIGNER;
  const pauses = new PauseStore({ journal, statePath: join(dir, 'pause-state.json'), seats: [seat], nowSeconds: () => NOW_S });
  const acc = new MockAccumulateClient();
  const tx = o.tx ?? TX;
  acc.addPending(tx, { body: o.body, principal: `${PRINCIPAL}/tokens`, ...(o.header ? { rawTransaction: { header: { principal: `${PRINCIPAL}/tokens`, expire: { atTime: o.header } }, body: o.body } } : {}) });
  const store = o.store ?? new MemoryStore();
  const policy = new MockPolicyClient(o.reply);
  const loaded = { ...RULES, ...(o.rules ?? {}) }.policyHash;
  if (o.stalePin !== undefined) pinStoreFor(journal, [{ seat, loadedHash: o.stalePin }]); // an earlier boot under the earlier rule set pinned it
  const pins = pinStoreFor(journal, [{ seat, loadedHash: loaded }], o.stalePin === undefined && o.pinned !== false);
  const refusals = new RefusalReceipts(journal, () => NOW_S);
  const orch = new Orchestrator({
    accumulate: acc, keyring: o.keyring ?? singleKeyring(new LocalSigner(new Uint8Array(32).fill(7))), policy, store, resolver: new Resolver(acc), logger: silent,
    now: () => NOW_S * 1000, pauses, ...(o.humanOnly ? { humanOnlyPages: [page] } : {}),
    ...(o.votes ? { votes: o.votes } : {}),
    seats: new Map([[page.toLowerCase(), { seat, ...(o.rules === null ? {} : { binding: { ...RULES, seat, ...(o.rules ?? {}) } }) }]]),
    binding: { nonces, pins, refusals, ...(o.world ? { world: o.world } : {}), nowSeconds: () => NOW_S },
    options: { submitRejectVote: o.submitRejectVote ?? false },
  });
  const handle = () => orch.handle({ txHash: tx, signerUrl: page });
  return { dir, journal, nonces, pins, refusals, pauses, acc, store, policy, orch, handle, tx };
}

export const approveFor = (body: Body, over: Parameters<typeof record>[0] extends infer R ? Partial<R> : never = {}, verb: 'approve' | 'deny' = 'approve', tx = TX) =>
  (): Decision => ({
    decision: verb, reason: 'FICTIONAL officers approved',
    [DECISION_RECORD_MEMBER]: record({ requestHash: requestHashOf(body, tx), decision: verb, issuedAt: NOW_S - 10, nonce: H('nonce-fixed'), ...over }),
  } as Decision);

