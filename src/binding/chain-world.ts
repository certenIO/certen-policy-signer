/**
 * The production `BindingWorld` (READER-MODEL-V2): the head of a Grant lineage and the subject a transaction resolves to, through
 * the core's ONLINE readers over an `AccumulateReader` view of the read cache (src/binding/read-cache.ts). No key page is read:
 * the gate is the account authority rule (the authority set now is exactly the owner's book, the account's own main chain from
 * creation shows only SAFE_AFTER types), canonical entries, the prior-hash chain and the owner match, so a routine key rotation
 * cannot brick a lineage (DAX2-L9).
 *
 * The Grant head. `readGrantLineage` takes the grantor's key book from the CALLER (the seat configures it). The lineage result
 * names the head's hash but not the Grant, so the view's data entries are kept and the head Grant is decoded from the same
 * bytes the lineage verified. A first pass learns the Grant's subject, the second passes the subject's books as the forbidden
 * books of the authority rule (both passes are served by ONE evaluation: the node is asked once per account).
 * A head that is not `in_force` (ended, not yet valid) is not a head a decision can be bound to.
 *
 * The subject. `readSubjectRegistry` resolves the asserted subject ONLY through `<grant.grantor.adi>/certen-subjects` and the
 * consent in `<subject>/certen-acceptances`; a registration by any other ADI is invisible. The expected type is the Grant's.
 */
import { decodeEntry } from '../core/envelope.js';
import { readGrantLineage, readSubjectRegistry, type AccumulateReader, type DataEntry } from '../core/reader.js';
import { validateGrant } from '../core/grant-profile.js';
import type { BindingWorld, GrantHead, WorldAnswer } from './world.js';
import type { CountedReader } from './read-cache.js';

export interface ChainWorldOptions {
  /** one evaluation view per call: its counters are the evaluation's */
  evaluation: () => CountedReader;
  nowSeconds: () => number;
}

/** a refusal as one line: its reason, then the cause or detail the core gave (an undecodable entry names why) */
function why(r: { reason: string; detail?: string; cause?: string; index?: number }): string {
  return r.reason + (r.cause ? ' ' + r.cause : '') + (r.detail ? ' ' + r.detail : '') + (r.index === undefined ? '' : ' @' + r.index);
}

export function createChainWorld(o: ChainWorldOptions): BindingWorld {
  return {
    async establish({ grantorAdi, grantorBook, grantId, asserted }) {
      const view = o.evaluation();
      const seen = new Map<string, DataEntry[] | null>();
      const reader: AccumulateReader = {
        authorities: (a) => view.authorities(a),
        accountHistory: (a) => view.accountHistory(a),
        dataEntries: async (a) => {
          const e = await view.dataEntries(a);
          seen.set(a, e);
          return e;
        },
      };
      const now = o.nowSeconds();
      const done = (head: WorldAnswer<GrantHead>, subject: Awaited<ReturnType<BindingWorld['establish']>>['subject'] = null) => ({ head, subject, stats: view.stats() });

      // pass 1: the lineage, to learn the Grant's subject; pass 2: again with the subject's books as the forbidden books
      const lineageArgs = { grantorAdi, grantorBook, grantId, now };
      const first = await readGrantLineage(reader, lineageArgs);
      if (!first.ok) return done({ ok: false, detail: `lineage:${why(first)}` });
      const grantsAccount = `${grantorAdi}/certen-grants`;
      const entryAt = (index: number): Uint8Array[] | undefined => seen.get(grantsAccount)?.[index]?.elements;
      const headRec = first.entries.find((e) => e.hash === first.head.hash && e.version === first.head.version);
      const elements = headRec === undefined ? undefined : entryAt(headRec.index);
      if (elements === undefined) return done({ ok: false, detail: 'head_entry_not_found' });
      const d = decodeEntry({ account: 'grants', elements });
      if (!d.ok || d.account !== 'grants') return done({ ok: false, detail: 'head_entry_undecodable' });
      const r = await readGrantLineage(reader, { ...lineageArgs, subjectAdi: d.grant.subject.adi });
      if (!r.ok) return done({ ok: false, detail: `lineage:${why(r)}` });
      if (r.head.hash !== first.head.hash) return done({ ok: false, detail: 'lineage_moved_during_read' });
      if (r.status !== 'in_force') return done({ ok: false, detail: `grant_${r.status}` });
      const g = validateGrant(d.grant);
      if (!g.ok) return done({ ok: false, detail: 'head_grant_malformed' });
      const head: WorldAnswer<GrantHead> = { ok: true, value: { hash: r.head.hash, subject: { adi: g.grant.subject.adi, type: g.grant.subject.type }, grant: g.grant } };
      if (asserted === null) return done(head);

      const res = await readSubjectRegistry(reader, { grant: g.grant, asserted, expectType: g.grant.subject.type });
      // an unproven subject names its state; an input the resolver refused (`resolve_input_malformed`, DAX-2 round 6) has none and names the reason
      if (!res.ok) return done(head, { ok: false, detail: 'state' in res ? `${res.state}:${why(res)}` : why(res) });
      return done(head, { ok: true, value: { adi: res.subject.adi, type: res.subject.type as 'agent' | 'merchant' | 'client' } });
    },
  };
}
