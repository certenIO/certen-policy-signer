/**
 * The production `BindingWorld`: the head of a Grant lineage and the subject a transaction resolves to, read through the core's
 * `readGrantLineage`, `readSubjectRegistry` and `resolveSubject` over an `AccumulateReader` (src/binding/chain-reader.ts).
 *
 * The Grant head. `readGrantLineage` verifies every version's envelope against the key pages the reader returns and evaluates
 * the whole lineage (a fork, a gap, a wrong prior hash or a version that does not verify refuses the WHOLE lineage). The
 * lineage result names the head's hash but not its subject, so the reader is wrapped to keep the bytes of the entries it
 * verified, and the head's subject is decoded from those same bytes (a version never changes its subject, GR-22). A head that is
 * not `in_force` (ended, not yet valid) is not a head a decision can be bound to: `{ ok: false }`, which the core names
 * `grant_unverified`.
 *
 * The subject. The registries of the seat's configured principals are read and every row of the asserted ADI is resolved with
 * `resolveSubject` (a fork, a gap, a suspended or retired subject, a submitter that is not the principal's: each is refused as
 * `subject_unproven`). The expected type is the type of the registry's own record: the comparison of the TYPE with the Grant's
 * is the core's, so that a registry type other than the Grant's is reported as `grant_subject_mismatch` and not hidden.
 */
import { decodeEntry } from '../core/envelope.js';
import { readGrantLineage, readSubjectRegistry, type AccumulateReader, type DataEntry } from '../core/reader.js';
import { resolveSubject } from '../core/registry.js';
import type { BindingWorld } from './world.js';

export function createChainWorld(o: { reader: AccumulateReader; nowSeconds: () => number }): BindingWorld {
  return {
    async grantHead({ grantorAdi, grantId }) {
      const seen = new Map<string, DataEntry[] | null>();
      const recording: AccumulateReader = {
        authorities: (a) => o.reader.authorities(a),
        keyBookPages: (b) => o.reader.keyBookPages(b),
        async dataEntries(account) {
          const e = await o.reader.dataEntries(account);
          seen.set(account, e);
          return e;
        },
      };
      const r = await readGrantLineage(recording, { grantorAdi, grantId, now: o.nowSeconds() });
      if (!r.ok) return { ok: false, detail: `lineage:${r.reason}${'detail' in r && r.detail ? ' ' + r.detail : ''}` };
      if (r.status !== 'in_force') return { ok: false, detail: `grant_${r.status}` };
      const rec = r.entries?.find((e) => e.hash === r.head.hash && e.version === r.head.version);
      const elements = rec === undefined ? undefined : [...seen.values()].flatMap((v) => v ?? []).find((e) => e.txId === rec.txId)?.elements;
      if (elements === undefined) return { ok: false, detail: 'head_entry_not_found' };
      const d = decodeEntry({ account: 'grants', elements });
      if (!d.ok || d.account !== 'grants') return { ok: false, detail: 'head_entry_undecodable' };
      return { ok: true, value: { hash: r.head.hash, subject: { adi: d.grant.subject.adi, type: d.grant.subject.type } } };
    },

    async resolveSubject({ principals, asserted }) {
      if (principals.length === 0) return { ok: false, detail: 'no_registry_principals_configured' };
      const rows: Array<{ record: unknown; envelopeVerdict: string; txId: string; registrationHash: string }> = [];
      for (const p of principals) {
        const reg = await readSubjectRegistry(o.reader, p);
        if (!reg.ok) return { ok: false, detail: `registry:${reg.reason}` };
        rows.push(...reg.registry);
      }
      const mine = rows.find((r) => (r.record as { adi?: unknown }).adi === asserted.adi);
      const expectType = (mine?.record as { type?: string } | undefined)?.type ?? 'agent';
      const res = resolveSubject({ asserted, expectType, registry: rows });
      if (!res.ok) return { ok: false, detail: `${res.state}:${res.reason}` };
      const type = res.subject.type as 'agent' | 'merchant' | 'client';
      return { ok: true, value: { adi: res.subject.adi, type } };
    },
  };
}
