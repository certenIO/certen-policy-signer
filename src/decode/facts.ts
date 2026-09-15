/**
 * Body facts read independently of the decoder chain. FICTIONAL Business Transaction Controls lab, Phase 6.
 *
 * Like the header, these are read by the resolver for every transaction whatever decoder claimed it, so an
 * operator's `resolver.decoders` ordering can never make a seat lose them:
 *   - `governance` (6.2): the typed operations of an `updateKeyPage` / `updateAccountAuth` body;
 *   - `acceptance` (6.1): a firm's acceptance WriteData (decision 0028 / 0038 §4).
 *
 * Both are READINGS of the bytes. Anything that does not match the expected shape exactly yields no fact
 * (or, for a governance operation, an entry marked `unrecognized`) — never a guess.
 */
import type { AcceptanceFact, GovernanceFact } from '../types.js';
import type { DecodeContext, DecodedAction, SummaryDecoder, TxBody } from './types.js';

const HEX64 = /^[0-9a-f]{64}$/;

function hexOf(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const h = v.toLowerCase().replace(/^0x/, '');
  return /^[0-9a-f]*$/.test(h) && h.length > 0 ? h : undefined;
}
const str = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined);
const num = (v: unknown): number | undefined => {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 ? n : undefined;
};

function keyEntry(e: unknown, prefix = ''): Record<string, string> {
  const o = (e && typeof e === 'object' ? e : {}) as Record<string, unknown>;
  const out: Record<string, string> = {};
  const kh = hexOf(o.keyHash);
  if (kh) out[prefix ? `${prefix}KeyHash` : 'keyHash'] = kh;
  const dg = str(o.delegate);
  if (dg) out[prefix ? `${prefix}Delegate` : 'delegate'] = dg;
  return out;
}

/** Typed governance operations, or undefined when the body is not a governance body. */
export function extractGovernance(body: TxBody | undefined, principal: string): GovernanceFact | undefined {
  if (!body || (body.type !== 'updateKeyPage' && body.type !== 'updateAccountAuth')) return undefined;
  const raw = (body.type === 'updateKeyPage' ? body.operation ?? body.operations : body.operations ?? body.operation);
  const list = Array.isArray(raw) ? raw : [];
  const operations = list.map((op: unknown): { type: string; [k: string]: unknown } => {
    const o = (op && typeof op === 'object' ? op : {}) as Record<string, unknown>;
    const type = String(o.type ?? 'unknown');
    if (body.type === 'updateKeyPage') {
      switch (type) {
        case 'add':
        case 'remove': {
          const entry = keyEntry(o.entry);
          return Object.keys(entry).length ? { type, ...entry } : { type, unrecognized: true };
        }
        case 'update': return { type, ...keyEntry(o.oldEntry, 'old'), ...keyEntry(o.newEntry, 'new') };
        case 'setThreshold':
        case 'setRejectThreshold':
        case 'setResponseThreshold': {
          const threshold = num(o.threshold);
          return threshold !== undefined ? { type, threshold } : { type, unrecognized: true };
        }
        case 'updateAllowed': {
          const names = (v: unknown) => (Array.isArray(v) ? v.map(String) : []);
          return { type, allow: names(o.allow), deny: names(o.deny) };
        }
      }
    } else {
      switch (type) {
        case 'addAuthority':
        case 'removeAuthority':
        case 'enable':
        case 'disable': {
          const authority = str(o.authority);
          return authority ? { type, authority } : { type, unrecognized: true };
        }
      }
    }
    return { type, unrecognized: true };
  });
  return { kind: body.type, principal, operations };
}

/** The canonical acceptance content, exactly: sorted keys, no whitespace, integer amount, 64-hex hash. */
export function parseAcceptanceContent(text: string): AcceptanceFact | undefined {
  let o: unknown;
  try { o = JSON.parse(text); } catch { return undefined; }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return undefined;
  const r = o as Record<string, unknown>;
  if (Object.keys(r).length !== 4) return undefined;
  const { amount, category, firm, instructionHash } = r;
  if (typeof amount !== 'number' || !Number.isSafeInteger(amount) || amount < 0) return undefined;
  if (typeof category !== 'string' || !category || typeof firm !== 'string' || !firm) return undefined;
  if (typeof instructionHash !== 'string' || !HEX64.test(instructionHash)) return undefined;
  const fact = { amount, category, firm, instructionHash };
  // Canonical form only: re-serialising must reproduce the bytes, so two encodings never read the same.
  if (JSON.stringify(fact) !== text) return undefined;
  return { instructionHash, category, amount, firm };
}

/** The acceptance fact, when the body is a WriteData on `acc://…/acceptances` with one canonical element. */
export function extractAcceptance(body: TxBody | undefined, principal: string): AcceptanceFact | undefined {
  if (!body || body.type !== 'writeData') return undefined;
  if (!/^acc:\/\/[^/]+\/acceptances\/?$/i.test(principal)) return undefined;
  const data = (body.entry as { data?: unknown } | undefined)?.data;
  if (!Array.isArray(data) || data.length !== 1) return undefined;
  const hex = typeof data[0] === 'string' ? data[0].replace(/^0x/, '') : undefined;
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return undefined;
  const bytes = Buffer.from(hex, 'hex');
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) return undefined;
  return parseAcceptanceContent(text);
}

/** Built-in decoder `governance`: a readable sentence for key-page and account-authority updates. */
export const governanceDecoder: SummaryDecoder = {
  name: 'governance',
  decode(body: TxBody, ctx: DecodeContext): DecodedAction | undefined {
    const g = extractGovernance(body, ctx.principal);
    if (!g) return undefined;
    const ops = g.operations.map((o) => {
      const detail = Object.entries(o).filter(([k]) => k !== 'type').map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('|') : String(v)}`).join(' ');
      return detail ? `${o.type} ${detail}` : o.type;
    });
    return {
      summary: { action: `${g.kind} on ${ctx.principal}: ${ops.length ? ops.join('; ') : 'no operations'}` },
      operationId: (body.operationId as string) || undefined,
    };
  },
};
