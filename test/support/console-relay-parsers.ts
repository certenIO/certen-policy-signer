/**
 * THE CONSOLE'S STRICT PARSERS, COPIED AS FIXTURES (no import across repos). Source: src/relay/routes.ts of branch pl/dax-4c-decision-binding of the
 * Console (transaction-controls) at commit f50d5b31c81a73038f7d2b69bd7c1b44980ec7cb; sha256 of that file with LF line endings 074ad9076e8acafe02eae52b22d917ac8f6fae730b63e9f9d7c2c850b771a0ba.
 * Everything from `type Obj` to `parseKeybook` below is that file's text, unchanged; only the import line differs (the signer's own copy of the core).
 * When the Console changes a route shape this file is re-copied and test/binding-console-contract.test.ts says what the signer must now answer.
 *
 * `parseChainLen` is NOT the Console's: its routes.ts at f50d5b3 has no chain-length route yet. It is the shape the DAX-4S round 3 addendum
 * fixed ({ length: number }, nothing else) written in the style of the parsers above, so the Console's future parser can be diffed against it.
 */
import type { AccountHistory, DataEntry } from '../../src/core/reader.js';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const only = (o: Obj, keys: readonly string[]): boolean => Object.keys(o).every((k) => keys.includes(k)) && keys.every((k) => k in o);
const HEX64 = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})*$/;
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

export function parseDataEntries(v: unknown): DataEntry[] | null {
  if (!isObj(v) || !only(v, ['entries']) || !Array.isArray(v['entries'])) return null;
  const out: DataEntry[] = [];
  for (const e of v['entries'] as unknown[]) {
    if (!isObj(e) || !only(e, ['txId', 'time', 'elements']) || typeof e['txId'] !== 'string' || e['txId'] === '' || !isTime(e['time']) || !Array.isArray(e['elements'])) return null;
    const elements: Uint8Array[] = [];
    for (const h of e['elements'] as unknown[]) {
      if (typeof h !== 'string' || !HEX.test(h)) return null;
      elements.push(Uint8Array.from(Buffer.from(h, 'hex')));
    }
    out.push({ txId: e['txId'], time: e['time'], elements });
  }
  return out;
}

export function parseAuthorities(v: unknown): string[] | null {
  if (!isObj(v) || !only(v, ['authorities']) || !Array.isArray(v['authorities'])) return null;
  const a = v['authorities'] as unknown[];
  return a.every((x) => typeof x === 'string' && x !== '') ? (a as string[]) : null;
}

export function parseHistory(v: unknown): AccountHistory | null {
  if (!isObj(v) || !only(v, ['types', 'incomplete']) || !Array.isArray(v['types']) || typeof v['incomplete'] !== 'boolean') return null;
  const types = v['types'] as unknown[];
  if (!types.every((t) => typeof t === 'string' && t !== '')) return null;
  return { types: types as string[], incomplete: v['incomplete'] };
}

export interface KeybookPage { url: string; keyHashes: string[]; delegates: string[]; threshold: number }

export function parseKeybook(v: unknown): KeybookPage[] | null {
  if (!isObj(v) || !only(v, ['pages']) || !Array.isArray(v['pages'])) return null;
  const out: KeybookPage[] = [];
  for (const p of v['pages'] as unknown[]) {
    if (!isObj(p) || !only(p, ['url', 'keyHashes', 'delegates', 'threshold']) || typeof p['url'] !== 'string' || !Array.isArray(p['keyHashes']) || !Array.isArray(p['delegates'])) return null;
    if (typeof p['threshold'] !== 'number' || !Number.isSafeInteger(p['threshold']) || p['threshold'] < 1) return null;
    if (!(p['keyHashes'] as unknown[]).every((h) => typeof h === 'string' && HEX64.test(h)) || !(p['delegates'] as unknown[]).every((d) => typeof d === 'string')) return null;
    out.push({ url: p['url'], keyHashes: p['keyHashes'] as string[], delegates: p['delegates'] as string[], threshold: p['threshold'] });
  }
  return out;
}

/** NOT the Console's text (see the header): GET /relay/chainlen/:account -> { length: number } */
export function parseChainLen(v: unknown): number | null {
  if (!isObj(v) || !only(v, ['length']) || typeof v['length'] !== 'number' || !Number.isSafeInteger(v['length']) || v['length'] < 0) return null;
  return v['length'];
}
