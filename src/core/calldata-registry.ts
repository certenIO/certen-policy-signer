/**
 * The policy token registry (DAX-7A, DESIGN.md sections 3, 4 D10 and D11). It is the POLICY's statement of what a token is on
 * a chain: its symbol and its decimals, and which wrapper contracts the policy lets act for it. The decoder trusts it and
 * never reads a chain: a token whose registry decimals or symbol disagree with the chain is the registry's problem, and the
 * only protection is that the registry is content-hashed (so its owner can pin the hash in the policy hash) and reviewed.
 *
 * Shape: { schema: "certen.tokenreg/v1", tokens: [{ chainId, address, symbol, decimals, proxies? }] }.
 *   address   `native` (the chain's native currency) or a lowercase 0x address
 *   symbol    1 to 12 ASCII letters and digits with at least one letter (no punctuation, no spaces, no Unicode, no controls)
 *   decimals  an integer from 0 to 36
 *   proxies   lowercase addresses of wrapper contracts the policy names for this token (never on a native entry)
 * Refusals (reason, detail is a path such as tokens[2].symbol): registry_malformed, registry_schema_invalid,
 * registry_too_large, token_malformed, token_chain_invalid, token_address_invalid, token_symbol_invalid,
 * token_decimals_invalid, token_proxies_invalid, token_duplicate, proxy_duplicate, symbol_collision, symbol_confusable.
 *
 * Hash: SHA-256( lp("certen:tokenreg:v1") || lp(canonical registry) ), the canonical form being the RFC 8785 text of the
 * validated registry with tokens sorted by chain then address and proxies sorted, an absent or empty `proxies` omitted. The
 * registry is a set: order and the spelling of "no proxies" do not move the hash, any change of content does.
 */
import { ADDRESS_RE, CoreError, utf8 } from './bytes.js';
import { closedObject, dataArray, dataObject } from './decision-identity.js';
import { digestHex, taggedPreimage } from './hashes.js';
import { canonicalize, parseJson } from './jcs.js';

export const TOKEN_REGISTRY_SCHEMA = 'certen.tokenreg/v1';
export const TOKEN_REGISTRY_TAG = 'certen:tokenreg:v1';
export const TOKEN_REGISTRY_LIMITS = { maxTokens: 1024, maxProxies: 16, maxSymbolLength: 12, maxDecimals: 36 } as const;

export interface TokenEntry {
  chainId: number;
  address: string;
  symbol: string;
  decimals: number;
  proxies?: string[];
}
export interface TokenRegistry {
  schema: 'certen.tokenreg/v1';
  tokens: TokenEntry[];
}
export type RegistryValidation = { ok: true; registry: TokenRegistry } | { ok: false; reason: string; detail?: string };

const refuse = (reason: string, detail?: string): { ok: false; reason: string; detail?: string } => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail });

const SYMBOL_RE = /^[A-Za-z0-9]{1,12}$/;
const HAS_LETTER_RE = /[A-Za-z]/;

/** What a symbol reads like: uppercase, with 0 read as O and 1 and L read as I. Equal skeletons on one chain are refused. */
function skeleton(symbol: string): string {
  let out = '';
  for (const ch of symbol.toUpperCase()) out += ch === '0' ? 'O' : ch === '1' || ch === 'L' ? 'I' : ch;
  return out;
}

const compareEntries = (a: TokenEntry, b: TokenEntry): number => (a.chainId !== b.chainId ? a.chainId - b.chainId : a.address < b.address ? -1 : a.address > b.address ? 1 : 0);

function validateInner(v: unknown): RegistryValidation {
  const o = dataObject(v);
  if (o === null) return refuse('registry_malformed', 'shape');
  for (const k of Object.keys(o)) if (k !== 'schema' && k !== 'tokens') return refuse('registry_malformed', 'unknown:' + k);
  if (o['schema'] === undefined) return refuse('registry_malformed', 'missing:schema');
  if (o['tokens'] === undefined) return refuse('registry_malformed', 'missing:tokens');
  if (o['schema'] !== TOKEN_REGISTRY_SCHEMA) return refuse('registry_schema_invalid');
  const rawTokens = o['tokens'];
  if (!Array.isArray(rawTokens)) return refuse('registry_malformed', 'tokens');
  if (rawTokens.length > TOKEN_REGISTRY_LIMITS.maxTokens) return refuse('registry_too_large', 'tokens');
  const list = dataArray(rawTokens, TOKEN_REGISTRY_LIMITS.maxTokens);
  if (list === null) return refuse('registry_malformed', 'tokens');

  // pass 1: every entry on its own, in the order shape, chain, address, symbol, decimals, proxies
  const entries: TokenEntry[] = [];
  for (let i = 0; i < list.length; i++) {
    const at = 'tokens[' + i + ']';
    const e = closedObject(list[i], ['chainId', 'address', 'symbol', 'decimals'], ['proxies']);
    if (e === null) return refuse('token_malformed', at);
    const chainId = e['chainId'];
    if (typeof chainId !== 'number' || !Number.isSafeInteger(chainId) || chainId < 1 || Object.is(chainId, -0)) return refuse('token_chain_invalid', at + '.chainId');
    const address = e['address'];
    if (typeof address !== 'string' || (address !== 'native' && !ADDRESS_RE.test(address))) return refuse('token_address_invalid', at + '.address');
    const symbol = e['symbol'];
    if (typeof symbol !== 'string' || !SYMBOL_RE.test(symbol) || !HAS_LETTER_RE.test(symbol)) return refuse('token_symbol_invalid', at + '.symbol');
    const decimals = e['decimals'];
    if (typeof decimals !== 'number' || !Number.isInteger(decimals) || Object.is(decimals, -0) || decimals < 0 || decimals > TOKEN_REGISTRY_LIMITS.maxDecimals) return refuse('token_decimals_invalid', at + '.decimals');
    const entry: TokenEntry = { chainId, address, symbol, decimals };
    if ('proxies' in e) {
      const rawProxies = e['proxies'];
      if (address === 'native' || !Array.isArray(rawProxies)) return refuse('token_proxies_invalid', at + '.proxies');
      if (rawProxies.length > TOKEN_REGISTRY_LIMITS.maxProxies) return refuse('registry_too_large', at + '.proxies');
      const proxies = dataArray(rawProxies, TOKEN_REGISTRY_LIMITS.maxProxies);
      if (proxies === null) return refuse('token_proxies_invalid', at + '.proxies');
      for (let j = 0; j < proxies.length; j++) {
        const p = proxies[j];
        if (typeof p !== 'string' || !ADDRESS_RE.test(p) || p === address) return refuse('token_proxies_invalid', at + '.proxies[' + j + ']');
      }
      if (proxies.length > 0) entry.proxies = [...(proxies as string[])].sort();
    }
    entries.push(entry);
  }

  // pass 2: the entries against each other, per chain: address, symbol, then proxies
  const used = new Map<string, 'address' | 'proxy'>();
  const symbols = new Map<string, string>();
  const skeletons = new Set<string>();
  for (let i = 0; i < entries.length; i++) {
    const at = 'tokens[' + i + ']';
    const t = entries[i]!;
    const key = t.chainId + ':' + t.address;
    const seen = used.get(key);
    if (seen === 'address') return refuse('token_duplicate', at);
    if (seen === 'proxy') return refuse('proxy_duplicate', at);
    const sk = t.chainId + ':' + skeleton(t.symbol);
    if (skeletons.has(sk)) return refuse(symbols.get(t.chainId + ':' + t.symbol) !== undefined ? 'symbol_collision' : 'symbol_confusable', at);
    skeletons.add(sk);
    symbols.set(t.chainId + ':' + t.symbol, at);
    used.set(key, 'address');
    const proxies = t.proxies ?? [];
    for (let j = 0; j < proxies.length; j++) {
      const pk = t.chainId + ':' + proxies[j]!;
      if (used.has(pk)) return refuse('proxy_duplicate', at + '.proxies[' + j + ']');
      used.set(pk, 'proxy');
    }
  }

  entries.sort(compareEntries);
  return { ok: true, registry: { schema: TOKEN_REGISTRY_SCHEMA, tokens: entries } };
}

/** A validated, normalised copy of the registry (tokens and proxies sorted), or a named refusal. Never throws. */
export function validateTokenRegistry(v: unknown): RegistryValidation {
  try {
    return validateInner(v);
  } catch {
    return refuse('registry_malformed', 'unreadable');
  }
}

/** The RFC 8785 text of a validated registry. */
function canonicalText(registry: TokenRegistry): string {
  return canonicalize({ schema: registry.schema, tokens: registry.tokens });
}

export type RegistryHashResult = { ok: true; hash: string; canonical: string; registry: TokenRegistry } | { ok: false; reason: string; detail?: string };

/** The content hash of a registry (certen:tokenreg:v1, length-prefixed), with the canonical text it was computed over. */
export function hashTokenRegistry(v: unknown): RegistryHashResult {
  const r = validateTokenRegistry(v);
  if (!r.ok) return r;
  const canonical = canonicalText(r.registry);
  return { ok: true, hash: digestHex(taggedPreimage(TOKEN_REGISTRY_TAG, [utf8(canonical)])), canonical, registry: r.registry };
}

export type ParseRegistryResult = { ok: true; registry: TokenRegistry; canonical: string; registryHash: string } | { ok: false; reason: string; detail?: string };

/** Strict parse of registry text (duplicate members, lone surrogates, floats and trailing data refuse), then validation and hash. */
export function parseTokenRegistryText(text: string): ParseRegistryResult {
  let parsed: unknown;
  try {
    parsed = parseJson(text, { integersOnly: true });
  } catch (e) {
    if (e instanceof CoreError) return refuse('registry_text_invalid', e.code);
    return refuse('registry_text_invalid', 'unreadable');
  }
  const h = hashTokenRegistry(parsed);
  if (!h.ok) return h;
  return { ok: true, registry: h.registry, canonical: h.canonical, registryHash: h.hash };
}

/** The entry for a token on a chain (`native` for the chain's currency), or null. A proxy address is NOT a token address. */
export function findToken(registry: TokenRegistry, chainId: number, address: string): TokenEntry | null {
  for (const t of registry.tokens) if (t.chainId === chainId && t.address === address) return t;
  return null;
}

/** Whether some entry of the registry names this address as a wrapper on this chain. */
export function isNamedProxy(registry: TokenRegistry, chainId: number, address: string): boolean {
  for (const t of registry.tokens) if (t.chainId === chainId && t.proxies !== undefined && t.proxies.includes(address)) return true;
  return false;
}
