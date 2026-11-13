/**
 * Strict JSON parsing and RFC 8785 (JCS) canonicalization. Written for this package from RFC 8259 and RFC 8785 and
 * judged by the DAX-2 vectors; it shares no code with docs/core/vectors/lib (GR-06: a third implementation).
 *
 * Parsing refuses what has no single meaning: a duplicate member name, a lone surrogate, trailing data, anything that
 * is not JSON (NaN, a leading zero, a trailing comma). Canonicalization emits members sorted by UTF-16 code units, the
 * ECMAScript form of numbers and the minimal string escapes, and refuses values JSON cannot carry.
 */
import { CoreError, hasLoneSurrogate, isPlainObject, type Json } from './bytes.js';

export const MAX_DEPTH = 128;

const BS = String.fromCharCode(92);
const DQ = String.fromCharCode(34);

export interface ParseOptions {
  /** Grant profile: every number must be written as a plain integer literal within +/-(2^53-1). */
  integersOnly?: boolean;
  maxDepth?: number;
}

const isDigit = (c: string | undefined): boolean => c !== undefined && c >= '0' && c <= '9';
const isHexDigit = (c: string): boolean => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

class Parser {
  private i = 0;
  constructor(
    private readonly s: string,
    private readonly integersOnly: boolean,
    private readonly maxDepth: number,
  ) {}

  parseTop(): Json {
    const v = this.value(0);
    this.ws();
    if (this.i < this.s.length) throw new CoreError('json_trailing_data');
    return v;
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 32 || c === 9 || c === 10 || c === 13) this.i++;
      else break;
    }
  }

  private value(depth: number): Json {
    if (depth > this.maxDepth) throw new CoreError('json_too_deep');
    this.ws();
    if (this.i >= this.s.length) throw new CoreError('json_unexpected_end');
    const c = this.s[this.i]!;
    if (c === '{') return this.object(depth);
    if (c === '[') return this.array(depth);
    if (c === DQ) return this.string();
    if (c === '-' || isDigit(c)) return this.number();
    if (this.s.startsWith('true', this.i)) {
      this.i += 4;
      return true;
    }
    if (this.s.startsWith('false', this.i)) {
      this.i += 5;
      return false;
    }
    if (this.s.startsWith('null', this.i)) {
      this.i += 4;
      return null;
    }
    throw new CoreError('json_unexpected_token');
  }

  private object(depth: number): Json {
    this.i++;
    const out: { [key: string]: Json } = {};
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.i] === '}') {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.i >= this.s.length) throw new CoreError('json_unexpected_end');
      if (this.s[this.i] !== DQ) throw new CoreError('json_expected_member_name');
      const key = this.string();
      if (seen.has(key)) throw new CoreError('duplicate_key');
      seen.add(key);
      this.ws();
      if (this.i >= this.s.length) throw new CoreError('json_unexpected_end');
      if (this.s[this.i] !== ':') throw new CoreError('json_expected_colon');
      this.i++;
      const v = this.value(depth + 1);
      // defineProperty keeps a member named __proto__ as plain data
      Object.defineProperty(out, key, { value: v, enumerable: true, writable: true, configurable: true });
      this.ws();
      if (this.i >= this.s.length) throw new CoreError('json_unexpected_end');
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        continue;
      }
      if (c === '}') {
        this.i++;
        return out;
      }
      throw new CoreError('json_expected_comma_or_end');
    }
  }

  private array(depth: number): Json {
    this.i++;
    const out: Json[] = [];
    this.ws();
    if (this.s[this.i] === ']') {
      this.i++;
      return out;
    }
    for (;;) {
      out.push(this.value(depth + 1));
      this.ws();
      if (this.i >= this.s.length) throw new CoreError('json_unexpected_end');
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        continue;
      }
      if (c === ']') {
        this.i++;
        return out;
      }
      throw new CoreError('json_expected_comma_or_end');
    }
  }

  private hex4(): number {
    const h = this.s.slice(this.i, this.i + 4);
    if (h.length < 4 || ![...h].every(isHexDigit)) throw new CoreError('json_bad_escape');
    this.i += 4;
    return parseInt(h, 16);
  }

  private string(): string {
    this.i++;
    let out = '';
    for (;;) {
      if (this.i >= this.s.length) throw new CoreError('json_unterminated_string');
      const code = this.s.charCodeAt(this.i);
      if (code === 34) {
        this.i++;
        return out;
      }
      if (code < 0x20) throw new CoreError('json_control_character');
      if (code === 92) {
        this.i++;
        if (this.i >= this.s.length) throw new CoreError('json_unterminated_string');
        const e = this.s[this.i]!;
        this.i++;
        switch (e) {
          case DQ: out += DQ; break;
          case BS: out += BS; break;
          case '/': out += '/'; break;
          case 'b': out += String.fromCharCode(8); break;
          case 'f': out += String.fromCharCode(12); break;
          case 'n': out += String.fromCharCode(10); break;
          case 'r': out += String.fromCharCode(13); break;
          case 't': out += String.fromCharCode(9); break;
          case 'u': {
            const u = this.hex4();
            if (u >= 0xd800 && u <= 0xdbff) {
              if (this.s[this.i] === BS && this.s[this.i + 1] === 'u') {
                this.i += 2;
                const low = this.hex4();
                if (low < 0xdc00 || low > 0xdfff) throw new CoreError('lone_surrogate');
                out += String.fromCharCode(u, low);
              } else throw new CoreError('lone_surrogate');
            } else if (u >= 0xdc00 && u <= 0xdfff) throw new CoreError('lone_surrogate');
            else out += String.fromCharCode(u);
            break;
          }
          default:
            throw new CoreError('json_bad_escape');
        }
        continue;
      }
      if (code >= 0xd800 && code <= 0xdbff) {
        const n = this.i + 1 < this.s.length ? this.s.charCodeAt(this.i + 1) : 0;
        if (n >= 0xdc00 && n <= 0xdfff) {
          out += this.s[this.i]! + this.s[this.i + 1]!;
          this.i += 2;
          continue;
        }
        throw new CoreError('lone_surrogate');
      }
      if (code >= 0xdc00 && code <= 0xdfff) throw new CoreError('lone_surrogate');
      out += this.s[this.i]!;
      this.i++;
    }
  }

  private number(): number {
    const start = this.i;
    if (this.s[this.i] === '-') this.i++;
    if (!isDigit(this.s[this.i])) throw new CoreError('json_bad_number');
    if (this.s[this.i] === '0') this.i++;
    else while (isDigit(this.s[this.i])) this.i++;
    let integerLiteral = true;
    if (this.s[this.i] === '.') {
      integerLiteral = false;
      this.i++;
      if (!isDigit(this.s[this.i])) throw new CoreError('json_bad_number');
      while (isDigit(this.s[this.i])) this.i++;
    }
    if (this.s[this.i] === 'e' || this.s[this.i] === 'E') {
      integerLiteral = false;
      this.i++;
      if (this.s[this.i] === '+' || this.s[this.i] === '-') this.i++;
      if (!isDigit(this.s[this.i])) throw new CoreError('json_bad_number');
      while (isDigit(this.s[this.i])) this.i++;
    }
    const token = this.s.slice(start, this.i);
    if (this.integersOnly) {
      if (integerLiteral) {
        if (token === '-0') throw new CoreError('number_spelling');
        const mag = BigInt(token.startsWith('-') ? token.slice(1) : token);
        if (mag > 9007199254740991n) throw new CoreError('number_not_safe_integer');
      } else {
        // an integer-valued number written with a fraction or an exponent (1.0, 4e0) is a spelling problem (GR-45);
        // a real fraction or a value beyond 2^53-1 is not a safe integer (GR-03)
        const v = Number(token);
        if (Number.isFinite(v) && Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER) throw new CoreError('number_spelling');
        throw new CoreError('number_not_safe_integer');
      }
    }
    return Number(token);
  }
}

/** Parses JSON text strictly; throws CoreError with a stable code. */
export function parseJson(text: string, opts: ParseOptions = {}): Json {
  if (typeof text !== 'string') throw new CoreError('json_not_text');
  return new Parser(text, opts.integersOnly === true, opts.maxDepth ?? MAX_DEPTH).parseTop();
}

function escapeString(s: string): string {
  if (hasLoneSurrogate(s)) throw new CoreError('lone_surrogate');
  let out = DQ;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 34) out += BS + DQ;
    else if (c === 92) out += BS + BS;
    else if (c === 8) out += BS + 'b';
    else if (c === 9) out += BS + 't';
    else if (c === 10) out += BS + 'n';
    else if (c === 12) out += BS + 'f';
    else if (c === 13) out += BS + 'r';
    else if (c < 0x20) out += BS + 'u' + c.toString(16).padStart(4, '0');
    else out += s[i]!;
  }
  return out + DQ;
}

function canon(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new CoreError('json_too_deep');
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new CoreError('number_not_finite');
      return String(v);
    case 'string':
      return escapeString(v);
    case 'undefined':
      throw new CoreError('undefined_value');
    case 'object':
      break;
    default:
      throw new CoreError('unsupported_type', typeof v);
  }
  if (Array.isArray(v)) {
    const parts: string[] = [];
    for (let i = 0; i < v.length; i++) {
      if (!(i in v)) throw new CoreError('unsupported_type', 'sparse array');
      parts.push(canon(v[i], depth + 1));
    }
    return '[' + parts.join(',') + ']';
  }
  if (!isPlainObject(v)) throw new CoreError('unsupported_type', 'object');
  if (Object.getOwnPropertySymbols(v).length > 0) throw new CoreError('unsupported_type', 'symbol key');
  const keys = Object.keys(v).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(v, k);
    if (d === undefined || !('value' in d)) throw new CoreError('unsupported_type', 'accessor');
    parts.push(escapeString(k) + ':' + canon(d.value, depth + 1));
  }
  return '{' + parts.join(',') + '}';
}

/** RFC 8785 text of an in-memory JSON value; throws CoreError for a value JSON cannot carry. */
export function canonicalize(value: unknown): string {
  return canon(value, 0);
}

export type CanonicalizeTextResult = { ok: true; canonical: string } | { ok: false; reason: string };

/** Parse then canonicalize, with a named refusal instead of a throw. */
export function canonicalizeText(text: string): CanonicalizeTextResult {
  try {
    return { ok: true, canonical: canonicalize(parseJson(text)) };
  } catch (e) {
    if (e instanceof CoreError) return { ok: false, reason: e.code };
    throw e;
  }
}
