/**
 * A small, strict Solidity ABI calldata decoder. FICTIONAL Business Transaction Controls lab, Phase 6.1.
 *
 * Only the types the lab's pinned contracts use are supported: address, bool, uintN, intN, bytesN and the
 * dynamic `bytes` / `string`. A function whose inputs use anything else (arrays, tuples) is not decodable
 * and is left out of the selector table, so its calldata is reported as undecoded rather than guessed at.
 *
 * STRICT BY DESIGN: every padding byte must be zero, every dynamic offset must point inside the calldata
 * and the calldata must end exactly where the encoding ends. A lenient decode would let two different byte
 * strings read as the same call, and the decision is taken on the reading.
 */

/* ------------------------------------------------------------------ */
/* keccak-256 (Ethereum's pre-standard Keccak, pad 0x01)               */
/* ------------------------------------------------------------------ */

const MASK = (1n << 64n) - 1n;
const RC: bigint[] = (() => {
  const out: bigint[] = [];
  let r = 1;
  for (let i = 0; i < 24; i++) {
    let c = 0n;
    for (let j = 0; j < 7; j++) {
      r = ((r << 1) ^ ((r >> 7) * 0x71)) & 0xff;
      if (r & 2) c ^= 1n << ((1n << BigInt(j)) - 1n);
    }
    out.push(c);
  }
  return out;
})();
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const rotl = (x: bigint, n: number) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK);

function keccakF(s: bigint[]) {
  for (let round = 0; round < 24; round++) {
    const c = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) s[y + x] ^= d;
    }
    const b = new Array<bigint>(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + ((2 * x + 3 * y) % 5) * 5] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
    for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) s[y + x] = b[y + x] ^ (~b[y + ((x + 1) % 5)] & MASK & b[y + ((x + 2) % 5)]);
    s[0] ^= RC[round];
  }
}

/** keccak-256 of bytes (or a UTF-8 string), as lowercase hex without 0x. */
export function keccak256Hex(input: Uint8Array | string): string {
  const data = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  const rate = 136;
  const padded = new Uint8Array(Math.floor(data.length / rate) * rate + rate);
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Array<bigint>(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let w = 0n;
      for (let k = 7; k >= 0; k--) w = (w << 8n) | BigInt(padded[off + i * 8 + k]);
      s[i] ^= w;
    }
    keccakF(s);
  }
  let hex = '';
  for (let i = 0; i < 4; i++) for (let k = 0; k < 8; k++) hex += Number((s[i] >> BigInt(8 * k)) & 0xffn).toString(16).padStart(2, '0');
  return hex;
}

/* ------------------------------------------------------------------ */
/* ABI                                                                  */
/* ------------------------------------------------------------------ */

export interface AbiParam { name?: string; type: string }
export interface AbiFunction { name: string; signature: string; selector: string; inputs: Array<{ name: string; type: string }> }

const TYPE_RE = /^(address|bool|string|bytes([1-9]|[12][0-9]|3[0-2])?|u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?)$/;

/** Canonical ABI type (`uint` → `uint256`), or undefined when unsupported. */
function canonicalType(t: unknown): string | undefined {
  if (typeof t !== 'string' || !TYPE_RE.test(t)) return undefined;
  if (t === 'uint') return 'uint256';
  if (t === 'int') return 'int256';
  return t;
}

/**
 * Build the selector table for a JSON ABI. Accepts a bare ABI array or a build artifact with `.abi`.
 * Functions using an unsupported input type are skipped (their calldata reads as undecoded).
 */
export function buildSelectorTable(abi: unknown): Map<string, AbiFunction> {
  const list = Array.isArray(abi) ? abi : Array.isArray((abi as { abi?: unknown })?.abi) ? (abi as { abi: unknown[] }).abi : undefined;
  if (!list) throw new Error('ABI must be a JSON array (or an artifact with an `abi` array)');
  const out = new Map<string, AbiFunction>();
  for (const e of list as Array<Record<string, unknown>>) {
    if (!e || e.type !== 'function' || typeof e.name !== 'string') continue;
    const raw = Array.isArray(e.inputs) ? (e.inputs as AbiParam[]) : [];
    const types = raw.map((p) => canonicalType(p?.type));
    if (types.some((t) => t === undefined)) continue;
    const signature = `${e.name}(${types.join(',')})`;
    const selector = keccak256Hex(signature).slice(0, 8);
    out.set(selector, {
      name: e.name, signature, selector,
      inputs: raw.map((p, i) => ({ name: typeof p?.name === 'string' && p.name ? p.name : `arg${i}`, type: types[i]! })),
    });
  }
  return out;
}

export interface DecodedCall { fn: AbiFunction; args: Record<string, string> }

/**
 * Decode calldata against a selector table. Returns undefined for an unknown selector or any encoding that
 * is not canonical. Integers are decimal strings; address/bytesN/bytes are lowercase 0x hex; string is text.
 */
export function decodeCalldata(table: Map<string, AbiFunction>, callData: unknown): DecodedCall | undefined {
  if (typeof callData !== 'string') return undefined;
  const hex = (callData.startsWith('0x') ? callData.slice(2) : callData).toLowerCase();
  if (hex.length < 8 || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return undefined;
  const fn = table.get(hex.slice(0, 8));
  if (!fn) return undefined;
  const body = Buffer.from(hex.slice(8), 'hex');
  if (body.length % 32 !== 0 || body.length < fn.inputs.length * 32) return undefined;

  const word = (off: number) => body.subarray(off, off + 32);
  const zero = (b: Uint8Array) => b.every((x) => x === 0);
  let end = fn.inputs.length * 32;
  const args: Record<string, string> = {};

  for (let i = 0; i < fn.inputs.length; i++) {
    const { name, type } = fn.inputs[i];
    const w = word(i * 32);
    let v: string;
    if (type === 'address') {
      if (!zero(w.subarray(0, 12))) return undefined;
      v = '0x' + Buffer.from(w.subarray(12)).toString('hex');
    } else if (type === 'bool') {
      if (!zero(w.subarray(0, 31)) || w[31] > 1) return undefined;
      v = w[31] === 1 ? 'true' : 'false';
    } else if (/^uint/.test(type)) {
      const bits = Number(type.slice(4) || 256);
      const n = BigInt('0x' + Buffer.from(w).toString('hex'));
      if (n >> BigInt(bits) !== 0n) return undefined;
      v = n.toString();
    } else if (/^int/.test(type)) {
      const bits = Number(type.slice(3) || 256);
      let n = BigInt('0x' + Buffer.from(w).toString('hex'));
      if (n >> 255n) n -= 1n << 256n;
      if (n >= 1n << BigInt(bits - 1) || n < -(1n << BigInt(bits - 1))) return undefined;
      v = n.toString();
    } else if (/^bytes\d+$/.test(type)) {
      const len = Number(type.slice(5));
      if (!zero(w.subarray(len))) return undefined;
      v = '0x' + Buffer.from(w.subarray(0, len)).toString('hex');
    } else {
      // bytes | string: head holds the offset of a length-prefixed, zero-padded tail.
      const offBig = BigInt('0x' + Buffer.from(w).toString('hex'));
      // A tail offset must point past the head (canonical encoding); pointing into the head lets two different
      // byte strings decode as the same call.
      if (offBig % 32n !== 0n || offBig < BigInt(fn.inputs.length * 32) || offBig + 32n > BigInt(body.length)) return undefined;
      const off = Number(offBig);
      const lenBig = BigInt('0x' + Buffer.from(word(off)).toString('hex'));
      const padded = Number(((lenBig + 31n) / 32n) * 32n);
      if (lenBig > BigInt(body.length) || off + 32 + padded > body.length) return undefined;
      const len = Number(lenBig);
      const data = body.subarray(off + 32, off + 32 + len);
      if (!zero(body.subarray(off + 32 + len, off + 32 + padded))) return undefined;
      if (type === 'string') {
        const s = Buffer.from(data).toString('utf8');
        if (!Buffer.from(s, 'utf8').equals(Buffer.from(data))) return undefined;
        v = s;
      } else v = '0x' + Buffer.from(data).toString('hex');
      end = Math.max(end, off + 32 + padded);
    }
    args[name] = v;
  }
  // Nothing may trail the encoding.
  if (end !== body.length) return undefined;
  return { fn, args };
}
