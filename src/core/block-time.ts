/**
 * The chain time of a data entry on Accumulate v3 (DAX-3A live finding R5-1).
 *
 * A real v3 data entry record carries no timestamp. It carries `value.received`, the index of the MINOR BLOCK that executed the entry. The chain
 * time of the entry is the `time` of that block, read with `query` on the account scope and `{queryType:'block', minor: <received>}` (the network
 * resolves the partition from the account). The signature timestamp is chosen by the signer and is NOT chain time; `lastBlockTime` is not on a
 * data entry record. A reader binding to Kermit uses these two functions and nothing else to fill `DataEntry.time`.
 *
 * Pure: no clock, no I/O. A block that is not exactly the block asked for, or a time that is not an exact UTC RFC 3339 instant, yields undefined
 * (the entry then has no time and every verdict that needs one refuses by name).
 */

const isDigits = (s: string): boolean => s.length > 0 && [...s].every((c) => c >= '0' && c <= '9');

const isLeap = (y: number): boolean => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const daysIn = (y: number, m: number): number => (m === 2 && isLeap(y) ? 29 : (DAYS[m - 1] as number));

/** days since 1970-01-01 of a proleptic Gregorian date (the civil-from-days inverse, integer arithmetic only) */
function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const mp = (m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

/** 'YYYY-MM-DDTHH:MM:SS' with an optional '.' and 1 to 9 fraction digits, then 'Z'; whole Unix seconds (fraction floored), or undefined */
function utcSeconds(t: unknown): number | undefined {
  if (typeof t !== 'string' || !t.endsWith('Z')) return undefined;
  const body = t.slice(0, -1);
  if (body.length < 19 || body.charAt(4) !== '-' || body.charAt(7) !== '-' || body.charAt(10) !== 'T' || body.charAt(13) !== ':' || body.charAt(16) !== ':') return undefined;
  const parts = [body.slice(0, 4), body.slice(5, 7), body.slice(8, 10), body.slice(11, 13), body.slice(14, 16), body.slice(17, 19)];
  if (!parts.every(isDigits)) return undefined;
  if (body.length > 19) {
    const frac = body.slice(20);
    if (body.charAt(19) !== '.' || !isDigits(frac) || frac.length > 9) return undefined;
  }
  const [y, mo, d, h, mi, s] = parts.map((p) => Number(p)) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || s > 59) return undefined;
  const seconds = daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
  return seconds >= 0 ? seconds : undefined;
}

/** the index of the minor block that executed the entry (`value.received` of a v3 data or chain record), or undefined */
export function entryBlockIndex(record: unknown): number | undefined {
  if (typeof record !== 'object' || record === null) return undefined;
  const value = (record as { value?: unknown }).value;
  if (typeof value !== 'object' || value === null) return undefined;
  const received = (value as { received?: unknown }).received;
  return typeof received === 'number' && Number.isSafeInteger(received) && received > 0 ? received : undefined;
}

/** the chain time, Unix seconds, from the minor block record answering `{queryType:'block', minor: expectedIndex}`; undefined for any other block */
export function minorBlockTime(block: unknown, expectedIndex: number): number | undefined {
  if (!Number.isSafeInteger(expectedIndex) || expectedIndex <= 0) return undefined;
  if (typeof block !== 'object' || block === null) return undefined;
  const b = block as { recordType?: unknown; index?: unknown; time?: unknown };
  if (b.recordType !== 'minorBlock' || b.index !== expectedIndex) return undefined;
  return utcSeconds(b.time);
}
