/**
 * Seat ids. EVERY signing scope has a seat id (`seat:<name>`, the core's SEAT_RE): the one configured for it, or one derived
 * deterministically from the page URL, so that a seat pause can address any scope and a decision record can name it.
 */
import { createHash } from 'node:crypto';
import { SEAT_RE } from '../core/decision-identity.js';

export function derivedSeat(page: string): string {
  let name = page.toLowerCase().replace(/^acc:\/\//, '').replace(/[^a-z0-9._-]+/g, '-').replace(/^[^a-z0-9]+/, '').replace(/-+$/, '');
  if (name.length === 0) name = 'page';
  if (name.length > 62) name = `${name.slice(0, 49)}-${createHash('sha256').update(page.toLowerCase()).digest('hex').slice(0, 12)}`;
  const seat = `seat:${name}`;
  if (!SEAT_RE.test(seat)) throw new Error(`cannot derive a seat id from ${JSON.stringify(page)}: set \`seat\` on the scope`);
  return seat;
}

export const isSeat = (v: unknown): v is string => typeof v === 'string' && SEAT_RE.test(v);
