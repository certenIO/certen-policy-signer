/**
 * The entries of a data account are the WriteData transactions of its MAIN chain (DAX-3A live finding R5-2).
 *
 * The `data` chain query resolves a data-chain index to a transaction through the entry hash, so two entries with identical bytes (an acceptance
 * written, revoked and written again) come back as the same, later transaction: the first one is then dated by the second one's block. The main
 * chain lists every WriteData as a transaction of its own with its own executing block (`value.received`, see block-time.ts). A reader binding
 * to Kermit therefore reads the main chain (the records that also give the account history), passes each record here and takes the
 * entries in chain order.
 *
 * Pure: no clock, no I/O. A record that cannot be read exactly is reported as malformed so that the reader treats the whole account as
 * unreadable; it is never skipped and never turned into an empty entry. A WriteData that is not delivered (`value.status`) is malformed too
 * (entry_not_delivered): the signer, the Console and chain-check all refuse it through this one function (DAX4S-F26).
 */
import { fromHex } from './bytes.js';

export type MainChainEntry =
  | { kind: 'entry'; txId: string; elements: Uint8Array[] }
  | { kind: 'other'; type: string }
  | { kind: 'malformed'; reason: string };

const obj = (v: unknown): Record<string, unknown> | null => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

export function mainChainEntryOf(record: unknown): MainChainEntry {
  const value = obj(obj(record)?.['value']);
  if (value === null) return { kind: 'malformed', reason: 'record_value_missing' };
  const message = obj(value['message']);
  if (message === null || message['type'] !== 'transaction') return { kind: 'malformed', reason: 'record_not_a_transaction' };
  const body = obj(obj(message['transaction'])?.['body']);
  if (body === null || typeof body['type'] !== 'string') return { kind: 'malformed', reason: 'transaction_body_missing' };
  if (body['type'] !== 'writeData') return { kind: 'other', type: body['type'] };
  // GR-67: a WriteData whose delivery status is not exactly 'delivered' is not an entry; it makes the account unreadable (never a shorter list)
  if (value['status'] !== 'delivered') return { kind: 'malformed', reason: 'entry_not_delivered' };
  const txId = value['id'];
  if (typeof txId !== 'string' || !txId.startsWith('acc://')) return { kind: 'malformed', reason: 'transaction_id_missing' };
  const data = obj(body['entry'])?.['data'];
  if (!Array.isArray(data)) return { kind: 'malformed', reason: 'entry_data_missing' };
  const elements: Uint8Array[] = [];
  for (const item of data) {
    if (typeof item !== 'string') return { kind: 'malformed', reason: 'entry_item_not_hex' };
    try {
      elements.push(fromHex(item));
    } catch {
      return { kind: 'malformed', reason: 'entry_item_not_hex' };
    }
  }
  return { kind: 'entry', txId, elements };
}
