/**
 * Durable fix for an accumulate.js@0.12 bug (applied via `postinstall`).
 *
 * accumulate.js encodes `time.Time` fields (TransactionHeader.expire/holdUntil) as an UNSIGNED varint of
 * fractional Unix seconds. Accumulate core encodes them as a SIGNED varint of whole Unix seconds
 * (`EncodeInt(v.UTC().Unix())`). The mismatch makes the header hash disagree with the network, so any tx
 * with `expire`/`holdUntil` fails at submission with "transaction is not signed" (and throws on fractional
 * seconds). This rewrites Time.encode to match core. Idempotent + safe (warns if upstream changed shape).
 *
 * The production wallet never builds such txs (it only signs votes), so this matters only to the e2e
 * harness that mints expiring txs — but it's a real upstream bug, fixed here rather than worked around.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const FILE = 'node_modules/accumulate.js/lib/encoding/encodable.js';
const BAD = 'return uintMarshalBinary(value.getTime() / 1000);';
const GOOD = 'return intMarshalBinary(Math.floor(value.getTime() / 1000)); // certen: signed varint + whole seconds (matches Accumulate core)';

if (!existsSync(FILE)) {
  console.warn(`[fix-accumulate-encoding] ${FILE} not found — skipping (accumulate.js not installed?)`);
  process.exit(0);
}
const src = readFileSync(FILE, 'utf8');
if (src.includes(BAD)) {
  writeFileSync(FILE, src.replace(BAD, GOOD));
  console.log('[fix-accumulate-encoding] patched Time.encode → signed varint + whole seconds');
} else if (src.includes('intMarshalBinary(Math.floor(value.getTime()')) {
  console.log('[fix-accumulate-encoding] already patched');
} else {
  console.warn('[fix-accumulate-encoding] WARNING: Time.encode not in the expected form; upstream may have changed — verify manually');
}
