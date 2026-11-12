/**
 * The ONE place that says where the signer's copy of the shared core comes from (MOD-03, DAX-4-A10).
 *
 * The core is canonical in transaction-controls, packages/core. The signer consumes a byte-for-byte COPY, never a
 * retype or a fork. To move the copy to a newer core: change CORE_SOURCE_COMMIT below to a commit that exists in
 * transaction-controls, then run, in this order,
 *
 *     node scripts/sync-core.mjs                     (copies and rewrites src/core/SOURCE.json)
 *     npx vitest run test/core-drift.test.ts         (proves the copy, the manifest and the constant agree)
 *
 * Nothing else names the commit: scripts/sync-core.mjs and test/core-drift.test.ts both import this file.
 */
export const CORE_SOURCE_COMMIT = '54c70696c49a4e30cb3096cace8dc571bdfb0f40';
/** the directory of the canonical files inside transaction-controls */
export const CORE_SOURCE_DIR = 'packages/core/src';
/** the folder of the copies, relative to the signer repository root */
export const CORE_COPY_DIR = 'src/core';
/** the manifest of the copy: the commit and the sha256 of every copied file */
export const CORE_MANIFEST = 'src/core/SOURCE.json';
/**
 * Every file copied verbatim: the import closure of decision-binding, pause, log and reader. Nothing in the closure is
 * edited; the signer's own code lives outside src/core and imports it.
 */
export const CORE_FILES = [
  'bytes.ts',
  'jcs.ts',
  'grant-profile.ts',
  'registry-profile.ts',
  'hashes.ts',
  'envelope.ts',
  'grant.ts',
  'registry.ts',
  'reader.ts',
  'log.ts',
  'decision-identity.ts',
  'decision-binding.ts',
  'pause.ts',
];
