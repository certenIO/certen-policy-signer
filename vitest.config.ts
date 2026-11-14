import { defineConfig } from 'vitest/config';

// The default 5 s test timeout is shorter than the cold import of a heavy module (the AWS SDK, the HTTP server) on a loaded host: a test that
// passes alone then times out inside the whole suite (DAX-F91, seen 2026-11-14 on test/cloud-kms-aws-ed25519, phase7-officer-intake and
// round6-config-admin). The bound is raised, never removed: a test that really hangs still fails after 30 s.
export default defineConfig({ test: { testTimeout: 30_000, hookTimeout: 30_000 } });
