/**
 * DAX-F148 (lead, DAX-4-A7 code read 2026-11-23): the Orchestrator's pause gate was optional ("absent = nothing is paused"), so a composition that
 * forgot to wire the persisted PauseStore would sign while its seat was paused: a latent fail-open, unchanged since the in-memory `isPaused?`. It is
 * now required by the type AND refused at construction (a JavaScript caller or a cast can still omit it). Fail-before: on signer main bc4bcf7 each
 * construction below succeeds.
 */
import { describe, expect, it } from 'vitest';
import { Orchestrator, type OrchestratorDeps } from '../src/orchestrator.js';
import { NO_PAUSES } from './support/no-pauses.js';

// Only the pause gate is under test: the constructor refuses before it reads anything else.
const without = (pauses: unknown): OrchestratorDeps => ({ pauses } as unknown as OrchestratorDeps);

describe('the Orchestrator requires a pause gate (DAX-F148)', () => {
  it('refuses to be built with no pause gate, a null one, or one with no check()', () => {
    for (const p of [undefined, null, {}, { check: 'yes' }]) {
      expect(() => new Orchestrator(without(p))).toThrow(/a pause gate is required/);
    }
  });
  it('a gate that says nothing is paused is accepted (the constructor goes on to its other checks)', () => {
    expect(() => new Orchestrator(without(NO_PAUSES))).not.toThrow(/a pause gate is required/);
  });
});
