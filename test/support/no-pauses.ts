/**
 * DAX-F148: the Orchestrator requires a pause gate. A test that is not about pausing passes this one, which says explicitly that nothing is paused
 * (the production composition, src/index.ts, always passes the persisted PauseStore).
 */
import type { PauseGate } from '../../src/binding/pause-store.js';

export const NO_PAUSES: PauseGate = { check: () => ({ ok: true }) };
