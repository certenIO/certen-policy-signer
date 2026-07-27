/**
 * SR4 local value ceiling — defense-in-depth behind the policy engine.
 *
 * Exported (rather than an inline lambda in index.ts) so that the SHIPPED guard is the one under test.
 * A test that re-declares a copy of the expression proves only that the copy works.
 */

export interface GuardSubject {
  account?: string;
  summary?: string;
  value?: string;      // representative amount (leg 0)
  values?: string[];   // every leg amount
}

/**
 * Refuse to sign if ANY leg exceeds the ceiling — all-or-nothing, matching the policy engine's gate.
 * Checking only the representative (leg 0) value would let a multi-leg intent hide an over-ceiling
 * amount in a later leg. Compared as BigInt: at wei scale, Number() silently rounds
 * (Number('10000000000000000001') === Number('10000000000000000000')) and would wave it through.
 * An unparseable amount blocks (fail-closed); no amounts at all passes (the engine already gated it).
 */
export function makeValueCeilingGuard(ceiling: bigint): (t: GuardSubject) => boolean {
  return (t) => {
    const amounts = t.values?.length ? t.values : (t.value !== undefined ? [t.value] : []);
    if (!amounts.length) return true;
    return amounts.every((a) => {
      try {
        return BigInt(String(a).trim().split('.')[0]) <= ceiling;
      } catch {
        return false;
      }
    });
  };
}
