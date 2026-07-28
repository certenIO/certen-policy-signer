/**
 * SR4 local value ceiling — defense-in-depth behind the policy engine.
 *
 * Exported (rather than an inline lambda in index.ts) so that the SHIPPED guard is the one under test.
 * A test that re-declares a copy of the expression proves only that the copy works.
 */

export interface GuardSubject {
  account?: string;
  summary?: string;
  value?: string;         // representative amount (leg 0)
  values?: string[];      // every leg amount the decoder could read
  unpricedLegs?: number;  // legs that move value but could not be priced — see below
}

/**
 * Refuse to sign if ANY leg exceeds the ceiling — all-or-nothing, matching the policy engine's gate.
 * Checking only the representative (leg 0) value would let a multi-leg intent hide an over-ceiling
 * amount in a later leg. Compared as BigInt: at wei scale, Number() silently rounds
 * (Number('10000000000000000001') === Number('10000000000000000000')) and would wave it through.
 * An unparseable amount blocks (fail-closed); no amounts at all passes (the engine already gated it).
 *
 * A leg the decoder could not price blocks for the same reason, and this is not the same case as "no
 * amounts at all": there, nothing claims to move value; here, `values` is a PARTIAL list and every entry
 * in it can sit under the ceiling while the leg missing from it does not. An amount we cannot read cannot
 * be shown to be within the limit, so it is refused rather than skipped.
 */
export function makeValueCeilingGuard(ceiling: bigint): (t: GuardSubject) => boolean {
  return (t) => {
    if ((t.unpricedLegs ?? 0) > 0) return false;
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
