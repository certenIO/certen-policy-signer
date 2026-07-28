/** Minimal Prometheus-style metrics, served on /metrics. No external dep. */
export class Metrics {
  private counters = new Map<string, number>();
  private gauges = new Map<string, number>();

  inc(name: string, by = 1) { this.counters.set(name, (this.counters.get(name) ?? 0) + by); }
  gauge(name: string, v: number) { this.gauges.set(name, v); }

  /**
   * Render the exposition format.
   *
   * Series are grouped by metric FAMILY (the name without its labels) and each family gets exactly one
   * `# TYPE` line. Emitting one per series looked fine while every counter had a single label set, but
   * the moment a second appeared — a `wallet_errors_total{stage="submit"}` beside the existing
   * `{stage="poller"}` — the duplicate TYPE line makes Prometheus reject the whole scrape, taking every
   * other metric down with it. The failure would arrive with an unrelated change, long after this code.
   */
  render(): string {
    const lines: string[] = [];
    for (const [type, series] of [['counter', this.counters], ['gauge', this.gauges]] as const) {
      const families = new Map<string, string[]>();
      for (const [k, v] of series) {
        const f = base(k);
        const rows = families.get(f) ?? [];
        rows.push(`${k} ${v}`);
        families.set(f, rows);
      }
      // A family's series must also be contiguous, which grouping gives us for free.
      for (const [f, rows] of families) lines.push(`# TYPE ${f} ${type}`, ...rows);
    }
    return lines.join('\n') + '\n';
  }
}
function base(k: string) { return k.split('{')[0]; }

export const metrics = new Metrics();
