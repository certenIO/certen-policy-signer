/** Minimal Prometheus-style metrics (SPEC §12). No external dep. */
export class Metrics {
  private counters = new Map<string, number>();
  private gauges = new Map<string, number>();

  inc(name: string, by = 1) { this.counters.set(name, (this.counters.get(name) ?? 0) + by); }
  gauge(name: string, v: number) { this.gauges.set(name, v); }

  render(): string {
    const lines: string[] = [];
    for (const [k, v] of this.counters) lines.push(`# TYPE ${base(k)} counter`, `${k} ${v}`);
    for (const [k, v] of this.gauges) lines.push(`# TYPE ${base(k)} gauge`, `${k} ${v}`);
    return lines.join('\n') + '\n';
  }
}
function base(k: string) { return k.split('{')[0]; }

export const metrics = new Metrics();
