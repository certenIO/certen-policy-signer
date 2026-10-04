/** Poller: periodically discover pending txs awaiting our signer, feed them to the orchestrator. */
import { AccumulateClient } from './accumulate/client.js';
import { Orchestrator } from './orchestrator.js';
import { metrics } from './metrics.js';
import { Logger } from './logger.js';
import { WrapperRegistry } from './registry/wrappers.js';
import { PendingRef } from './types.js';

/**
 * Wrapper discovery (wrapper runbook, change 1): read every enrolled wrapper book's pending list.
 *
 * In the wrapper model this is where the work is. Our own page and book are always empty for a delegate
 * — no signature request reaches a delegate, and the vote routes to the wrapper's book — so finding
 * nothing there is the normal state, not a fault, and is not logged as one.
 */
export interface WrapperSource {
  registry: WrapperRegistry;
  /** How many wrapper books are queried at once. */
  concurrency: number;
}

const MAX_BACKOFF_MULTIPLIER = 8;

export class Poller {
  private timer?: NodeJS.Timeout;
  private running = false;
  private stopped = false;
  private lastSuccessAt = 0;
  private consecutiveFailures = 0;
  private readonly startedAt: number;

  constructor(
    private readonly acc: AccumulateClient,
    private readonly orch: Orchestrator,
    private readonly signerUrl: string,
    private readonly intervalMs: number,
    private readonly logger: Logger,
    private readonly now: () => number = Date.now,
    /**
     * Optional extra discovery source — the Certen api-gateway's pending list.
     * It is a SUPPLEMENT, never a replacement: the gateway's own discovery is anchored on accounts the org
     * owns, so it does not reliably surface transactions where the org is merely a per-tx
     * `Header.Authorities` entry. Those are exactly our case, and we find them on the signature chain.
     */
    private readonly extraSource?: () => Promise<string[]>,
    /** The key BOOK to scan for signature requests. Defaults to the signer page's parent book. Multi-scope
     * passes it explicitly so a page under a non-standard book name is still scanned correctly. */
    private readonly bookUrl?: string,
    private readonly wrapperSource?: WrapperSource,
  ) {
    this.startedAt = this.now();   // must use the injected clock, not the wall clock
  }

  start() {
    this.stopped = false;
    void this.schedule(0);
  }
  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }

  lastSuccess(): number { return this.lastSuccessAt; }

  /** Which page this poller watches — so health can name the stalled scope instead of just counting one. */
  page(): string { return this.signerUrl; }

  /**
   * Healthy = we have polled successfully recently. A poller that has NEVER succeeded is unhealthy once
   * it has had a fair chance to (previously `lastSuccess === 0` was treated as healthy forever, so a
   * wallet that could not reach Accumulate at all still reported 200 while signing nothing).
   */
  healthy(): boolean {
    const stale = this.intervalMs * 3;
    if (this.lastSuccessAt === 0) return this.now() - this.startedAt < stale; // grace period at boot
    return this.now() - this.lastSuccessAt < stale;
  }

  /** The parent key book of a signer page URL: acc://o.acme/book/1 -> acc://o.acme/book */
  private bookOf(signerUrl: string): string {
    return signerUrl.replace(/\/\d+$/, '');
  }

  /**
   * One pass over the registry: each wrapper book's pending list, at most `concurrency` at a time. Read
   * fresh every cycle, so a wrapper enrolled since the last cycle is polled now, with no restart.
   *
   * One wrapper's failed query is counted and logged and does not fail the cycle: the other wrappers'
   * work is just as real, and their subscribers should not wait on someone else's node error. A failure
   * to read the REGISTRY itself does fail the cycle (the poller backs off), because then we cannot say
   * which wrappers we serve at all.
   */
  private async pollWrappers(src: WrapperSource): Promise<PendingRef[]> {
    const wrappers = await src.registry.list();
    const out: PendingRef[] = [];
    let failures = 0;
    let next = 0;
    const worker = async () => {
      while (next < wrappers.length) {
        const w = wrappers[next++]!;
        try {
          for (const p of await this.acc.listPendingForAccount(w.wrapperBook)) {
            if (!p.txHash || !p.principal) continue;
            out.push({ txHash: p.txHash, signerUrl: this.signerUrl, principal: p.principal, wrapperBook: w.wrapperBook });
          }
        } catch (e) {
          failures++;
          this.logger.warn({ wrapper: w.wrapperBook, err: (e as Error).message }, 'could not read a wrapper book pending list; the others continue');
        }
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(src.concurrency, wrappers.length)) }, worker));
    metrics.inc('wallet_wrappers_polled_total', wrappers.length);
    metrics.inc('wallet_wrapper_hits_total', out.length);
    if (failures) metrics.inc('wallet_wrapper_poll_failures_total', failures);
    metrics.gauge('wallet_wrappers_enrolled', wrappers.length);
    return out;
  }

  /** Re-arm after each cycle, backing off while Accumulate is unreachable rather than hammering it. */
  private schedule(delayMs: number) {
    if (this.stopped) return;
    this.timer = setTimeout(async () => {
      await this.tick();
      const backoff = Math.min(2 ** this.consecutiveFailures, MAX_BACKOFF_MULTIPLIER);
      this.schedule(this.intervalMs * (this.consecutiveFailures ? backoff : 1));
    }, delayMs);
    this.timer.unref?.();
  }

  private async tick() {
    if (this.running) return;
    this.running = true;
    try {
      // Phase 1/2: the signer page's on-chain Pending() index.
      // Phase 3: the book's signature chain — catches txs where we are an additional (header) authority,
      //          which Baikonur does NOT write to any Pending() index. Dedup across both.
      const book = this.bookUrl ?? this.bookOf(this.signerUrl);
      const [viaPending, viaSigChain, viaGateway] = await Promise.all([
        this.acc.listPendingForSigner(this.signerUrl),
        this.acc.listPendingViaSignatureChain(book),
        this.extraSource ? this.extraSource().catch((e) => {
          // The gateway being down must not stop us finding work on chain.
          this.logger.warn({ err: (e as Error).message }, 'gateway discovery failed; continuing with on-chain discovery');
          return [] as string[];
        }) : Promise.resolve([] as string[]),
      ]);
      const viaWrappers = this.wrapperSource ? await this.pollWrappers(this.wrapperSource) : [];
      const hashes = [...new Set([...viaPending, ...viaSigChain, ...viaGateway])];
      const refs: PendingRef[] = [
        ...viaWrappers,
        // A hash a wrapper already surfaced is handled through that wrapper's ref, which knows where to read.
        ...hashes.filter((h) => !viaWrappers.some((w) => w.txHash === h)).map((txHash) => ({ txHash, signerUrl: this.signerUrl })),
      ];
      for (const ref of refs) {
        metrics.inc('wallet_pending_seen_total');
        await this.orch.handleAll(ref).catch((e) =>
          this.logger.error({ tx: ref.txHash, err: e.message }, 'poller handle failed'));
      }
      this.lastSuccessAt = this.now();
      if (this.consecutiveFailures) {
        this.logger.info({ afterFailures: this.consecutiveFailures }, 'poll cycle recovered');
      }
      this.consecutiveFailures = 0;
      metrics.gauge('wallet_poller_last_success_seconds', Math.floor(this.lastSuccessAt / 1000));
      this.logger.debug({ count: refs.length, viaWrappers: viaWrappers.length }, 'poll cycle complete');
    } catch (e) {
      this.consecutiveFailures++;
      metrics.inc('wallet_errors_total{stage="poller"}');
      this.logger.warn(
        { err: (e as Error).message, consecutiveFailures: this.consecutiveFailures },
        'poll cycle failed; backing off',
      );
    } finally {
      this.running = false;
    }
  }
}
