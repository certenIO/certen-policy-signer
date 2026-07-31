/** Poller: periodically discover pending txs awaiting our signer, feed them to the orchestrator. */
import { AccumulateClient } from './accumulate/client.js';
import { Orchestrator } from './orchestrator.js';
import { metrics } from './metrics.js';
import { Logger } from './logger.js';

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
      const hashes = [...new Set([...viaPending, ...viaSigChain, ...viaGateway])];
      for (const txHash of hashes) {
        metrics.inc('wallet_pending_seen_total');
        await this.orch.handle({ txHash, signerUrl: this.signerUrl }).catch((e) =>
          this.logger.error({ tx: txHash, err: e.message }, 'poller handle failed'));
      }
      this.lastSuccessAt = this.now();
      if (this.consecutiveFailures) {
        this.logger.info({ afterFailures: this.consecutiveFailures }, 'poll cycle recovered');
      }
      this.consecutiveFailures = 0;
      metrics.gauge('wallet_poller_last_success_seconds', Math.floor(this.lastSuccessAt / 1000));
      this.logger.debug({ count: hashes.length }, 'poll cycle complete');
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
