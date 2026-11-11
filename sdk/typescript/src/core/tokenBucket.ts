/**
 * Token-bucket transport rate limiter (docs/PROTOCOL.md §5 / SECURITY INV-M6).
 * Applied at BOTH the merchant middleware boundary and the SDK outbound loop.
 * A runaway agent loop (e.g. 500 reqs / 2s) throttles locally with HTTP 429
 * semantics BEFORE the allowance burns.
 */
export interface TokenBucketOptions {
  /** Max burst capacity (default 100). */
  capacity: number;
  /** Refill rate, tokens per second (default 10). */
  refillPerSecond: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  /** Seconds until the next token (present only when throttled). */
  retryAfterSeconds: number;
}

export class TokenBucket {
  private tokens: number;
  private lastRefillAt: number;

  constructor(
    private readonly options: TokenBucketOptions,
    private readonly now: () => number = () => Date.now(),
  ) {
    if (!Number.isFinite(options.capacity) || options.capacity < 1) {
      throw new RangeError(`token bucket capacity must be a number >= 1 (got ${String(options.capacity)})`);
    }
    if (!Number.isFinite(options.refillPerSecond) || options.refillPerSecond <= 0) {
      throw new RangeError(`token bucket refillPerSecond must be > 0 (got ${String(options.refillPerSecond)})`);
    }
    this.tokens = options.capacity;
    this.lastRefillAt = now();
  }

  tryConsume(cost: number = 1): RateLimitDecision {
    const t = this.now();
    const elapsed = Math.max(0, t - this.lastRefillAt);
    this.tokens = Math.min(this.options.capacity, this.tokens + (elapsed / 1000) * this.options.refillPerSecond);
    this.lastRefillAt = t;

    if (this.tokens < cost) {
      const deficit = cost - this.tokens;
      return {
        allowed: false,
        remaining: Math.floor(this.tokens),
        retryAfterSeconds: Math.ceil((deficit / this.options.refillPerSecond) * 1000) / 1000,
      };
    }
    this.tokens -= cost;
    return { allowed: true, remaining: Math.floor(this.tokens), retryAfterSeconds: 0 };
  }
}
