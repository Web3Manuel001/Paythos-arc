"""
Token-bucket transport rate limiter (docs/PROTOCOL.md §5 / SECURITY INV-M6).
Applied at BOTH the merchant middleware boundary and the SDK outbound loop.
A runaway agent loop (e.g. 500 reqs / 2s) throttles locally BEFORE allowance burns.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: float


class TokenBucket:
    def __init__(
        self,
        capacity: int = 100,
        refill_per_second: float = 10.0,
        *,
        clock: "callable[[], float] | None" = None,
    ) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._tokens = float(capacity)
        self._clock = clock or time.monotonic
        self._last_refill_at = self._clock()

    def try_consume(self, cost: float = 1.0) -> RateLimitDecision:
        now = self._clock()
        elapsed = max(0.0, now - self._last_refill_at)
        self._tokens = min(
            float(self.capacity),
            self._tokens + elapsed * self.refill_per_second,
        )
        self._last_refill_at = now
        if self._tokens < cost:
            deficit = cost - self._tokens
            return RateLimitDecision(
                allowed=False,
                remaining=int(self._tokens),
                retry_after_seconds=deficit / self.refill_per_second,
            )
        self._tokens -= cost
        return RateLimitDecision(allowed=True, remaining=int(self._tokens), retry_after_seconds=0.0)
