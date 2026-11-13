"""
Hold ledger for ``upto`` streaming (docs/PROTOCOL.md §4.2). A hold is an
INTERNAL budget authorization — never a voucher. The ceiling is locked when
the stream opens and released on failure/break (YOPO, INV-M5); settlement
converts exactly the attested consumption into the signed cumulative voucher.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal, Optional

from eth_utils import keccak

HoldState = Literal["active", "settled", "released"]


@dataclass
class HoldEntry:
    stream_id: str
    merchant: str
    #: Locked ceiling in micro-USDC (NOT a claimable amount).
    ceiling_micro: int
    #: Settled consumption in micro-USDC (0 while active/released).
    settled_micro: int = 0
    state: HoldState = "active"
    created_at: float = field(default_factory=time.time)
    settled_at: Optional[float] = None
    released_at: Optional[float] = None


def stream_id_for(url: str, prompt: str, timestamp_ms: int) -> str:
    """Deterministic client-side stream id."""
    return keccak(text=f"{url}|{prompt}|{timestamp_ms}").hex()


class HoldLedger:
    """Locks are internal: active ceilings count against the rolling budget."""

    def __init__(self) -> None:
        self._holds: dict[str, HoldEntry] = {}

    def lock(self, stream_id: str, merchant: str, ceiling_micro: int) -> HoldEntry:
        if ceiling_micro <= 0:
            raise ValueError("hold ceiling must be positive")
        existing = self._holds.get(stream_id)
        if existing is not None:
            raise ValueError(f"hold {stream_id[:10]}… already {existing.state}")
        entry = HoldEntry(
            stream_id=stream_id,
            merchant=merchant.lower(),
            ceiling_micro=ceiling_micro,
        )
        self._holds[stream_id] = entry
        return entry

    def release(self, stream_id: str) -> None:
        entry = self._require(stream_id)
        if entry.state != "active":
            return  # idempotent
        entry.state = "released"
        entry.released_at = time.time()

    def settle(self, stream_id: str, consumed_micro: int) -> None:
        entry = self._require(stream_id)
        if entry.state != "active":
            raise ValueError(f"hold {stream_id[:10]}… already {entry.state}")
        if consumed_micro <= 0:
            self.release(stream_id)
            raise ValueError("consumed must be positive — zero-rendered streams release unpaid (YOPO)")
        if consumed_micro > entry.ceiling_micro:
            self.release(stream_id)
            raise ValueError(f"consumed {consumed_micro} exceeds locked ceiling {entry.ceiling_micro}")
        entry.state = "settled"
        entry.settled_micro = consumed_micro
        entry.settled_at = time.time()

    def sweep_expired(self, ttl_seconds: float, now: float | None = None) -> list[HoldEntry]:
        """Release ACTIVE holds older than ``ttl_seconds`` (abandoned streams).

        Holds are budget reservations, not vouchers; without a TTL a stream
        whose client never returns would pin allowance forever (reviewer 2026-11).
        """
        if ttl_seconds <= 0:
            raise ValueError("hold TTL must be > 0")
        current = time.time() if now is None else now
        released: list[HoldEntry] = []
        for hold in self._holds.values():
            if hold.state != "active":
                continue
            if current - hold.created_at >= ttl_seconds:
                hold.state = "released"
                hold.released_at = current
                released.append(hold)
        return released

    def get(self, stream_id: str) -> HoldEntry | None:
        return self._holds.get(stream_id)

    def active_hold_micro(self, merchant: str | None = None) -> int:
        total = 0
        for hold in self._holds.values():
            if hold.state != "active":
                continue
            if merchant is not None and hold.merchant != merchant.lower():
                continue
            total += hold.ceiling_micro
        return total

    def snapshot(self) -> list[HoldEntry]:
        return list(self._holds.values())

    def _require(self, stream_id: str) -> HoldEntry:
        entry = self._holds.get(stream_id)
        if entry is None:
            raise ValueError(f"unknown hold {stream_id[:10]}…")
        return entry


__all__ = ["HoldEntry", "HoldLedger", "HoldState", "stream_id_for"]
