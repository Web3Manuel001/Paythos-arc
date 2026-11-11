"""
Transactability Index (docs/ARCHITECTURE.md Module 4.2, SECURITY.md §3).

Counterparty health scored from MEASURED service quality: uptime, response
validity, latency, 5xx rate. Vendors of pay-then-fail endpoints are downgraded
and eventually blocked (INV-M5's companion defense).

The registry is pluggable: the MVP ships an in-memory store; signed p2p
attestations and a decentralized registry land post-MVP (SECURITY.md §3).
Unknown merchants are ALLOWED by default — the Destination Allowlist is the
fail-closed boundary.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal, Optional, Protocol

TransactabilityVerdict = Literal["allow", "downgrade", "block"]


@dataclass(frozen=True)
class MerchantObservation:
    ok: bool
    latency_ms: int
    status: Optional[int] = None
    #: Response VALIDITY (attested metering / well-formed proof); None = no signal.
    valid: Optional[bool] = None
    at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class TransactabilityScore:
    merchant: str
    score: int
    verdict: TransactabilityVerdict
    uptime: float
    validity: float
    latency_ms: float
    error_rate_5xx: float
    samples: int
    source: Literal["local", "registry", "empty"]
    updated_at: float


@dataclass(frozen=True)
class TransactabilityAttestation:
    merchant: str
    score: int
    uptime: float
    validity: float
    latency_ms: float
    error_rate_5xx: float
    samples: int
    updated_at: float


class TransactabilityRegistry(Protocol):
    def lookup(self, merchant: str) -> Optional[TransactabilityAttestation]: ...

    def publish(self, attestation: TransactabilityAttestation) -> None: ...


class InMemoryTransactabilityRegistry:
    def __init__(self) -> None:
        self._attestations: dict[str, TransactabilityAttestation] = {}

    def lookup(self, merchant: str) -> Optional[TransactabilityAttestation]:
        return self._attestations.get(merchant.lower())

    def publish(self, attestation: TransactabilityAttestation) -> None:
        self._attestations[attestation.merchant.lower()] = attestation

    def snapshot(self) -> list[TransactabilityAttestation]:
        return list(self._attestations.values())


@dataclass
class TransactabilityConfig:
    window_size: int = 64
    latency_budget_ms: int = 2_000
    downgrade_below: int = 75
    block_below: int = 50
    validity_floor: float = 0.5
    min_samples: int = 4
    unknown_verdict: Literal["allow", "block"] = "allow"


DEFAULT_TRANSACTABILITY_CONFIG = TransactabilityConfig()


class TransactabilityIndex:
    """Oracle surface (``approve``) plus measured observations (``record``)."""

    def __init__(
        self,
        *,
        config: Optional[TransactabilityConfig] = None,
        registry: Optional[TransactabilityRegistry] = None,
    ) -> None:
        cfg = config or TransactabilityConfig()
        # Fail closed at construction: a zero-latency-budget or empty window
        # would silently disable the defence instead of raising.
        if cfg.window_size < 1:
            raise ValueError(f"transactability window_size must be >= 1 (got {cfg.window_size!r})")
        if cfg.latency_budget_ms <= 0:
            raise ValueError(f"transactability latency_budget_ms must be > 0 (got {cfg.latency_budget_ms!r})")
        if cfg.min_samples < 1:
            raise ValueError(f"transactability min_samples must be >= 1 (got {cfg.min_samples!r})")
        self._config = cfg
        self._registry = registry
        self._observations: dict[str, list[MerchantObservation]] = {}

    def approve(self, merchant: str) -> bool:
        """Block only on measured/published evidence (allowlist stays the boundary)."""
        return self.score(merchant).verdict != "block"

    __call__ = approve

    def record(
        self,
        merchant: str,
        observation: MerchantObservation,
    ) -> TransactabilityScore:
        key = merchant.lower()
        window = self._observations.setdefault(key, [])
        window.append(observation)
        if len(window) > self._config.window_size:
            del window[: len(window) - self._config.window_size]
        score = self._compute(key, window)
        if self._registry is not None:
            self._registry.publish(
                TransactabilityAttestation(
                    merchant=score.merchant,
                    score=score.score,
                    uptime=score.uptime,
                    validity=score.validity,
                    latency_ms=score.latency_ms,
                    error_rate_5xx=score.error_rate_5xx,
                    samples=score.samples,
                    updated_at=score.updated_at,
                )
            )
        return score

    def score(self, merchant: str) -> TransactabilityScore:
        key = merchant.lower()
        window = self._observations.get(key)
        if window:
            return self._compute(key, window)
        published = self._registry.lookup(key) if self._registry is not None else None
        if published is not None:
            return TransactabilityScore(
                merchant=key,
                score=published.score,
                verdict=self._verdict(published.score, published.validity, published.samples),
                uptime=published.uptime,
                validity=published.validity,
                latency_ms=published.latency_ms,
                error_rate_5xx=published.error_rate_5xx,
                samples=published.samples,
                source="registry",
                updated_at=published.updated_at,
            )
        return TransactabilityScore(
            merchant=key,
            score=100,
            verdict=self._config.unknown_verdict,
            uptime=1.0,
            validity=1.0,
            latency_ms=0.0,
            error_rate_5xx=0.0,
            samples=0,
            source="empty",
            updated_at=time.time(),
        )

    def snapshot(self) -> list[TransactabilityScore]:
        return [self.score(merchant) for merchant in self._observations]

    def _compute(self, merchant: str, window: list[MerchantObservation]) -> TransactabilityScore:
        total = len(window)
        ok_count = sum(1 for o in window if o.ok)
        valid_count = sum(1 for o in window if o.valid is not False)
        five_xx_count = sum(1 for o in window if o.status is not None and 500 <= o.status < 600)
        latency_avg = sum(max(0, o.latency_ms) for o in window) / total

        uptime = ok_count / total
        validity = valid_count / total
        error_rate_5xx = five_xx_count / total
        latency_score = _clamp01(1 - latency_avg / self._config.latency_budget_ms)
        score = round(100 * (0.35 * uptime + 0.35 * validity + 0.2 * latency_score + 0.1 * (1 - error_rate_5xx)))

        return TransactabilityScore(
            merchant=merchant,
            score=score,
            verdict=self._verdict(score, validity, total),
            uptime=uptime,
            validity=validity,
            latency_ms=round(latency_avg),
            error_rate_5xx=error_rate_5xx,
            samples=total,
            source="local",
            updated_at=window[-1].at,
        )

    def _verdict(self, score: int, validity: float, samples: int) -> TransactabilityVerdict:
        if score < self._config.block_below:
            return "block"
        if samples >= self._config.min_samples and validity < self._config.validity_floor:
            return "block"
        if score < self._config.downgrade_below:
            return "downgrade"
        return "allow"


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def is_transactability_index(oracle: object) -> bool:
    """Structural check: does this oracle accept observations?"""
    return oracle is not None and callable(getattr(oracle, "record", None))


__all__ = [
    "DEFAULT_TRANSACTABILITY_CONFIG",
    "InMemoryTransactabilityRegistry",
    "MerchantObservation",
    "TransactabilityAttestation",
    "TransactabilityConfig",
    "TransactabilityIndex",
    "TransactabilityRegistry",
    "TransactabilityScore",
    "TransactabilityVerdict",
    "is_transactability_index",
]
