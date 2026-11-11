"""
Merchant membranes (docs/ARCHITECTURE.md Module 2 + 3).
Framework-agnostic core: ``VoucherAccumulator`` verifies in memory (INV-M1),
accumulates strictly-increasing vouchers (INV-M2), enforces the credit wall
(INV-M4) against UNSETTLED exposure and surfaces flush plans.
Accepts BOTH wire formats (REV-5): the x402 v2 ``PAYMENT-SIGNATURE`` JSON
envelope and the native ``x-paythos-voucher``/``x-paythos-signature`` pair.
FastAPI middleware is a thin adapter that refuses unpriced traffic with a
402 challenge when ``challenge_for`` is configured (REV-4).
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Mapping

from pydantic import BaseModel, ConfigDict

from .rate_limit import TokenBucket
from .signer import SigningDomainArgs, domain_for, recover_voucher_signer
from .types import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    X_PAYTHOS_SIGNATURE_HEADER,
    X_PAYTHOS_VOUCHER_HEADER,
    PaymentChallenge,
    PaythosNetwork,
    Voucher,
)

FlushCallback = Callable[["FlushPlan"], Awaitable[None]]


class MerchantChallengeContext(BaseModel):
    """Everything a challenge factory may need to price the resource."""

    model_config = ConfigDict(frozen=True)

    method: str
    url: str


@dataclass(frozen=True)
class MerchantVerifierConfig:
    network: PaythosNetwork
    vault_address: str
    #: The vault's immutable settlement token (Arc native-USDC precompile).
    settlement_token: str
    #: ACTIVE delegation epochs per agentKey (lowercase ⇒ epoch, INV-6).
    authorized_agents: Mapping[str, int]
    #: x402 challenge factory (PROTOCOL.md §3.1). Requests WITHOUT payment
    #: headers get a 402 PAYMENT-REQUIRED challenge instead of a free pass.
    challenge_for: Callable[[MerchantChallengeContext], PaymentChallenge] | None = None
    #: Merchant credit-line ceiling in micro-USDC (INV-M4; docs default $2.00).
    credit_tolerance_micro: int = 2_000_000
    #: Value flush threshold in micro-USDC ($5.00 default, docs/PROTOCOL.md §6).
    flush_threshold_micro: int = 5_000_000
    #: Age-based flush trigger: unsettled > 0 for ≥ N seconds (2h default).
    flush_interval_seconds: int = 7_200
    on_flush_ready: FlushCallback | None = None
    rate_limit: tuple[int, float] = (100, 10.0)


@dataclass(frozen=True)
class FlushPlan:
    agent_key: str
    merchant: str
    voucher: Voucher  # the HIGHEST unclaimed voucher (INV-M2)
    #: EIP-712 signature for exactly this voucher — required by claimVoucher.
    signature: str


@dataclass(frozen=True)
class VerifyOutcome:
    ok: bool
    status: int
    reason: str = ""
    agent_key: str = ""
    unsettled_micro: int = 0
    #: Seconds until the next token (present only on 429 throttles).
    retry_after_seconds: float | None = None


class VoucherAccumulator:
    """Merchant-side session ledger: agentKey → highest voucher (INV-M2)."""

    def __init__(self, config: MerchantVerifierConfig) -> None:
        self.cfg = config
        self._highest: dict[str, tuple[Voucher, str]] = {}
        # Settled cumulative per agent — the daemon reports it post-confirmation.
        self._settled: dict[str, int] = {}
        # Last activity per agent (voucher accepted or settlement confirmed).
        self._last_activity_at: dict[str, int] = {}
        self._domain = domain_for(
            SigningDomainArgs(network=config.network, vault_address=config.vault_address)
        )
        self._buckets: dict[str, TokenBucket] = {}
        # Fail closed at construction: invalid limiter config must not surface
        # as a runtime 500 under attack.
        capacity, refill = config.rate_limit
        if not isinstance(capacity, int) or capacity < 1:
            raise ValueError(f"rate_limit capacity must be an int >= 1 (got {capacity!r})")
        if refill <= 0:
            raise ValueError(f"rate_limit refill must be > 0 (got {refill!r})")

    @property
    def domain(self) -> dict[str, object]:
        return dict(self._domain)

    def emit_challenge(self, challenge: PaymentChallenge) -> dict[str, str]:
        """Merchant-side challenge emission (docs/PROTOCOL.md §3.1)."""
        payload = challenge.model_dump(by_alias=True, exclude_none=True)
        # camelCase wire keys are protocol-mandated; pydantic aliases map snake→camel.
        encoded = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return {PAYMENT_REQUIRED_HEADER: encoded}

    def verify_payment(self, headers: Mapping[str, str]) -> VerifyOutcome:
        """
        Verify an inbound voucher in memory. No chain call (INV-M1).
        Accepts BOTH wire formats. Accumulates strictly-increasing vouchers
        only (INV-1/INV-M2).
        """
        lowered = {k.lower(): v for k, v in headers.items()}

        envelope = lowered.get(PAYMENT_SIGNATURE_HEADER)
        voucher: Voucher | None
        signature: str | None
        if envelope is not None:
            parsed = _decode_payment_signature(envelope)
            if parsed is None:
                return VerifyOutcome(
                    ok=False, status=402, reason="PAYMENT-SIGNATURE envelope undecodable"
                )
            voucher, signature = parsed
        else:
            voucher_b64 = lowered.get(X_PAYTHOS_VOUCHER_HEADER)
            signature = lowered.get(X_PAYTHOS_SIGNATURE_HEADER)
            if not voucher_b64 or not signature:
                return VerifyOutcome(
                    ok=False, status=402, reason="missing Paythos payment headers"
                )
            voucher = _decode_voucher(voucher_b64)
            if voucher is None:
                return VerifyOutcome(
                    ok=False, status=402, reason="PAYTHOS voucher undecodable"
                )

        return self._verify_core(voucher, signature)

    def _limit_for(self, agent_key: str) -> TokenBucket:
        """Per-agent bucket (created lazily; config-driven with spec defaults)."""
        key = agent_key.lower()
        bucket = self._buckets.get(key)
        if bucket is None:
            capacity, refill = self.cfg.rate_limit
            bucket = TokenBucket(capacity=capacity, refill_per_second=refill)
            self._buckets[key] = bucket
        return bucket

    def _verify_core(self, voucher: Voucher, signature: str) -> VerifyOutcome:
        if voucher.token.lower() != self.cfg.settlement_token.lower():
            return VerifyOutcome(
                ok=False, status=402, reason="voucher token is not the configured settlement token"
            )
        lower_key = voucher.agent_key.lower()
        authorized_epoch = self.cfg.authorized_agents.get(lower_key)
        if authorized_epoch is None:
            return VerifyOutcome(
                ok=False, status=402, reason="unknown agentKey — no session authorization on record"
            )
        # INV-6: a voucher signed under a dead delegation epoch never settles,
        # even though its EIP-712 signature verifies perfectly.
        if voucher.epoch != authorized_epoch:
            return VerifyOutcome(
                ok=False,
                status=402,
                reason="voucher epoch does not match the agent's active delegation (INV-6)",
            )
        # INV-M6: throttle BEFORE any cryptographic work (zero backend hits).
        # After authorization ⇒ the bucket map stays bounded for unknown keys.
        throttle = self._limit_for(voucher.agent_key).try_consume()
        if not throttle.allowed:
            return VerifyOutcome(
                ok=False,
                status=429,
                reason=f"local rate limit — retry in {throttle.retry_after_seconds}s (INV-M6)",
                retry_after_seconds=throttle.retry_after_seconds,
            )

        try:
            recovered = recover_voucher_signer(self._domain, voucher, signature)
        except Exception:  # noqa: BLE001 — any recovery failure denies
            return VerifyOutcome(
                ok=False,
                status=402,
                reason="voucher signature did not recover against the vault domain",
            )

        if voucher.valid_until < int(time.time()):
            return VerifyOutcome(ok=False, status=402, reason="voucher expired")
        if recovered != lower_key:
            return VerifyOutcome(
                ok=False, status=402, reason="signature was NOT signed by voucher.agentKey"
            )

        current = self._highest.get(recovered)
        if current is not None and voucher.cumulative_amount <= current[0].cumulative_amount:
            # INV-1/INV-M2: reject stale/identical replays.
            return VerifyOutcome(
                ok=False,
                status=402,
                reason="stale voucher: cumulative amount not strictly increasing",
            )

        # INV-M4 credit wall: halt streaming until a flush confirms settlement,
        # measured as UNSETTLED exposure (cumulative − confirmed on-chain).
        settled = self._settled.get(recovered, 0)
        unsettled_candidate = max(voucher.cumulative_amount - settled, 0)
        if unsettled_candidate > self.cfg.credit_tolerance_micro:
            return VerifyOutcome(
                ok=False,
                status=402,
                reason="credit tolerance exceeded — flush required (INV-M4)",
                unsettled_micro=self.unsettled_for(recovered),
            )

        self._highest[recovered] = (voucher, signature)
        unsettled = self.unsettled_for(recovered)
        # Flush evaluated BEFORE the activity stamp resets: the age trigger
        # must measure the idle window that just elapsed.
        self._maybe_flush(recovered)
        self._last_activity_at[recovered] = int(time.time())
        return VerifyOutcome(
            ok=True,
            status=200,
            agent_key=recovered,
            unsettled_micro=unsettled,
        )

    def unsettled_micro(self, voucher: Voucher) -> int:
        """Unsettled exposure for ONE voucher: cumulative − confirmed settled."""
        settled = self._settled.get(voucher.agent_key.lower(), 0)
        return max(voucher.cumulative_amount - settled, 0)

    def unsettled_for(self, agent_key: str) -> int:
        key = agent_key.lower()
        record = self._highest.get(key)
        if record is None:
            return 0
        return self.unsettled_micro(record[0])

    def mark_settled(self, agent_key: str, cumulative_settled: int) -> None:
        """
        Record an on-chain settlement (INV-M3). Called by the flush daemon
        after confirmation; resets the credit wall so the session continues.
        """
        key = agent_key.lower()
        if cumulative_settled > self._settled.get(key, 0):
            self._settled[key] = cumulative_settled
        self._last_activity_at[key] = int(time.time())

    def highest(self, agent_key: str) -> Voucher | None:
        record = self._highest.get(agent_key.lower())
        return record[0] if record is not None else None

    def signature_for(self, agent_key: str) -> str | None:
        record = self._highest.get(agent_key.lower())
        return record[1] if record is not None else None

    def _maybe_flush(self, agent_key: str) -> bool:
        """
        Production flush policy (INV-M2/M3), mirroring the TS daemon:
          (value): unsettled ≥ min(flush_threshold, credit wall − 1¢) — the
                   $5 default can never fire under the $2 wall otherwise; or
          (time):  unsettled > 0 idle for ≥ flush_interval_seconds.
        """
        record = self._highest.get(agent_key)
        if record is None or self.cfg.on_flush_ready is None:
            return False
        voucher, signature = record
        # Effective threshold: flush MUST fire before the wall trips.
        tolerance = self.cfg.credit_tolerance_micro
        configured = self.cfg.flush_threshold_micro
        effective = configured if configured < tolerance else max(tolerance - 1, tolerance)
        unsettled = self.unsettled_for(agent_key)
        now = int(time.time())
        last_activity = self._last_activity_at.get(agent_key, now)
        interval = self.cfg.flush_interval_seconds
        by_value = unsettled >= effective
        by_time = unsettled > 0 and now - last_activity >= interval
        if not by_value and not by_time:
            return False
        plan = FlushPlan(
            agent_key=agent_key, merchant=voucher.merchant, voucher=voucher, signature=signature
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        loop.create_task(self.cfg.on_flush_ready(plan))
        return True


def _decode_voucher(b64: str) -> Voucher | None:
    try:
        raw = json.loads(base64.b64decode(b64).decode("utf-8"))
        return Voucher(
            agent_key=raw["agentKey"],
            merchant=raw["merchant"],
            token=raw["token"],
            cumulative_amount=int(raw["cumulativeAmount"]),
            valid_until=int(raw["validUntil"]),
            epoch=int(raw["epoch"]),
            memo=raw["memo"],
        )
    except (KeyError, ValueError, TypeError, UnicodeDecodeError):
        return None


def _decode_payment_signature(raw: str) -> tuple[Voucher, str] | None:
    """x402 v2 ``PAYMENT-SIGNATURE`` wire: JSON ``{ voucher: {...}, signature }``."""
    try:
        payload = json.loads(raw)
        voucher_json = payload.get("voucher")
        signature = payload.get("signature")
        if not isinstance(voucher_json, dict) or not isinstance(signature, str):
            return None
        voucher = Voucher(
            agent_key=voucher_json["agentKey"],
            merchant=voucher_json["merchant"],
            token=voucher_json["token"],
            cumulative_amount=int(voucher_json["cumulativeAmount"]),
            valid_until=int(voucher_json["validUntil"]),
            epoch=int(voucher_json["epoch"]),
            memo=voucher_json["memo"],
        )
        return voucher, signature
    except (KeyError, ValueError, TypeError, AttributeError):
        return None


def paythos_fastapi_middleware(config: MerchantVerifierConfig):
    """
    FastAPI/Starlette ASGI middleware factory.
    GATING (REV-4): with ``challenge_for`` configured, a request WITHOUT
    payment headers receives a 402 x402 challenge — never a free pass.
    Without it (legacy/unpriced mount) traffic passes through untouched.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    accumulator = VoucherAccumulator(config)
    challenge_for = config.challenge_for

    def _has_payment_headers(headers: Mapping[str, str]) -> bool:
        lowered = {k.lower() for k in headers}
        return (
            X_PAYTHOS_VOUCHER_HEADER in lowered
            or X_PAYTHOS_SIGNATURE_HEADER in lowered
            or PAYMENT_SIGNATURE_HEADER in lowered
        )

    def _challenge_response(request: Request) -> JSONResponse:
        assert challenge_for is not None  # caller checked
        ctx = MerchantChallengeContext(method=request.method, url=request.url.path)
        challenge = challenge_for(ctx)
        encoded = base64.b64encode(
            json.dumps(challenge.model_dump(by_alias=True, exclude_none=True), separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return JSONResponse(
            {"error": "payment_required"},
            status_code=402,
            headers={
                PAYMENT_REQUIRED_HEADER: encoded,
                "accept-payment": "PAYTHOS/x402v2",
            },
        )

    class PaythosMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
            headers = dict(request.headers)
            if not _has_payment_headers(headers):
                if challenge_for is None:
                    return await call_next(request)
                return _challenge_response(request)
            outcome = accumulator.verify_payment(headers)
            if not outcome.ok:
                response_headers = {"accept-payment": "PAYTHOS/x402v2"}
                if outcome.status == 429:
                    # INV-M6: throttle the loop — no re-challenge, just backoff.
                    response_headers["Retry-After"] = str(
                        max(1, math.ceil(outcome.retry_after_seconds or 1))
                    )
                    return JSONResponse(
                        {"error": outcome.reason or "rate limited"},
                        status_code=429,
                        headers=response_headers,
                    )
                if challenge_for is not None:
                    # Re-challenge so the agent can retry with a fresh voucher.
                    ctx = MerchantChallengeContext(method=request.method, url=request.url.path)
                    ch = challenge_for(ctx)
                    response_headers[PAYMENT_REQUIRED_HEADER] = base64.b64encode(
                        json.dumps(ch.model_dump(by_alias=True, exclude_none=True), separators=(",", ":")).encode("utf-8")
                    ).decode("ascii")
                return JSONResponse(
                    {"error": outcome.reason or "payment rejected"},
                    status_code=outcome.status,
                    headers=response_headers,
                )
            request.state.paythos_agent_key = outcome.agent_key
            request.state.paythos_unsettled_micro = outcome.unsettled_micro
            return await call_next(request)

    return PaythosMiddleware, accumulator


__all__ = [
    "MerchantChallengeContext",
    "MerchantVerifierConfig",
    "FlushPlan",
    "VerifyOutcome",
    "VoucherAccumulator",
    "paythos_fastapi_middleware",
]
