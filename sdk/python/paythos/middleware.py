"""
Merchant membranes (docs/ARCHITECTURE.md Module 2 + 3).
Framework-agnostic core: ``VoucherAccumulator`` verifies in memory (INV-M1),
accumulates strictly-increasing vouchers (INV-M2), enforces the credit wall
(INV-M4) and surfaces flush plans. FastAPI middleware is a thin adapter.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Mapping, Set

from .rate_limit import TokenBucket
from .signer import SigningDomainArgs, domain_for, recover_voucher_signer
from .types import (
    PAYMENT_REQUIRED_HEADER,
    X_PAYTHOS_SIGNATURE_HEADER,
    X_PAYTHOS_VOUCHER_HEADER,
    PaymentChallenge,
    PaythosNetwork,
    Voucher,
)

FlushCallback = Callable[["FlushPlan"], Awaitable[None]]


@dataclass(frozen=True)
class MerchantVerifierConfig:
    network: PaythosNetwork
    vault_address: str
    #: The vault's immutable settlement token (Arc native-USDC precompile).
    settlement_token: str
    #: Addresses whose settlement the vault will honor (allowlist mirror).
    authorized_agents: Set[str]
    #: Merchant credit-line ceiling in micro-USDC (INV-M4; docs default $2.00 / $1.00).
    credit_tolerance_micro: int = 2_000_000
    #: Value flush threshold in micro-USDC ($5.00 default, docs/PROTOCOL.md §6).
    flush_threshold_micro: int = 5_000_000
    on_flush_ready: FlushCallback | None = None
    rate_limit: tuple[int, float] = (100, 10.0)


@dataclass(frozen=True)
class FlushPlan:
    agent_key: str
    merchant: str
    voucher: Voucher  # the HIGHEST unclaimed voucher (INV-M2)


@dataclass(frozen=True)
class VerifyOutcome:
    ok: bool
    status: int
    reason: str = ""
    agent_key: str = ""
    unsettled_micro: int = 0


class VoucherAccumulator:
    """Merchant-side session ledger: agentKey → highest voucher (INV-M2)."""

    def __init__(self, config: MerchantVerifierConfig) -> None:
        self.cfg = config
        self._highest: dict[str, Voucher] = {}
        self._domain = domain_for(
            SigningDomainArgs(network=config.network, vault_address=config.vault_address)
        )
        self._bucket = TokenBucket(
            capacity=config.rate_limit[0], refill_per_second=config.rate_limit[1]
        )

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
        Accumulates strictly-increasing vouchers only (INV-1/INV-M2).
        """
        lowered = {k.lower(): v for k, v in headers.items()}

        if not self._bucket.try_consume().allowed:
            return VerifyOutcome(ok=False, status=429, reason="token bucket exhausted (INV-M6)")

        voucher_b64 = lowered.get(X_PAYTHOS_VOUCHER_HEADER)
        signature = lowered.get(X_PAYTHOS_SIGNATURE_HEADER)
        if not voucher_b64 or not signature:
            return VerifyOutcome(ok=False, status=402, reason="missing Paythos payment headers")

        voucher = _decode_voucher(voucher_b64)
        if voucher is None:
            return VerifyOutcome(ok=False, status=402, reason="PAYTHOS voucher undecodable")

        if voucher.token.lower() != self.cfg.settlement_token.lower():
            return VerifyOutcome(
                ok=False, status=402, reason="voucher token is not the configured settlement token"
            )
        if voucher.agent_key.lower() not in {a.lower() for a in self.cfg.authorized_agents}:
            return VerifyOutcome(
                ok=False, status=402, reason="unknown agentKey — no session authorization on record"
            )

        try:
            recovered = recover_voucher_signer(self._domain, voucher, signature)
        except Exception:  # noqa: BLE001 — any recovery failure denies
            return VerifyOutcome(
                ok=False, status=402, reason="voucher signature did not recover against the vault domain"
            )

        if voucher.valid_until < int(time.time()):
            return VerifyOutcome(ok=False, status=402, reason="voucher expired")
        if recovered != voucher.agent_key.lower():
            return VerifyOutcome(
                ok=False, status=402, reason="signature was NOT signed by voucher.agentKey"
            )

        current = self._highest.get(recovered)
        if current is not None and voucher.cumulative_amount <= current.cumulative_amount:
            # INV-1/INV-M2: reject stale/identical replays.
            return VerifyOutcome(
                ok=False,
                status=402,
                reason="stale voucher: cumulative amount not strictly increasing",
            )

        # INV-M4: the credit wall halts streaming until a flush confirms settlement.
        if voucher.cumulative_amount > self.cfg.credit_tolerance_micro:
            return VerifyOutcome(
                ok=False,
                status=402,
                reason="credit tolerance exceeded — flush required (INV-M4)",
                unsettled_micro=current.cumulative_amount if current else 0,
            )

        self._highest[recovered] = voucher
        self._maybe_flush(recovered)
        return VerifyOutcome(
            ok=True,
            status=200,
            agent_key=recovered,
            unsettled_micro=voucher.cumulative_amount,
        )

    def highest(self, agent_key: str) -> Voucher | None:
        return self._highest.get(agent_key.lower())

    def _maybe_flush(self, agent_key: str) -> None:
        voucher = self._highest.get(agent_key)
        if voucher is None or voucher.cumulative_amount < self.cfg.flush_threshold_micro:
            return
        if self.cfg.on_flush_ready is None:
            return
        import asyncio

        plan = FlushPlan(
            agent_key=agent_key, merchant=voucher.merchant, voucher=voucher
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.cfg.on_flush_ready(plan))


def _decode_voucher(b64: str) -> Voucher | None:
    try:
        raw = json.loads(base64.b64decode(b64).decode("utf-8"))
        return Voucher(
            agent_key=raw["agentKey"],
            merchant=raw["merchant"],
            token=raw["token"],
            cumulative_amount=int(raw["cumulativeAmount"]),
            valid_until=int(raw["validUntil"]),
            memo=raw["memo"],
        )
    except (KeyError, ValueError, TypeError, UnicodeDecodeError):
        return None


def paythos_fastapi_middleware(config: MerchantVerifierConfig):
    """
    FastAPI/Starlette ASGI middleware factory. Verifies Paythos headers when
    present; requests without payment headers pass through untouched.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    accumulator = VoucherAccumulator(config)

    class PaythosMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
            headers = dict(request.headers)
            if X_PAYTHOS_VOUCHER_HEADER not in {k.lower() for k in headers}:
                return await call_next(request)
            outcome = accumulator.verify_payment(headers)
            if not outcome.ok:
                return JSONResponse(
                    {"error": outcome.reason or "payment rejected"},
                    status_code=outcome.status,
                    headers={"accept-payment": "PAYTHOS/x402v2"},
                )
            request.state.paythos_agent_key = outcome.agent_key
            request.state.paythos_unsettled_micro = outcome.unsettled_micro
            return await call_next(request)

    return PaythosMiddleware, accumulator


__all__ = [
    "MerchantVerifierConfig",
    "FlushPlan",
    "VerifyOutcome",
    "VoucherAccumulator",
    "paythos_fastapi_middleware",
]
