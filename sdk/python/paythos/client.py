"""
PaythosClient — x402 v2 auto-negotiation (docs/ARCHITECTURE.md Module 3.2).
Intercepts HTTP 402 challenges, runs the GOFER policy gate, signs a cumulative
EIP-712 voucher, retries once with the payment headers.
YOPO for ``upto`` streams: tokens for unrendered output are NEVER signed.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Set

import httpx

from .errors import PaythosError
from .policy_engine import GoferPolicyEngine, PolicyContext, TierThresholds
from .rate_limit import TokenBucket
from .signer import AgentVoucherSigner
from .types import (
    PAYMENT_SIGNATURE_HEADER,
    PaymentChallenge,
    PaythosNetwork,
    PolicyEvaluatedFailure,
    PreFlightReport,
    format_micro_usd,
    parse_usd_to_micro,
)

#: Spec-default rolling allowance until on-chain telemetry lands (Gate 2.5).
DEFAULT_ALLOWANCE_MICRO = parse_usd_to_micro("20")

TransactabilityOracle = Callable[[str], bool]
HumanApprovalSummary = dict[str, str]
HumanGate = Callable[[HumanApprovalSummary], Awaitable[bool]]


@dataclass(frozen=True)
class GateDecision:
    ok: bool
    memo: str = ""
    amount_micro: int = 0
    needs_human: bool = False
    reason: str = ""
    error: PolicyEvaluatedFailure | None = None


@dataclass(frozen=True)
class ExecutedResult:
    ok: bool
    response: httpx.Response | None = None
    voucher: object | None = None
    error: PolicyEvaluatedFailure | None = None
    status: int | None = None


@dataclass(frozen=True)
class RequestAttempt:
    url: str
    method: str = "GET"
    prompt: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = None


class PaythosClient:
    def __init__(
        self,
        signer: AgentVoucherSigner,
        *,
        network: PaythosNetwork,
        allowlist: Set[str],
        transactability: TransactabilityOracle | None = None,
        tiers: TierThresholds | None = None,
        rate_limit: tuple[int, float] = (100, 10.0),
        approve_with_human: HumanGate | None = None,
        allowance_micro: int = DEFAULT_ALLOWANCE_MICRO,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.signer = signer
        self.network = network
        self.allowlist = allowlist
        self._gofer = GoferPolicyEngine(tiers or TierThresholds())
        self._transactability = transactability or (lambda _merchant: True)
        self._bucket = TokenBucket(capacity=rate_limit[0], refill_per_second=rate_limit[1])
        self._human_gate = approve_with_human
        self._allowance_micro = allowance_micro
        self._http = http or httpx.AsyncClient(follow_redirects=True)

    def dry_run(self, challenge: PaymentChallenge) -> PreFlightReport:
        """Structured pre-flight on a challenge, capital untouched (Module 4.1)."""
        return self._gofer.pre_flight(self._context_for(challenge))

    def gate(self, challenge: PaymentChallenge, prompt: str) -> GateDecision:
        amount_micro = parse_max_micro(challenge)
        memo = GoferPolicyEngine.intent_memo(prompt, int(time.time()))
        if not self._bucket.try_consume().allowed:
            return GateDecision(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="rate_limited", detail="local token-bucket throttled this loop"
                ),
            )
        report = self._gofer.pre_flight(self._context_for(challenge))
        if not report.will_succeed:
            return GateDecision(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_failure", detail=report.reason),
            )
        return GateDecision(
            ok=True,
            memo=memo,
            amount_micro=amount_micro,
            needs_human=report.requires_human_approval,
            reason=report.reason,
        )

    async def confirm_tier2(self, summary: HumanApprovalSummary) -> bool:
        """Tier-2 path: awaited cryptographic review; absent provider ⇒ deny."""
        if self._human_gate is None:
            return False  # fail closed
        return await self._human_gate(summary)

    async def fetch_with_x402(self, attempt: RequestAttempt) -> ExecutedResult:
        """GET → 402 → challenge decode → GOFER gate → voucher → retry once."""
        first = await self._raw_fetch(attempt)
        if first.status_code != 402:
            if first.is_success:
                return ExecutedResult(ok=True, response=first)
            return ExecutedResult(
                ok=False,
                status=first.status_code,
                error=PolicyEvaluatedFailure(
                    code="network_error", detail=f"HTTP {first.status_code}"
                ),
            )

        challenge = decode_challenge(first)
        gate = self.gate(challenge, attempt.prompt or attempt.url)
        if not gate.ok:
            return ExecutedResult(ok=False, error=gate.error)

        if gate.needs_human:
            approved = await self.confirm_tier2(
                {
                    "amount_usd": format_micro_usd(gate.amount_micro),
                    "merchant": challenge.pay_to,
                    "memo": gate.memo,
                    "kind": "tier2_review",
                }
            )
            if not approved:
                return ExecutedResult(
                    ok=False,
                    error=PolicyEvaluatedFailure(
                        code="human_approval_required", detail=gate.reason
                    ),
                )

        signed = self.signer.record_and_sign(challenge.pay_to, gate.amount_micro, gate.memo)
        if not signed.ok or signed.voucher is None or signed.signature is None:
            detail = signed.error["detail"] if signed.error else "signing failed"
            return ExecutedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_failure", detail=detail),
            )

        retry_headers = dict(attempt.headers)
        retry_headers[PAYMENT_SIGNATURE_HEADER] = json.dumps(
            {
                "voucher": serialize_voucher(signed.voucher),
                "signature": signed.signature,
            }
        )
        retry = await self._raw_fetch(
            RequestAttempt(
                url=attempt.url,
                method=attempt.method,
                prompt=attempt.prompt,
                headers=retry_headers,
                content=attempt.content,
            )
        )
        if retry.status_code == 402:
            return ExecutedResult(
                ok=False,
                status=402,
                error=PolicyEvaluatedFailure(
                    code="invalid_voucher", detail="payment rejected on retry"
                ),
            )
        if retry.is_success:
            return ExecutedResult(ok=True, response=retry, voucher=signed.voucher)
        return ExecutedResult(
            ok=False,
            status=retry.status_code,
            error=PolicyEvaluatedFailure(
                code="network_error", detail=f"HTTP {retry.status_code}"
            ),
        )

    def _context_for(self, challenge: PaymentChallenge) -> PolicyContext:
        return PolicyContext(
            amount_micro=parse_max_micro(challenge),
            remaining_allowance_micro=self._allowance_micro,
            merchant=challenge.pay_to,
            allowlist=self.allowlist,
            counterparty_approved=self._transactability(challenge.pay_to),
        )

    async def _raw_fetch(self, attempt: RequestAttempt) -> httpx.Response:
        try:
            return await self._http.request(
                attempt.method,
                attempt.url,
                headers=attempt.headers,
                content=attempt.content,
            )
        except httpx.HTTPError as exc:
            raise PaythosError("network_error", f"fetch failed: {exc}") from exc

    async def aclose(self) -> None:
        await self._http.aclose()


def serialize_voucher(voucher: object) -> dict[str, str]:
    """The x402 ``PAYMENT-SIGNATURE`` envelope is JSON ``{ voucher, signature }``."""
    v = voucher  # typed duck: Voucher
    return {
        "agentKey": v.agent_key,  # type: ignore[attr-defined]
        "merchant": v.merchant,  # type: ignore[attr-defined]
        "token": v.token,  # type: ignore[attr-defined]
        "cumulativeAmount": str(v.cumulative_amount),  # type: ignore[attr-defined]
        "validUntil": str(v.valid_until),  # type: ignore[attr-defined]
        "memo": v.memo,  # type: ignore[attr-defined]
    }


def parse_max_micro(challenge: PaymentChallenge) -> int:
    raw = challenge.max
    if not isinstance(raw, str):
        raise PaythosError("invalid_challenge", "challenge carries no max field")
    try:
        return parse_usd_to_micro(raw) if "." in raw else int(raw)
    except ValueError as exc:
        raise PaythosError("invalid_challenge", f"unparseable challenge amount: {raw}") from exc


def decode_challenge(response: httpx.Response) -> PaymentChallenge:
    header = response.headers.get("payment-required")
    if not header:
        raise PaythosError("invalid_challenge", "402 without PAYMENT-REQUIRED header")
    try:
        decoded = json.loads(base64.b64decode(header).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PaythosError("invalid_challenge", "PAYMENT-REQUIRED is not valid base64 JSON") from exc
    if decoded.get("x402Version") != 2:
        raise PaythosError(
            "invalid_challenge", f"unsupported x402Version {decoded.get('x402Version')}"
        )
    if not decoded.get("payTo") or not decoded.get("network"):
        raise PaythosError("invalid_challenge", "challenge missing payTo/network")
    return PaymentChallenge(
        x402_version=2,
        scheme=decoded.get("scheme", "exact"),
        network=decoded["network"],
        asset=decoded.get("asset", ""),
        pay_to=decoded["payTo"],
        max=str(decoded.get("max", "")),
        resource=decoded.get("resource", ""),
        description=decoded.get("description"),
        mime_type=decoded.get("mimeType"),
        memo_required=bool(decoded.get("memoRequired", False)),
    )


__all__ = [
    "DEFAULT_ALLOWANCE_MICRO",
    "GateDecision",
    "ExecutedResult",
    "RequestAttempt",
    "PaythosClient",
    "serialize_voucher",
    "parse_max_micro",
    "decode_challenge",
    "TransactabilityOracle",
    "HumanGate",
]
