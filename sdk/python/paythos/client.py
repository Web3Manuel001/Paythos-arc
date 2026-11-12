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
from .hold_ledger import HoldLedger, stream_id_for
from .metering import MeteringReport, parse_metering_report, recover_metering_signer
from .policy_engine import GoferPolicyEngine, PolicyContext, TierThresholds
from .rate_limit import TokenBucket
from .signer import AgentVoucherSigner
from .transactability import MerchantObservation, is_transactability_index
from .types import (
    PAYMENT_SIGNATURE_HEADER,
    PaymentChallenge,
    PaythosNetwork,
    PolicyEvaluatedFailure,
    PreFlightReport,
    X_PAYTHOS_STREAM_HEADER,
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
    method: str | None = None
    prompt: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = None


@dataclass(frozen=True)
class StreamedResult:
    """YOPO ``upto`` stream outcome — ``hold_state`` ∈ unset | released | settled."""

    ok: bool
    data: str | None = None
    stream_id: str | None = None
    consumed_usd: str | None = None
    consumed_micro: int | None = None
    voucher: object | None = None
    error: PolicyEvaluatedFailure | None = None
    status: int | None = None
    hold_state: str = "unset"


@dataclass
class StreamHooks:
    on_chunk: Callable[[str, str], None] | None = None
    extract_metering: Callable[[httpx.Response, str], MeteringReport | None] | None = None


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
        self.holds = HoldLedger()
        # Per-client nonce: identical url+prompt streams in the same ms must not collide.
        self._stream_seq = 0
        self._gofer = GoferPolicyEngine(tiers or TierThresholds())
        self._transactability = transactability or (lambda _merchant: True)
        self._transactability_oracle = transactability
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
        retried_at = time.time()
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
            self._observe(
                challenge.pay_to,
                MerchantObservation(
                    ok=True, latency_ms=_elapsed_ms(retried_at), status=retry.status_code
                ),
            )
            return ExecutedResult(ok=True, response=retry, voucher=signed.voucher)
        self._observe(
            challenge.pay_to,
            MerchantObservation(
                ok=False,
                latency_ms=_elapsed_ms(retried_at),
                status=retry.status_code,
                valid=False,
            ),
        )
        return ExecutedResult(
            ok=False,
            status=retry.status_code,
            error=PolicyEvaluatedFailure(
                code="network_error", detail=f"HTTP {retry.status_code}"
            ),
        )

    def _context_for(self, challenge: PaymentChallenge) -> PolicyContext:
        active_hold = self.holds.active_hold_micro()
        free = self._allowance_micro - active_hold if self._allowance_micro > active_hold else 0
        return PolicyContext(
            amount_micro=parse_max_micro(challenge),
            # ACTIVE `upto` holds run against the same rolling budget until
            # they settle or release (YOPO ceiling = reserved headroom).
            remaining_allowance_micro=free,
            merchant=challenge.pay_to,
            allowlist=self.allowlist,
            counterparty_approved=self._transactability(challenge.pay_to),
        )

    async def _raw_fetch(self, attempt: RequestAttempt) -> httpx.Response:
        try:
            return await self._http.request(
                attempt.method or "GET",
                attempt.url,
                headers=attempt.headers,
                content=attempt.content,
            )
        except httpx.HTTPError as exc:
            raise PaythosError("network_error", f"fetch failed: {exc}") from exc

    def _observe(self, merchant: str, observation: MerchantObservation) -> None:
        """Feed measured service quality into a TransactabilityIndex (best-effort)."""
        oracle = self._transactability_oracle
        if not is_transactability_index(oracle):
            return
        try:
            oracle.record(merchant, observation)  # type: ignore[union-attr]
        except Exception:
            pass  # health telemetry must never break a spend path

    async def stream_with_x402(
        self,
        attempt: RequestAttempt,
        hooks: StreamHooks | None = None,
    ) -> StreamedResult:
        """YOPO streaming for ``scheme: "upto"`` challenges (PROTOCOL §4.2, INV-M5)."""
        hooks = hooks or StreamHooks()
        prompt = attempt.prompt or attempt.url

        first = await self._raw_fetch(attempt)
        if first.status_code != 402:
            if first.is_success:
                return StreamedResult(ok=True, data=first.text)  # free endpoint
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="network_error", detail=f"upstream {first.status_code}"),
            )

        challenge = decode_challenge(first)
        if challenge.scheme != "upto":
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_ambiguous",
                    detail=f'stream_with_x402 requires scheme "upto" (got "{challenge.scheme}") — use fetch_with_x402 for exact',
                ),
            )

        ceiling = parse_max_micro(challenge)
        active_hold = self.holds.active_hold_micro()
        free = self._allowance_micro - active_hold if self._allowance_micro > active_hold else 0
        if free < ceiling:
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_failure",
                    detail=f"insufficient allowance for the {format_micro_usd(ceiling)} upto hold — {format_micro_usd(free)} free",
                ),
                hold_state="unset",
            )
        gate = self.gate(challenge, prompt)
        if not gate.ok or gate.error is not None:
            return StreamedResult(ok=False, error=gate.error, hold_state="unset")

        # ---- HOLD (internal lock — the ceiling is NEVER signed here) ----
        # Lock BEFORE awaiting human approval: two concurrent streams used to
        # pass the free-budget check, both await, then both lock, exceeding the
        # allowance (reviewer 2026-11). No await occurs between check and lock.
        stream_id = stream_id_for(
            attempt.url,
            prompt,
            int(time.time() * 1000) * 1000 + (self._stream_seq % 1000),
        )
        self._stream_seq += 1
        self.holds.lock(stream_id, challenge.pay_to, ceiling)
        if gate.needs_human:
            try:
                approved = await self.confirm_tier2(
                    {
                        "amount_usd": format_micro_usd(gate.amount_micro),
                        "merchant": challenge.pay_to,
                        "memo": gate.memo,
                        "kind": "tier2_review",
                    }
                )
            except Exception:
                self.holds.release(stream_id)
                raise
            if not approved:
                self.holds.release(stream_id)
                return StreamedResult(
                    ok=False,
                    error=PolicyEvaluatedFailure(code="human_approval_required", detail=gate.reason),
                    hold_state="released",
                )

        # ---- open the stream UNPAID ----
        stream_started_at = time.time()
        open_headers = dict(attempt.headers or {})
        open_headers[X_PAYTHOS_STREAM_HEADER] = stream_id
        request = self._http.build_request(
            attempt.method or "GET",
            attempt.url,
            headers=open_headers,
            content=attempt.content,
        )
        try:
            stream = await self._http.send(request, stream=True)
        except httpx.HTTPError as exc:
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=False, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="network_error", detail=f"stream open failed: {exc}"),
                hold_state="released",
            )
        if stream.status_code >= 400:
            self.holds.release(stream_id)
            await stream.aclose()
            self._observe(
                challenge.pay_to,
                MerchantObservation(
                    ok=False,
                    latency_ms=_elapsed_ms(stream_started_at),
                    status=stream.status_code,
                    valid=False,
                ),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="network_error", detail=f"stream refused: HTTP {stream.status_code}"),
                hold_state="released",
            )

        pieces: list[str] = []
        try:
            async for delta in stream.aiter_text():
                pieces.append(delta)
                cumulative = "".join(pieces)
                try:
                    if hooks.on_chunk is not None:
                        hooks.on_chunk(delta, cumulative)
                except Exception:
                    pass  # observer errors MUST NOT kill the stream (best-effort UI)
        except httpx.HTTPError as exc:
            # ---- YOPO: connection broke mid-stream ⇒ hold released, no voucher ----
            await stream.aclose()
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=False, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="network_error", detail=f"stream broke before completion: {exc}"),
                hold_state="released",
            )
        await stream.aclose()
        full_text = "".join(pieces)

        # ---- metering proof (attested, ≤ ceiling, recovering to pay_to) ----
        if hooks.extract_metering is not None:
            report = hooks.extract_metering(stream, full_text)
        else:
            report = default_extract_metering(full_text)
        if report is None:
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=True, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_ambiguous",
                    detail="no metering report on the terminal frame — hold released unpaid (YOPO)",
                ),
                hold_state="released",
            )
        try:
            recovered = recover_metering_signer(report)
        except PaythosError as exc:
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=True, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_ambiguous", detail=f"metering attestation malformed: {exc}"),
                hold_state="released",
            )
        if recovered != challenge.pay_to.lower():
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=True, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_ambiguous",
                    detail="metering attestation did NOT recover to the payTo destination",
                ),
                hold_state="released",
            )
        # Replay binding: a signature over stream A must never settle stream B.
        if report.stream_id != stream_id:
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=True, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_ambiguous",
                    detail="metering attestation is bound to a different stream — hold released (replay)",
                ),
                hold_state="released",
            )
        try:
            consumed_micro = parse_usd_to_micro(report.consumed)
        except ValueError:
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=True, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_ambiguous", detail=f'unparseable consumed amount: "{report.consumed}"'),
                hold_state="released",
            )
        if consumed_micro > ceiling:
            self.holds.release(stream_id)
            self._observe(
                challenge.pay_to,
                MerchantObservation(ok=True, latency_ms=_elapsed_ms(stream_started_at), valid=False),
            )
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_failure",
                    detail=f"metered {format_micro_usd(consumed_micro)} exceeds the {format_micro_usd(ceiling)} ceiling",
                ),
                hold_state="released",
            )
        try:
            self.holds.settle(stream_id, consumed_micro)
        except ValueError as exc:
            # settle() releases the hold itself on zero/over-ceiling consumed —
            # nothing owed, nothing signed (YOPO zero-render ⇒ unpaid).
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_failure", detail=f"hold settlement refused: {exc}"),
                hold_state="released",
            )

        # ---- sign EXACT consumption + POST the completion call ----
        signed = self.signer.record_and_sign(challenge.pay_to, consumed_micro, gate.memo)
        if not signed.ok or signed.voucher is None or signed.signature is None:
            detail = signed.error["detail"] if signed.error else "signing failed"
            return StreamedResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_failure", detail=f"settlement refused: {detail}"),
                hold_state="settled",
            )
        completion_headers = dict(attempt.headers)
        completion_headers[X_PAYTHOS_STREAM_HEADER] = stream_id
        completion_headers[PAYMENT_SIGNATURE_HEADER] = json.dumps(
            {
                "voucher": serialize_voucher(signed.voucher),
                "signature": signed.signature,
            }
        )
        completion = RequestAttempt(
            url=attempt.url,
            method=attempt.method or "POST",
            prompt=prompt,
            headers=completion_headers,
            content=json.dumps({"streamId": stream_id}).encode(),
        )
        retry = await self._raw_fetch(completion)
        if retry.status_code == 402:
            self._observe(
                challenge.pay_to,
                MerchantObservation(
                    ok=False,
                    latency_ms=_elapsed_ms(stream_started_at),
                    status=402,
                    valid=False,
                ),
            )
            return StreamedResult(
                ok=False,
                status=402,
                error=PolicyEvaluatedFailure(code="invalid_voucher", detail="completion payment rejected"),
                hold_state="settled",
            )
        if retry.is_success:
            self._observe(
                challenge.pay_to,
                MerchantObservation(
                    ok=True,
                    latency_ms=_elapsed_ms(stream_started_at),
                    status=retry.status_code,
                    valid=True,
                ),
            )
            return StreamedResult(
                ok=True,
                data=full_text,
                stream_id=stream_id,
                consumed_usd=format_micro_usd(consumed_micro),
                consumed_micro=consumed_micro,
                voucher=signed.voucher,
                hold_state="settled",
            )
        self._observe(
            challenge.pay_to,
            MerchantObservation(
                ok=False,
                latency_ms=_elapsed_ms(stream_started_at),
                status=retry.status_code,
                valid=False,
            ),
        )
        return StreamedResult(
            ok=False,
            status=retry.status_code,
            error=PolicyEvaluatedFailure(code="network_error", detail=f"upstream {retry.status_code} on completion"),
            hold_state="settled",
        )

    async def aclose(self) -> None:
        await self._http.aclose()


def _elapsed_ms(started_at: float) -> int:
    return int((time.time() - started_at) * 1000)


def serialize_voucher(voucher: object) -> dict[str, str]:
    """The x402 ``PAYMENT-SIGNATURE`` envelope is JSON ``{ voucher, signature }``."""
    v = voucher  # typed duck: Voucher
    return {
        "agentKey": v.agent_key,  # type: ignore[attr-defined]
        "merchant": v.merchant,  # type: ignore[attr-defined]
        "token": v.token,  # type: ignore[attr-defined]
        "cumulativeAmount": str(v.cumulative_amount),  # type: ignore[attr-defined]
        "validUntil": str(v.valid_until),  # type: ignore[attr-defined]
        "epoch": str(v.epoch),  # type: ignore[attr-defined]
        "memo": v.memo,  # type: ignore[attr-defined]
    }


def default_extract_metering(full_text: str) -> MeteringReport | None:
    """Terminal metering frame = LAST parseable non-empty line of the body."""
    lines = [line for line in full_text.split("\n") if line.strip()]
    for line in reversed(lines):
        report = parse_metering_report(line)
        if report is not None:
            return report
    return None


def parse_max_micro(challenge: PaymentChallenge) -> int:
    """Unambiguous amount parsing: ``max`` is decimal USD, ``amount`` atomic micro.

    A bare ``max="10"`` is $10.00 (10_000_000 micro), never 10 atomic micro;
    the x402 ``amount`` field is the only atomic-micro source (reviewer 2026-11).
    """
    if isinstance(challenge.max, str) and challenge.max:
        try:
            return parse_usd_to_micro(challenge.max)
        except ValueError as exc:
            raise PaythosError(
                "invalid_challenge", f"unparseable challenge max (decimal USD): {challenge.max}"
            ) from exc
    amount = getattr(challenge, "amount", None)
    if isinstance(amount, str) and amount:
        if not amount.isdigit():
            raise PaythosError(
                "invalid_challenge", f"unparseable challenge amount (atomic micro): {amount}"
            )
        return int(amount)
    raise PaythosError("invalid_challenge", "challenge carries no max/amount field")


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
    "StreamHooks",
    "StreamedResult",
    "default_extract_metering",
    "serialize_voucher",
    "parse_max_micro",
    "decode_challenge",
    "TransactabilityOracle",
    "HumanGate",
]
