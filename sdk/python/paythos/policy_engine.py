"""
GOFER — Governing Financial Objectives Runtime (docs/ARCHITECTURE.md Module 4).
The 3-Tier Enterprise Safety Threshold + destination allowlist + verifiable intent.
Fail closed: EVERY ambiguous input denies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Set

from eth_utils import keccak

from .types import PolicyEvaluatedFailure, PreFlightReport, parse_usd_to_micro


@dataclass(frozen=True)
class TierThresholds:
    """Threshold defaults are spec defaults (AGENTS.md); override per deployment."""

    micro_auto_exec_micro: int = parse_usd_to_micro("1")
    human_approval_upper_micro: int = parse_usd_to_micro("10")
    hard_ceiling_micro: int = parse_usd_to_micro("25")


DEFAULT_TIERS = TierThresholds()


@dataclass(frozen=True)
class PolicyContext:
    amount_micro: int  # this call's cost (or `upto` ceiling)
    remaining_allowance_micro: int
    merchant: str
    allowlist: Set[str]
    counterparty_approved: bool  # Transactability Index verdict


DecisionAction = Literal["allow", "human_approval_required", "deny"]


@dataclass(frozen=True)
class PolicyDecision:
    action: DecisionAction
    tier: Literal[1, 2, 3] | None
    reason: str = ""
    failure: PolicyEvaluatedFailure | None = None


class GoferPolicyEngine:
    def __init__(self, tiers: TierThresholds = DEFAULT_TIERS) -> None:
        self.tiers = tiers

    #: Mastercard-grade Verifiable Intent (Module 4.4):
    #: keccak256 over ``prompt || timestamp`` — stamped into the voucher ``memo``.
    #: The raw prompt NEVER leaves the local boundary; only its hash does.
    @staticmethod
    def intent_memo(prompt: str, timestamp_seconds: int) -> str:
        digest = keccak(text=f"{prompt}|{timestamp_seconds}")
        return "0x" + digest.hex()

    def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        """3-Tier evaluation. Never raises — and NEVER allows on ambiguity."""
        if ctx.amount_micro <= 0:
            return PolicyDecision(
                action="deny",
                tier=None,
                failure=PolicyEvaluatedFailure(
                    code="policy_ambiguous",
                    detail="amount is not a positive micro-USDC integer",
                ),
            )
        if ctx.merchant.lower() not in {m.lower() for m in ctx.allowlist}:
            return PolicyDecision(
                action="deny",
                tier=3,
                failure=PolicyEvaluatedFailure(
                    code="unauthorized_merchant",
                    detail=f"merchant {ctx.merchant} not on destination allowlist",
                ),
            )
        if not ctx.counterparty_approved:
            return PolicyDecision(
                action="deny",
                tier=3,
                failure=PolicyEvaluatedFailure(
                    code="counterparty_blocked",
                    detail="Transactability Index below vendor floor",
                ),
            )
        if ctx.amount_micro > self.tiers.hard_ceiling_micro:
            return PolicyDecision(
                action="deny",
                tier=3,
                failure=PolicyEvaluatedFailure(
                    code="max_per_tx_exceeded",
                    detail="Tier-3 hard policy ceiling exceeded",
                ),
            )
        if ctx.amount_micro > ctx.remaining_allowance_micro:
            return PolicyDecision(
                action="deny",
                tier=None,
                failure=PolicyEvaluatedFailure(
                    code="daily_limit_exceeded",
                    detail="insufficient rolling-24h allowance",
                ),
            )
        if ctx.amount_micro > self.tiers.micro_auto_exec_micro:
            # Reviewer catch: BOTH upper bands ($1–$10 AND $10–$25) require a
            # human — the $10–$25 band previously auto-allowed (inverted).
            upper = 3 if ctx.amount_micro > self.tiers.human_approval_upper_micro else 2
            return PolicyDecision(
                action="human_approval_required",
                tier=upper,
                reason=(
                    "Tier 3: below the hard ceiling but above the human-approval upper band"
                    if upper == 3
                    else "Tier 2: spend sits in the human review band"
                ),
            )
        return PolicyDecision(action="allow", tier=1, reason="within policy")

    def pre_flight(self, ctx: PolicyContext) -> PreFlightReport:
        """Structured dryRun report (Module 4.1) — pure, moves no capital."""
        decision = self.evaluate(ctx)
        if decision.action == "deny":
            return PreFlightReport(
                will_succeed=False,
                reason=decision.failure.detail if decision.failure else "denied",
                remaining_allowance_micro=ctx.remaining_allowance_micro,
                requires_human_approval=False,
                tier=decision.tier,
            )
        return PreFlightReport(
            will_succeed=True,
            reason=decision.reason,
            remaining_allowance_micro=ctx.remaining_allowance_micro - ctx.amount_micro,
            requires_human_approval=decision.action == "human_approval_required",
            tier=decision.tier,
        )
