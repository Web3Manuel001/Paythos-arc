from __future__ import annotations

from dataclasses import replace

from paythos import (
    DEFAULT_TIERS,
    GoferPolicyEngine,
    PolicyContext,
    parse_usd_to_micro,
)

from conftest import TEST_MERCHANT

MERCHANT = TEST_MERCHANT.lower()
ALLOWED = {MERCHANT}


def ctx(amount: str, **overrides: object) -> PolicyContext:
    base = PolicyContext(
        amount_micro=parse_usd_to_micro(amount),
        remaining_allowance_micro=parse_usd_to_micro("20"),
        merchant=MERCHANT,
        allowlist=ALLOWED,
        counterparty_approved=True,
    )
    return replace(base, **overrides) if overrides else base


def test_tier1_sub_dollar_autonomous() -> None:
    decision = GoferPolicyEngine().evaluate(ctx("0.75"))
    assert decision.action == "allow" and decision.tier == 1


def test_tier2_human_band() -> None:
    decision = GoferPolicyEngine().evaluate(ctx("3.50"))
    assert decision.action == "human_approval_required" and decision.tier == 2


def test_tier3_hard_ceiling() -> None:
    decision = GoferPolicyEngine().evaluate(ctx("25.01"))
    assert decision.action == "deny"
    assert decision.failure is not None and "ceiling" in decision.failure.detail


def test_denies_non_allowlisted_merchant() -> None:
    decision = GoferPolicyEngine().evaluate(
        ctx("0.10", merchant="0x9999999999999999999999999999999999999999")
    )
    assert decision.action == "deny"


def test_denies_blocked_counterparty() -> None:
    decision = GoferPolicyEngine().evaluate(ctx("0.10", counterparty_approved=False))
    assert decision.action == "deny"


def test_denies_over_remaining_allowance() -> None:
    decision = GoferPolicyEngine().evaluate(
        ctx("15", remaining_allowance_micro=parse_usd_to_micro("12"))
    )
    assert decision.action == "deny"


def test_denies_non_positive_amount() -> None:
    decision = GoferPolicyEngine().evaluate(ctx("0.10", amount_micro=0))
    assert decision.action == "deny"


def test_intent_memo_is_deterministic_keccak() -> None:
    memo = GoferPolicyEngine.intent_memo("buy flour", 1_700_000_000)
    assert memo.startswith("0x") and len(memo) == 66
    assert GoferPolicyEngine.intent_memo("buy flour", 1_700_000_000) == memo
    assert GoferPolicyEngine.intent_memo("buy flour", 1_700_000_001) != memo


def test_default_tiers_match_spec() -> None:
    assert DEFAULT_TIERS.micro_auto_exec_micro == 1_000_000
    assert DEFAULT_TIERS.human_approval_upper_micro == 10_000_000
    assert DEFAULT_TIERS.hard_ceiling_micro == 25_000_000


def test_preflight_never_moves_capital() -> None:
    report = GoferPolicyEngine().pre_flight(ctx("0.50"))
    assert report.will_succeed
    assert report.remaining_allowance_micro == parse_usd_to_micro("19.50")
