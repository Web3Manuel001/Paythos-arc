from __future__ import annotations

import asyncio

import pytest

from paythos import (
    AgentVoucherSigner,
    GoferPolicyEngine,
    MerchantVerifierConfig,
    SigningDomainArgs,
    VoucherAccumulator,
    parse_usd_to_micro,
)

from conftest import AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeral_private_key


def make_pair(price_micro: int, token: str = AR_NATIVE_USDC):
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )
    config = MerchantVerifierConfig(
        network=TESTNET,
        vault_address=TEST_VAULT,
        settlement_token=token,
        authorized_agents={signer.agent_key.lower()},
    )
    accumulator = VoucherAccumulator(config)
    return signer, accumulator


def test_verifies_signed_voucher_and_recovers_agent() -> None:
    signer, accumulator = make_pair(parse_usd_to_micro("0.30"))
    memo = GoferPolicyEngine.intent_memo("pay for data", 1_700_000_000)
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.30"), memo)
    assert signed.ok
    outcome = accumulator.verify_payment(signed.headers)
    assert outcome.ok and outcome.status == 200
    assert outcome.agent_key == signer.agent_key.lower()
    assert outcome.unsettled_micro == parse_usd_to_micro("0.30")


def test_rejects_replayed_voucher() -> None:
    signer, accumulator = make_pair(parse_usd_to_micro("0.10"))
    memo = GoferPolicyEngine.intent_memo("p", 1_700_000_000)
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), memo)
    assert signed.ok
    assert accumulator.verify_payment(signed.headers).ok
    replay = accumulator.verify_payment(signed.headers)
    assert not replay.ok and replay.status == 402
    assert "not strictly increasing" in replay.reason


def test_rejects_bad_signature() -> None:
    signer, accumulator = make_pair(parse_usd_to_micro("0.10"))
    memo = GoferPolicyEngine.intent_memo("p", 1_700_000_000)
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), memo)
    assert signed.ok
    tampered = dict(signed.headers)
    tampered["x-paythos-signature"] = "0x" + "00" * 65
    assert not accumulator.verify_payment(tampered).ok


def test_rejects_wrong_settlement_token() -> None:
    wrong = "0x1111111111111111111111111111111111111111"
    signer, accumulator = make_pair(parse_usd_to_micro("0.10"), token=wrong)
    memo = GoferPolicyEngine.intent_memo("p", 1_700_000_000)
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), memo)
    assert signed.ok
    outcome = accumulator.verify_payment(signed.headers)
    assert not outcome.ok and "settlement token" in outcome.reason


def test_rejects_unauthorized_agent() -> None:
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )
    accumulator = VoucherAccumulator(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            authorized_agents={"0x7777777777777777777777777777777777777777"},
        )
    )
    memo = GoferPolicyEngine.intent_memo("p", 1_700_000_000)
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), memo)
    assert signed.ok
    assert "unknown agentKey" in accumulator.verify_payment(signed.headers).reason


def test_credit_wall_halts_above_tolerance() -> None:
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )
    accumulator = VoucherAccumulator(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            authorized_agents={signer.agent_key.lower()},
            credit_tolerance_micro=parse_usd_to_micro("1"),
        )
    )
    memo = GoferPolicyEngine.intent_memo("p", 1_700_000_000)
    first = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("1"), memo)
    assert first.ok
    assert accumulator.verify_payment(first.headers).ok
    second = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("1"), memo)
    assert second.ok
    outcome = accumulator.verify_payment(second.headers)
    assert not outcome.ok and "INV-M4" in outcome.reason


def test_emit_challenge_roundtrip() -> None:
    import base64
    import json

    from paythos import PaymentChallenge

    _, accumulator = make_pair(parse_usd_to_micro("0.01"))
    challenge = PaymentChallenge(
        scheme="exact",
        network=TESTNET,
        asset=AR_NATIVE_USDC,
        pay_to=TEST_MERCHANT,
        max="0.01",
        resource="https://m.example.com/data",
    )
    headers = accumulator.emit_challenge(challenge)
    decoded = json.loads(base64.b64decode(headers["payment-required"]))
    assert decoded["x402Version"] == 2
    assert decoded["payTo"] == TEST_MERCHANT
    assert decoded["memoRequired"] is False


def test_flush_plan_fires_at_six_dollars() -> None:
    plans: list[object] = []

    async def on_flush(plan):  # type: ignore[no-untyped-def]
        plans.append(plan)

    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )
    accumulator = VoucherAccumulator(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            authorized_agents={signer.agent_key.lower()},
            credit_tolerance_micro=parse_usd_to_micro("10"),
            on_flush_ready=on_flush,
        )
    )
    memo = GoferPolicyEngine.intent_memo("p", 1_700_000_000)

    async def scenario() -> None:
        first = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("3"), memo)
        assert first.ok
        accumulator.verify_payment(first.headers)
        second = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("2"), memo)
        assert second.ok
        assert accumulator.verify_payment(second.headers).ok
        await asyncio.sleep(0)  # let the scheduled flush task run

    asyncio.run(scenario())
    assert len(plans) == 1
    assert plans[0].voucher.cumulative_amount == parse_usd_to_micro("5")  # type: ignore[attr-defined]
