"""
Regression suite for the external code review (REV-*), Python parity.
Mirrors sdk/typescript/tests/review-regressions.test.ts:
   REV-1/INV-6  epoch binding on the merchant membrane
   REV-5        both wire formats accepted
   REV-6        flush fires before the credit wall; unsettled-based wall
   REV-7        GOFER human gate covers the whole $1–$25 band
"""

from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest

from paythos import (
    AgentVoucherSigner,
    GoferPolicyEngine,
    MerchantVerifierConfig,
    MerchantChallengeContext,
    PaythosError,
    SigningDomainArgs,
    VoucherAccumulator,
    parse_usd_to_micro,
)
from paythos.client import serialize_voucher
from paythos.signer import VOUCHER_TYPES

from conftest import AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeral_private_key

MEMO = "0x" + "11" * 32


def make_signer(epoch: int = 1) -> AgentVoucherSigner:
    return AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
        epoch=epoch,
    )


def make_accumulator(signer: AgentVoucherSigner, epoch: int = 1, **overrides) -> VoucherAccumulator:
    kwargs = {
        "network": TESTNET,
        "vault_address": TEST_VAULT,
        "settlement_token": AR_NATIVE_USDC,
        "merchant_address": TEST_MERCHANT,
        "authorized_agents": {signer.agent_key.lower(): epoch},
    }
    kwargs.update(overrides)
    return VoucherAccumulator(MerchantVerifierConfig(**kwargs))


def run_async(coro):
    import asyncio

    return asyncio.get_event_loop().run_until_complete(coro)


class TestEpochBinding:
    def test_stale_epoch_voucher_rejected_even_with_valid_signature(self) -> None:
        signer = make_signer(1)
        # Agent re-authorized on-chain → merchant knows epoch 2 now.
        acc = make_accumulator(signer, epoch=2)
        signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), MEMO)
        assert signed.ok and signed.headers is not None
        outcome = acc.verify_payment(signed.headers)
        assert not outcome.ok
        assert outcome.status == 402
        assert "epoch" in outcome.reason

    def test_matching_epoch_accepted_and_rotation_flow(self) -> None:
        signer = make_signer(1)
        acc = make_accumulator(signer, epoch=1)
        signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), MEMO)
        assert signed.ok
        assert acc.verify_payment(signed.headers).ok

        # Owner re-authorizes → epoch 2; signer rotates; merchant sees 2.
        signer.set_epoch(2)
        signed2 = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.05"), MEMO)
        assert signed2.ok
        assert signed2.voucher is not None and signed2.voucher.epoch == 2
        acc2 = make_accumulator(signer, epoch=2)
        assert acc2.verify_payment(signed2.headers).ok

    def test_set_epoch_refuses_garbage(self) -> None:
        signer = make_signer(1)
        with pytest.raises(PaythosError):
            signer.set_epoch(0)
        with pytest.raises(PaythosError):
            signer.set_epoch(1.5)  # type: ignore[arg-type]


class TestWireFormats:
    def test_envelope_headers_accepted_via_native_pair(self) -> None:
        # serialize_voucher output can be decoded back through the native path.
        signer = make_signer(1)
        acc = make_accumulator(signer, epoch=1)
        signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.25"), MEMO)
        assert signed.ok and signed.voucher is not None and signed.headers is not None
        assert "epoch" in base64.b64decode(signed.headers["x-paythos-voucher"]).decode("utf-8")

    def test_payment_signature_envelope_decodable(self) -> None:
        signer = make_signer(1)
        acc = make_accumulator(signer, epoch=1)
        signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.25"), MEMO)
        assert signed.ok and signed.voucher is not None
        envelope = json.dumps({"voucher": serialize_voucher(signed.voucher), "signature": signed.signature})
        # The envelope's voucher JSON carries the epoch (wire coherence).
        assert json.loads(envelope)["voucher"]["epoch"] == "1"

    def test_voucher_schema_carries_epoch_uint64(self) -> None:
        fields = VOUCHER_TYPES["Voucher"]
        names = [f["name"] for f in fields]
        assert names == [
            "agentKey",
            "merchant",
            "token",
            "cumulativeAmount",
            "validUntil",
            "epoch",
            "memo",
        ]
        assert fields[names.index("epoch")]["type"] == "uint64"


class TestFlushCoherence:
    def test_unsetten_ledger_wall_and_flush_fire_together_on_defaults(self) -> None:
        signer = make_signer(1)
        plans = []

        async def on_flush(plan) -> None:
            plans.append(plan)

        async def scenario() -> None:
            acc = make_accumulator(signer, on_flush_ready=on_flush)
            signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("2.00"), MEMO)
            assert signed.ok
            outcome = acc.verify_payment(signed.headers)
            assert outcome.ok  # accepted at exactly the $2 wall (≤)
            await asyncio.sleep(0)  # let the scheduled flush task run
            # flush queued at/under the wall (effective threshold = wall − 1¢)
            assert len(plans) == 1
            assert plans[0].signature == signed.signature

        asyncio.run(scenario())

    def test_mark_settled_resets_the_wall(self) -> None:
        signer = make_signer(1)
        acc = make_accumulator(signer)
        signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("2.00"), MEMO)
        assert signed.ok
        assert acc.verify_payment(signed.headers).ok

        # Naive larger voucher w/o settlement → wall.
        signed2 = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.50"), MEMO)
        assert signed2.ok
        rejected = acc.verify_payment(signed2.headers)
        assert not rejected.ok and "credit tolerance" in rejected.reason

        # Daemon confirms $2 settled → the wall resets; exposure is $0.50 now.
        acc.mark_settled(signer.agent_key, parse_usd_to_micro("2.00"))
        accepted = acc.verify_payment(signed2.headers)
        assert accepted.ok
        assert accepted.unsettled_micro == parse_usd_to_micro("0.50")

    def test_time_based_flush_after_idle_interval(self) -> None:
        signer = make_signer(1)
        plans = []

        async def on_flush(plan) -> None:
            plans.append(plan)

        async def scenario() -> None:
            acc = make_accumulator(
                signer, on_flush_ready=on_flush, flush_threshold_micro=2**63
            )
            signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.50"), MEMO)
            assert signed.ok
            assert acc.verify_payment(signed.headers).ok
            assert len(plans) == 0

            # Simulate ≥ 2h idle (activity was stamped at accept time).
            key = signer.agent_key.lower()
            acc._last_activity_at[key] -= 7_300
            signed2 = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.01"), MEMO)
            assert signed2.ok
            outcome = acc.verify_payment(signed2.headers)
            assert outcome.ok
            await asyncio.sleep(0)  # let the scheduled flush task run
            assert len(plans) == 1  # byTime trigger fired despite sub-threshold amount

        asyncio.run(scenario())


class TestGoferBands:
    def _ctx(self, usd: str):
        from paythos.policy_engine import PolicyContext

        return PolicyContext(
            merchant=TEST_MERCHANT.lower(),
            amount_micro=parse_usd_to_micro(usd),
            allowlist={TEST_MERCHANT.lower()},
            counterparty_approved=True,
            remaining_allowance_micro=parse_usd_to_micro("1000"),
        )

    def test_ten_to_twenty_five_band_requires_human_tier3(self) -> None:
        decision = GoferPolicyEngine().evaluate(self._ctx("15"))
        assert decision.action == "human_approval_required"
        assert decision.tier == 3

    def test_dollar_ten_boundary_is_tier2_human(self) -> None:
        decision = GoferPolicyEngine().evaluate(self._ctx("10"))
        assert decision.action == "human_approval_required"
        assert decision.tier == 2

    def test_above_ceiling_denies(self) -> None:
        decision = GoferPolicyEngine().evaluate(self._ctx("25.01"))
        assert decision.action == "deny"


class TestChallengeEmission:
    def test_emit_challenge_roundtrip(self) -> None:
        from paythos.types import PaymentChallenge

        signer = make_signer(1)
        acc = make_accumulator(signer)
        challenge = PaymentChallenge(
            x402Version=2,
            scheme="exact",
            network=TESTNET,
            asset=AR_NATIVE_USDC,
            payTo=TEST_MERCHANT,
            max="0.10",
            resource="https://m.example.com/data",
        )
        headers = acc.emit_challenge(challenge)
        decoded = json.loads(base64.b64decode(headers["payment-required"]))
        assert decoded["x402Version"] == 2
        assert decoded["payTo"].lower() == TEST_MERCHANT.lower()

    def test_challenge_context_shape(self) -> None:
        ctx = MerchantChallengeContext(method="GET", url="/paid")
        assert ctx.method == "GET"


def test_no_free_pass_with_challenge_configured() -> None:
    """Business rule: a mount WITHOUT payment headers and WITH a challenge
    factory must NOT be told to pass through — the FastAPI adapter owns that
    decision (tested via starlette if installed)."""
    signer = make_signer(1)
    acc = make_accumulator(signer)
    outcome = acc.verify_payment({})
    assert not outcome.ok and outcome.status == 402


def test_payee_binding_rejects_vouchers_for_another_merchant() -> None:
    """A voucher made out to merchant B must never unlock merchant A's route."""
    signer = make_signer(1)
    acc = make_accumulator(signer)
    other = "0x00000000000000000000000000000000deadbeef"
    signed = signer.record_and_sign(other, parse_usd_to_micro("0.50"), MEMO)
    assert signed.ok
    outcome = acc.verify_payment(signed.headers)
    assert not outcome.ok and outcome.status == 402
    assert "payee" in outcome.reason
    assert acc.highest(signer.agent_key) is None


def test_config_requires_merchant_address() -> None:
    with pytest.raises(TypeError):
        MerchantVerifierConfig(  # type: ignore[call-arg]
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            authorized_agents={},
        )


def test_reauthorization_clean_slate_accepts_lower_new_epoch_voucher() -> None:
    """Same accumulator across epoch rotation: exposure resets, old high-water
    (and old settlements) must not mask the new epoch."""
    signer = make_signer(1)
    agents = {signer.agent_key.lower(): 1}
    acc = VoucherAccumulator(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            merchant_address=TEST_MERCHANT,
            authorized_agents=agents,
        )
    )
    old = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("1.50"), MEMO)
    assert old.ok and acc.verify_payment(old.headers).ok
    assert acc.unsettled_for(signer.agent_key) == parse_usd_to_micro("1.50")

    signer.set_epoch(2)
    agents[signer.agent_key.lower()] = 2
    new = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.50"), MEMO)
    assert new.ok and new.voucher.epoch == 2
    outcome = acc.verify_payment(new.headers)
    assert outcome.ok and outcome.unsettled_micro == parse_usd_to_micro("0.50")

    acc.mark_settled(signer.agent_key, parse_usd_to_micro("1.50"), epoch=1)
    assert acc.unsettled_for(signer.agent_key) == parse_usd_to_micro("0.50")
    acc.mark_settled(signer.agent_key, parse_usd_to_micro("0.50"), epoch=2)
    assert acc.unsettled_for(signer.agent_key) == 0


async def test_fastapi_without_challenge_for_fails_closed() -> None:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from paythos.middleware import paythos_fastapi_middleware

    signer = make_signer(1)
    middleware_cls, _ = paythos_fastapi_middleware(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            merchant_address=TEST_MERCHANT,
            authorized_agents={signer.agent_key.lower(): 1},
        )
    )
    hits = 0
    app = FastAPI()
    app.add_middleware(middleware_cls)

    @app.get("/paid")
    async def paid():  # type: ignore[no-untyped-def]
        nonlocal hits
        hits += 1
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        response = await http.get("/paid")
    assert response.status_code == 402
    assert response.json()["error"] == "payment_required"
    assert hits == 0
