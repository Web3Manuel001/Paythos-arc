"""
INV-M6 transport throttling parity (docs/PROTOCOL.md §5, Gate-2 acceptance).
A 500-request burst must throttle with 429 + Retry-After at the merchant
boundary — zero backend hits for throttled requests.
"""

from __future__ import annotations

import json
import time

import pytest
from eth_account import Account
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from paythos import (
    AgentVoucherSigner,
    MerchantVerifierConfig,
    SigningDomainArgs,
    VoucherAccumulator,
    paythos_fastapi_middleware,
)
from paythos.rate_limit import TokenBucket
from paythos.signer import build_voucher_headers

from conftest import AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeral_private_key

BURST = 500
CAPACITY = 20
REFILL = 1.0


def make_signer(epoch: int = 1) -> AgentVoucherSigner:
    return AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
        epoch=epoch,
    )


def signed_burst_headers(signer: AgentVoucherSigner) -> list[dict[str, str]]:
    headers: list[dict[str, str]] = []
    cumulative = 0
    for _ in range(BURST):
        cumulative += 1_000
        signed = signer.record_and_sign(TEST_MERCHANT, cumulative, "0x" + "11" * 32)
        assert signed.ok and signed.voucher is not None and signed.signature is not None
        headers.append(
            {
                "payment-signature": json.dumps(
                    {
                        "voucher": {
                            "agentKey": signed.voucher.agent_key,
                            "merchant": signed.voucher.merchant,
                            "token": signed.voucher.token,
                            "cumulativeAmount": str(signed.voucher.cumulative_amount),
                            "validUntil": str(signed.voucher.valid_until),
                            "epoch": str(signed.voucher.epoch),
                            "memo": signed.voucher.memo,
                        },
                        "signature": signed.signature,
                    }
                )
            }
        )
    return headers


def accumulator_for(signer: AgentVoucherSigner) -> VoucherAccumulator:
    return VoucherAccumulator(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            authorized_agents={signer.agent_key.lower(): signer.epoch},
            rate_limit=(CAPACITY, REFILL),
        )
    )


def test_token_bucket_rejects_fail_open_configuration():
    with pytest.raises(ValueError):
        TokenBucket(capacity=0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=10, refill_per_second=0)


def test_500_memory_verifications_throttle_with_429():
    signer = make_signer()
    headers = signed_burst_headers(signer)
    accumulator = accumulator_for(signer)

    started = time.time()
    outcomes = [accumulator.verify_payment(h) for h in headers]
    elapsed = time.time() - started

    throttled = [o for o in outcomes if o.status == 429]
    allowed = [o for o in outcomes if o.status != 429]
    assert len(throttled) >= BURST - CAPACITY - 10
    assert len(allowed) <= CAPACITY + 10
    for outcome in throttled:
        assert outcome.ok is False
        assert "rate limit" in outcome.reason
        assert outcome.retry_after_seconds is not None and outcome.retry_after_seconds > 0
        assert outcome.retry_after_seconds <= 2  # 1 token / 1 per second
    assert elapsed < 2.0  # burst lands inside the 2s window


def test_throttled_requests_never_consume_merchant_state():
    signer = make_signer()
    headers = signed_burst_headers(signer)
    accumulator = accumulator_for(signer)
    backend_hits = sum(1 for h in headers if accumulator.verify_payment(h).status == 200)
    assert backend_hits <= CAPACITY + 10
    assert accumulator.highest(signer.agent_key) is not None


def test_throttling_is_per_agent():
    noisy = make_signer()
    quiet = make_signer()
    headers = signed_burst_headers(noisy)
    accumulator = VoucherAccumulator(
        MerchantVerifierConfig(
            network=TESTNET,
            vault_address=TEST_VAULT,
            settlement_token=AR_NATIVE_USDC,
            authorized_agents={
                noisy.agent_key.lower(): noisy.epoch,
                quiet.agent_key.lower(): quiet.epoch,
            },
            rate_limit=(CAPACITY, REFILL),
        )
    )
    for h in headers:
        accumulator.verify_payment(h)
    assert accumulator.verify_payment(headers[0]).status == 429

    quiet_signed = quiet.record_and_sign(TEST_MERCHANT, 1_000, "0x" + "22" * 32)
    assert quiet_signed.ok
    assert quiet_signed.voucher is not None and quiet_signed.signature is not None
    quiet_headers = build_voucher_headers(quiet_signed.voucher, quiet_signed.signature)
    assert accumulator.verify_payment(quiet_headers).status == 200


def test_unknown_agent_flood_returns_402_without_allocating_buckets():
    authorized = make_signer()
    stranger = make_signer()  # valid keypair, NOT in authorized_agents
    headers = signed_burst_headers(stranger)
    accumulator = accumulator_for(authorized)

    statuses = [accumulator.verify_payment(h).status for h in headers]
    assert all(status == 402 for status in statuses)
    assert 429 not in statuses  # no bucket allocated for unknown keys


async def test_fastapi_mount_returns_429_with_retry_after():
    signer = make_signer()
    headers = signed_burst_headers(signer)
    config = MerchantVerifierConfig(
        network=TESTNET,
        vault_address=TEST_VAULT,
        settlement_token=AR_NATIVE_USDC,
        authorized_agents={signer.agent_key.lower(): signer.epoch},
        rate_limit=(CAPACITY, REFILL),
    )
    middleware_cls, accumulator = paythos_fastapi_middleware(config)
    backend_hits = 0

    app = FastAPI()
    app.add_middleware(middleware_cls)

    @app.get("/paid")
    async def paid():  # type: ignore[no-untyped-def]
        nonlocal backend_hits
        backend_hits += 1
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        responses = [await http.get("/paid", headers=h) for h in headers[:100]]

    statuses = [r.status_code for r in responses]
    throttled = [r for r in responses if r.status_code == 429]
    assert len(throttled) >= 100 - CAPACITY - 10
    assert backend_hits <= CAPACITY + 10
    for response in throttled:
        retry_after = response.headers.get("retry-after")
        assert retry_after is not None and retry_after.isdigit()
        assert int(retry_after) >= 1
        assert "payment-required" not in response.headers  # no re-challenge on throttle
    assert statuses.count(200) <= CAPACITY + 10
