"""
Transactability Index parity suite (ARCHITECTURE Module 4.2, SECURITY §3).
Measured merchant health: uptime · validity · latency · 5xx rate.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from paythos import (
    AgentVoucherSigner,
    DEFAULT_TRANSACTABILITY_CONFIG,
    InMemoryTransactabilityRegistry,
    MerchantObservation,
    PaythosClient,
    RequestAttempt,
    SigningDomainArgs,
    TransactabilityConfig,
    TransactabilityIndex,
    is_transactability_index,
)

from conftest import AR_NATIVE_USDC, TEST_VAULT, TESTNET, ephemeral_private_key

MERCHANT = "0x1234567890123456789012345678901234567890"  # TEST_MERCHANT
HEALTHY = MerchantObservation(ok=True, latency_ms=0, status=200, valid=True)


def test_fail_closed_configuration():
    from paythos.transactability import TransactabilityConfig, TransactabilityIndex

    with pytest.raises(ValueError):
        TransactabilityIndex(config=TransactabilityConfig(latency_budget_ms=0))
    with pytest.raises(ValueError):
        TransactabilityIndex(config=TransactabilityConfig(window_size=0))
    with pytest.raises(ValueError):
        TransactabilityIndex(config=TransactabilityConfig(min_samples=0))


def test_all_healthy_scores_100_and_allows():
    index = TransactabilityIndex()
    for _ in range(5):
        index.record(MERCHANT, HEALTHY)
    score = index.score(MERCHANT)
    assert score.score == 100
    assert score.verdict == "allow"
    assert score.source == "local"
    assert index.approve(MERCHANT) is True


def test_pay_then_fail_hits_validity_floor_and_blocks():
    index = TransactabilityIndex()
    for _ in range(4):
        index.record(MERCHANT, MerchantObservation(ok=True, latency_ms=50, status=200, valid=False))
    score = index.score(MERCHANT)
    assert score.validity == 0
    assert score.verdict == "block"
    assert index.approve(MERCHANT) is False


def test_mixed_history_downgrades_but_still_allows():
    index = TransactabilityIndex()
    for _ in range(3):
        index.record(MERCHANT, HEALTHY)
    for _ in range(3):
        index.record(MERCHANT, MerchantObservation(ok=False, latency_ms=50, valid=False))
    score = index.score(MERCHANT)
    assert score.samples == 6
    assert score.uptime == pytest.approx(0.5)
    assert score.verdict == "downgrade"
    assert index.approve(MERCHANT) is True


def test_five_xx_rate_drives_score_down():
    index = TransactabilityIndex()
    for _ in range(2):
        index.record(MERCHANT, HEALTHY)
    for _ in range(2):
        index.record(MERCHANT, MerchantObservation(ok=False, latency_ms=50, status=503, valid=False))
    score = index.score(MERCHANT)
    assert score.error_rate_5xx == pytest.approx(0.5)
    assert score.verdict == "downgrade"


def test_rolling_window_only():
    index = TransactabilityIndex(config=TransactabilityConfig(window_size=2))
    for _ in range(10):
        index.record(MERCHANT, MerchantObservation(ok=False, latency_ms=10, valid=False))
    index.record(MERCHANT, HEALTHY)
    index.record(MERCHANT, HEALTHY)
    score = index.score(MERCHANT)
    assert score.samples == 2
    assert score.score == 100
    assert score.verdict == "allow"


def test_latency_beyond_budget_zeroes_only_latency_component():
    index = TransactabilityIndex()
    for _ in range(4):
        index.record(MERCHANT, MerchantObservation(ok=True, latency_ms=10_000, status=200, valid=True))
    score = index.score(MERCHANT)
    assert score.latency_ms == 10_000
    assert score.score == 80
    assert score.verdict == "allow"


def test_unknown_merchants_allow_by_default():
    index = TransactabilityIndex()
    score = index.score("0x00000000000000000000000000000000000000aa")
    assert score.source == "empty"
    assert score.verdict == "allow"


def test_unknown_merchants_block_when_configured():
    index = TransactabilityIndex(config=TransactabilityConfig(unknown_verdict="block"))
    assert index.approve("0x00000000000000000000000000000000000000aa") is False


def test_registry_seeds_unknown_merchant():
    registry = InMemoryTransactabilityRegistry()
    from paythos import TransactabilityAttestation

    registry.publish(
        TransactabilityAttestation(
            merchant=MERCHANT,
            score=30,
            uptime=0.3,
            validity=0.2,
            latency_ms=900,
            error_rate_5xx=0.4,
            samples=10,
            updated_at=0.0,
        )
    )
    index = TransactabilityIndex(registry=registry)
    score = index.score(MERCHANT)
    assert score.source == "registry"
    assert score.verdict == "block"
    assert index.approve(MERCHANT) is False


def test_recording_publishes_attestations():
    registry = InMemoryTransactabilityRegistry()
    index = TransactabilityIndex(registry=registry)
    index.record(MERCHANT, HEALTHY)
    published = registry.lookup(MERCHANT)
    assert published is not None
    assert published.samples == 1
    assert published.score == 100
    assert len(registry.snapshot()) == 1


def test_local_measurements_take_precedence_over_registry():
    from paythos import TransactabilityAttestation

    registry = InMemoryTransactabilityRegistry()
    registry.publish(
        TransactabilityAttestation(
            merchant=MERCHANT,
            score=10,
            uptime=0.1,
            validity=0.1,
            latency_ms=5_000,
            error_rate_5xx=0.9,
            samples=20,
            updated_at=0.0,
        )
    )
    index = TransactabilityIndex(registry=registry)
    index.record(MERCHANT, HEALTHY)
    score = index.score(MERCHANT)
    assert score.source == "local"
    assert score.verdict == "allow"


def test_is_transactability_index_discriminates():
    assert is_transactability_index(TransactabilityIndex()) is True
    assert is_transactability_index(lambda _m: True) is False
    assert is_transactability_index(None) is False


def test_defaults_match_spec():
    assert DEFAULT_TRANSACTABILITY_CONFIG.window_size == 64
    assert DEFAULT_TRANSACTABILITY_CONFIG.latency_budget_ms == 2_000
    assert DEFAULT_TRANSACTABILITY_CONFIG.downgrade_below == 75
    assert DEFAULT_TRANSACTABILITY_CONFIG.block_below == 50
    assert DEFAULT_TRANSACTABILITY_CONFIG.validity_floor == 0.5
    assert DEFAULT_TRANSACTABILITY_CONFIG.min_samples == 4
    assert DEFAULT_TRANSACTABILITY_CONFIG.unknown_verdict == "allow"


# ---------------------------------------------------------------------------
# Client wiring: unattested streams block the merchant before the next hold
# ---------------------------------------------------------------------------


def _challenge_response() -> httpx.Response:
    payload = {
        "x402Version": 2,
        "scheme": "upto",
        "network": TESTNET,
        "asset": AR_NATIVE_USDC,
        "payTo": MERCHANT,
        "max": "0.01",
        "resource": "https://m.example.com/stream",
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return httpx.Response(402, headers={"payment-required": encoded}, text="payment required")


def _stream_without_metering() -> httpx.Response:
    async def stream():
        yield b"rendered but NO metering trailer\n"

    return httpx.Response(200, content=stream())


async def test_unattested_streams_block_merchant_before_hold():
    index = TransactabilityIndex()
    state = {"phase": 0, "streams": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            pytest.fail("completion must never fire — no metering was attested")
        state["phase"] += 1
        if state["phase"] % 2 == 1:
            return _challenge_response()
        state["streams"] += 1
        return _stream_without_metering()

    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
        epoch=1,
    )
    client = PaythosClient(
        signer,
        network=TESTNET,
        allowlist={MERCHANT},
        transactability=index,
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )

    for i in range(4):
        failed = await client.stream_with_x402(
            RequestAttempt(url="https://m.example.com/stream", prompt=f"p{i}")
        )
        assert failed.ok is False
    assert index.score(MERCHANT).verdict == "block"

    blocked = await client.stream_with_x402(
        RequestAttempt(url="https://m.example.com/stream", prompt="p-final")
    )
    await client.aclose()
    assert blocked.ok is False
    assert "Transactability Index" in blocked.error.detail
    assert blocked.hold_state == "unset"
    assert state["streams"] == 4  # the blocked attempt never opened a stream
    assert client.holds.active_hold_micro() == 0


async def test_fresh_index_allows_before_traffic():
    index = TransactabilityIndex()
    assert index.approve(MERCHANT) is True
    assert index.score(MERCHANT).source == "empty"
