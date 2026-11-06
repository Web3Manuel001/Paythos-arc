from __future__ import annotations

import base64
import json

import httpx
import pytest

from paythos import (
    AgentVoucherSigner,
    PaythosClient,
    RequestAttempt,
    SigningDomainArgs,
    decode_challenge,
    parse_max_micro,
    parse_usd_to_micro,
)

from conftest import AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeral_private_key

ALLOWLIST = {TEST_MERCHANT.lower()}


def challenge_payload(max_amount: str) -> dict:
    return {
        "x402Version": 2,
        "scheme": "exact",
        "network": TESTNET,
        "asset": AR_NATIVE_USDC,
        "payTo": TEST_MERCHANT,
        "max": max_amount,
        "resource": "https://api.example.com/premium",
    }


def make_backend(price: str):
    requests: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        requests.append(headers)
        if "payment-signature" not in headers:
            return httpx.Response(
                402,
                headers={
                    "payment-required": base64.b64encode(
                        json.dumps(challenge_payload(price)).encode()
                    ).decode()
                },
            )
        return httpx.Response(200, json={"ok": True, "paid": price})

    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)
    return http, requests


def make_client(http: httpx.AsyncClient, **kwargs) -> tuple[PaythosClient, AgentVoucherSigner]:
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )
    client = PaythosClient(
        signer, network=TESTNET, allowlist=ALLOWLIST, http=http, **kwargs
    )
    return client, signer


@pytest.mark.asyncio
async def test_full_402_lifecycle() -> None:
    http, requests = make_backend("0.25")
    client, signer = make_client(http)
    result = await client.fetch_with_x402(RequestAttempt(url="https://api.example.com/premium", prompt="buy"))
    assert result.ok and result.response is not None
    assert result.response.json()["paid"] == "0.25"
    assert len(requests) == 2
    payment = json.loads(requests[1]["payment-signature"])
    assert payment["voucher"]["cumulativeAmount"] == str(parse_usd_to_micro("0.25"))
    assert payment["signature"].startswith("0x")
    await client.aclose()


@pytest.mark.asyncio
async def test_repeated_purchases_are_cumulative() -> None:
    http, requests = make_backend("0.10")
    client, _ = make_client(http)
    await client.fetch_with_x402(RequestAttempt(url="https://api.example.com/x", prompt="a"))
    await client.fetch_with_x402(RequestAttempt(url="https://api.example.com/x", prompt="b"))
    payments = [
        json.loads(r["payment-signature"])
        for r in requests
        if "payment-signature" in r
    ]
    assert payments[0]["voucher"]["cumulativeAmount"] == "100000"
    assert payments[1]["voucher"]["cumulativeAmount"] == "200000"
    await client.aclose()


@pytest.mark.asyncio
async def test_denies_merchant_outside_allowlist() -> None:
    http, requests = make_backend("0.01")
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )
    client = PaythosClient(
        signer,
        network=TESTNET,
        allowlist={"0x8888888888888888888888888888888888888888"},
        http=http,
    )
    result = await client.fetch_with_x402(RequestAttempt(url="https://api.example.com/x"))
    assert not result.ok and result.error is not None
    assert result.error.code == "policy_failure"
    assert len(requests) == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_tier2_fails_closed_without_human_gate() -> None:
    http, requests = make_backend("5.00")
    client, _ = make_client(http)
    result = await client.fetch_with_x402(RequestAttempt(url="https://api.example.com/x", prompt="big"))
    assert not result.ok and result.error is not None
    assert result.error.code == "human_approval_required"
    assert len(requests) == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_tier2_approves_with_human_gate() -> None:
    http, _ = make_backend("5.00")
    seen: list[dict] = []

    async def gate(summary):
        seen.append(summary)
        return True

    client, _ = make_client(http, approve_with_human=gate)
    result = await client.fetch_with_x402(RequestAttempt(url="https://api.example.com/x", prompt="approved"))
    assert result.ok
    assert seen[0]["amount_usd"] == "5"
    assert seen[0]["kind"] == "tier2_review"
    await client.aclose()


def test_dry_run_moves_no_capital() -> None:
    http, _ = make_backend("0.50")
    client, signer = make_client(http)  # type: ignore[arg-type]
    from paythos import PaymentChallenge

    challenge = PaymentChallenge(**challenge_payload("0.50"))
    report = client.dry_run(challenge)
    assert report.will_succeed
    assert signer.ledger_snapshot() == []


def test_parse_max_micro_forms() -> None:
    from paythos import PaymentChallenge

    assert parse_max_micro(PaymentChallenge(**challenge_payload("0.01"))) == 10_000
    atomic = PaymentChallenge(**challenge_payload("100000"))
    assert parse_max_micro(atomic) == 100_000


def test_decode_challenge_rejects_v1() -> None:
    payload = challenge_payload("0.01")
    payload["x402Version"] = 1
    response = httpx.Response(
        402,
        headers={"payment-required": base64.b64encode(json.dumps(payload).encode()).decode()},
        request=httpx.Request("GET", "https://x"),
    )
    with pytest.raises(Exception, match="unsupported x402Version"):
        decode_challenge(response)
