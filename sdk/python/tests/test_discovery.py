"""
Circle Discovery ingestion + Transactability union firewall
(docs/CIRCLE-INTEGRATION.md §2.1–2.2) — Python parity suite.
"""

from __future__ import annotations

import json

import httpx
import pytest

from paythos import (
    CIRCLE_DISCOVERY_URL,
    CircleDiscoveryQuery,
    MerchantObservation,
    TransactabilityIndex,
    discovery_query_string,
    query_circle_marketplace,
)

MERCHANT_A = "0x1234567890123456789012345678901234567890"
MERCHANT_B = "0x00000000000000000000000000000000000000bb"
MERCHANT_C = "0x00000000000000000000000000000000000000cc"


def _listing(pay_tos: list[str], name: str = "svc") -> dict:
    return {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:5042002",
                "asset": "0x3600000000000000000000000000000000000000",
                "amount": "10000",
                "payTo": pay_to,
            }
            for pay_to in pay_tos
        ],
        "metadata": {"provider": {"name": name, "category": "FINANCIAL_ANALYSIS"}},
    }


def _catalog(items: list[dict], pagination: dict | None = None) -> httpx.Response:
    body: dict = {"x402Version": 2, "items": items}
    if pagination is not None:
        body["pagination"] = pagination
    return httpx.Response(200, json=body)


def _transport(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_query_string_only_defined_parameters():
    assert discovery_query_string(CircleDiscoveryQuery()) == ""
    qs = discovery_query_string(
        CircleDiscoveryQuery(network="eip155:5042002", max_usd_price=0.01, limit=10)
    )
    assert qs == "?network=eip155%3A5042002&maxUsdPrice=0.01&limit=10"
    qs = discovery_query_string(CircleDiscoveryQuery(supports_circle_gateway=True))
    assert qs == "?supportsCircleGateway=true"


async def test_returns_catalog_untouched_without_oracle():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _catalog([_listing([MERCHANT_A]), _listing([MERCHANT_B]), _listing([MERCHANT_C])])

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http)
    assert result.ok is True
    assert len(result.listings) == 3
    assert result.filtered == 0
    assert str(requests[0].url).startswith(CIRCLE_DISCOVERY_URL)


async def test_passes_query_through_to_endpoint():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _catalog([])

    async with _transport(handler) as http:
        await query_circle_marketplace(
            CircleDiscoveryQuery(network="eip155:5042002", category="FINANCIAL_ANALYSIS", limit=5),
            http=http,
        )
    url = str(requests[0].url)
    assert "network=eip155%3A5042002" in url
    assert "category=FINANCIAL_ANALYSIS" in url
    assert "limit=5" in url
    assert "query=" not in url


async def test_supports_ci_mock_url():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _catalog([])

    async with _transport(handler) as http:
        await query_circle_marketplace(
            CircleDiscoveryQuery(query="weather"), http=http, url="https://mock.test/catalog"
        )
    assert str(requests[0].url) == "https://mock.test/catalog?query=weather"


async def test_pagination_passes_through():
    def handler(request: httpx.Request) -> httpx.Response:
        return _catalog([], {"total": 636, "limit": 1, "offset": 0})

    async with _transport(handler) as http:
        result = await query_circle_marketplace(CircleDiscoveryQuery(limit=1), http=http)
    assert result.ok is True
    assert result.pagination == {"total": 636, "limit": 1, "offset": 0}


async def test_union_firewall_drops_blocked_listings():
    items = [
        _listing([MERCHANT_A], "keep"),
        _listing([MERCHANT_B], "drop"),
        _listing([MERCHANT_B, MERCHANT_C], "rescue"),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return _catalog(items)

    oracle = lambda m: m.lower() != MERCHANT_B  # noqa: E731
    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http, transactability=oracle)
    assert result.ok is True
    assert len(result.listings) == 2
    assert result.filtered == 1
    names = [item["metadata"]["provider"]["name"] for item in result.listings]
    assert names == ["keep", "rescue"]


async def test_pay_then_fail_merchant_disappears():
    index = TransactabilityIndex()
    for _ in range(4):
        index.record(MERCHANT_B, MerchantObservation(ok=True, latency_ms=0, status=200, valid=False))

    def handler(request: httpx.Request) -> httpx.Response:
        return _catalog([_listing([MERCHANT_B]), _listing([MERCHANT_A])])

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http, transactability=index)
    assert result.ok is True
    assert result.filtered == 1
    assert result.listings[0]["accepts"][0]["payTo"] == MERCHANT_A


async def test_empty_pay_to_never_passes():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return _catalog([_listing([""])])

    def oracle(merchant: str) -> bool:
        calls.append(merchant)
        return True

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http, transactability=oracle)
    assert result.ok is True
    assert result.listings == []
    assert calls == []


async def test_non_200_is_typed_network_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="nope")

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http)
    assert result.ok is False
    assert result.error.code == "network_error"
    assert "502" in result.error.detail


async def test_transport_error_is_typed():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("ECONNREFUSED")

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http)
    assert result.ok is False
    assert result.error.code == "network_error"
    assert "ECONNREFUSED" in result.error.detail


async def test_non_json_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>")

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http)
    assert result.ok is False
    assert result.error.code == "policy_ambiguous"


async def test_wrong_version_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"x402Version": 1, "items": []})

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http)
    assert result.ok is False
    assert "x402Version" in result.error.detail


async def test_listing_without_accepts_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"x402Version": 2, "items": [{"metadata": {}}]})

    async with _transport(handler) as http:
        result = await query_circle_marketplace(http=http)
    assert result.ok is False
    assert "accepts" in result.error.detail
