"""
Circle Discovery API ingestion + Transactability union firewall
(docs/CIRCLE-INTEGRATION.md §2.1–2.2).

Circle curates and sanctions-screens the catalog; Paythos re-gates it through
the Transactability Index. A listing is offered to an agent only when at least
one of its ``accepts`` entries pays a merchant that passes the Paythos
counterparty check. Paythos never re-lists — it re-gates.

Endpoint: GET https://api.circle.com/v2/x402/discovery/resources (keyless).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode

import httpx

from .errors import PaythosError
from .policy_engine import PolicyEvaluatedFailure

CIRCLE_DISCOVERY_URL = "https://api.circle.com/v2/x402/discovery/resources"


@dataclass(frozen=True)
class CircleDiscoveryQuery:
    query: Optional[str] = None
    type: Optional[str] = None
    category: Optional[str] = None
    network: Optional[str] = None
    asset: Optional[str] = None
    scheme: Optional[str] = None
    pay_to: Optional[str] = None
    max_usd_price: Optional[float] = None
    supports_vanilla_x402: Optional[bool] = None
    supports_circle_gateway: Optional[bool] = None
    siwx: Optional[bool] = None
    fields: Optional[str] = None
    limit: Optional[int] = None
    offset: Optional[int] = None


@dataclass(frozen=True)
class DiscoveryResult:
    ok: bool
    listings: list[dict] = field(default_factory=list)
    filtered: int = 0
    pagination: Optional[dict] = None
    error: Optional[PolicyEvaluatedFailure] = None


#: Wire-name mapping (the Circle OpenAPI uses camelCase).
_QUERY_WIRE_NAMES = {
    "query": "query",
    "type": "type",
    "category": "category",
    "network": "network",
    "asset": "asset",
    "scheme": "scheme",
    "pay_to": "payTo",
    "max_usd_price": "maxUsdPrice",
    "supports_vanilla_x402": "supportsVanillax402",
    "supports_circle_gateway": "supportsCircleGateway",
    "siwx": "siwx",
    "fields": "fields",
    "limit": "limit",
    "offset": "offset",
}


def discovery_query_string(query: CircleDiscoveryQuery) -> str:
    """Build the query string without emitting empty/None parameters."""
    params: dict[str, str] = {}
    for attr, wire in _QUERY_WIRE_NAMES.items():
        value = getattr(query, attr)
        if value is None:
            continue
        params[wire] = str(value).lower() if isinstance(value, bool) else str(value)
    encoded = urlencode(params)
    return f"?{encoded}" if encoded else ""


async def query_circle_marketplace(
    query: Optional[CircleDiscoveryQuery] = None,
    *,
    http: Optional[httpx.AsyncClient] = None,
    url: Optional[str] = None,
    transactability: object = None,
) -> DiscoveryResult:
    """Query the Circle Discovery catalog and apply the Paythos union firewall."""
    query = query or CircleDiscoveryQuery()
    endpoint = f"{url or CIRCLE_DISCOVERY_URL}{discovery_query_string(query)}"
    client = http
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(follow_redirects=True)
    try:
        try:
            response = await client.get(endpoint, headers={"accept": "application/json"})
        except httpx.HTTPError as exc:
            return DiscoveryResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="network_error", detail=f"Circle Discovery fetch failed: {exc}"),
            )
        if response.status_code >= 400:
            return DiscoveryResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="network_error", detail=f"Circle Discovery HTTP {response.status_code}"
                ),
            )
        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            return DiscoveryResult(
                ok=False,
                error=PolicyEvaluatedFailure(code="policy_ambiguous", detail="Circle Discovery returned non-JSON"),
            )
        try:
            items, pagination = _assert_discovery_envelope(body)
        except PaythosError as exc:
            return DiscoveryResult(
                ok=False,
                error=PolicyEvaluatedFailure(
                    code="policy_ambiguous", detail=f"malformed Discovery catalog: {exc}"
                ),
            )
    finally:
        if owns_client:
            await client.aclose()

    if transactability is None:
        listings = items
    else:
        approve = getattr(transactability, "approve", None) or transactability
        listings = [item for item in items if _has_approved_accept(item, approve)]
    return DiscoveryResult(
        ok=True,
        listings=listings,
        filtered=len(items) - len(listings),
        pagination=pagination,
    )


def _assert_discovery_envelope(body: object) -> tuple[list[dict], Optional[dict]]:
    if not isinstance(body, dict):
        raise PaythosError("invalid_challenge", "response is not an object")
    if body.get("x402Version") != 2:
        raise PaythosError("invalid_challenge", f"unsupported x402Version {body.get('x402Version')!r}")
    items = body.get("items")
    if not isinstance(items, list):
        raise PaythosError("invalid_challenge", "response.items is not an array")
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("accepts"), list):
            raise PaythosError("invalid_challenge", "listing lacks an accepts[] array")
    pagination = body.get("pagination")
    return items, pagination if isinstance(pagination, dict) else None


def _has_approved_accept(listing: dict, approve: object) -> bool:
    for accept in listing.get("accepts", []):
        if not isinstance(accept, dict):
            continue
        pay_to = accept.get("payTo")
        if not isinstance(pay_to, str) or not pay_to:
            continue
        if approve(pay_to):  # type: ignore[operator]
            return True
    return False


__all__ = [
    "CIRCLE_DISCOVERY_URL",
    "CircleDiscoveryQuery",
    "DiscoveryResult",
    "discovery_query_string",
    "query_circle_marketplace",
]
