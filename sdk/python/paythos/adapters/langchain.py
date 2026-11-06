"""LangChain (Python) adapter (docs/ARCHITECTURE.md Module 5).

Builds ``StructuredTool`` instances from a :class:`PaythosClient`. ``langchain_core``
is imported lazily so the core SDK never hard-depends on it.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..client import PaythosClient, RequestAttempt
from ..signer import AgentVoucherSigner
from ..types import format_micro_usd, parse_usd_to_micro


def make_langchain_tools(
    client: PaythosClient,
    signer: AgentVoucherSigner,
    *,
    structured_tool: type | None = None,
) -> list[Any]:
    """Build LangChain tools; ``structured_tool`` defaults to ``langchain_core.tools.StructuredTool``."""
    if structured_tool is None:
        from langchain_core.tools import StructuredTool  # noqa: PLC0415

        structured_tool = StructuredTool

    from pydantic import BaseModel, Field  # noqa: PLC0415

    class PurchaseInput(BaseModel):
        url: str = Field(description="https:// resource URL that returned the x402 challenge")
        prompt: str = Field(
            description="verifiable-intent prompt text; only its hash is stamped into the voucher memo"
        )

    def purchase_sync(url: str, prompt: str) -> str:
        result = asyncio.run(
            client.fetch_with_x402(RequestAttempt(url=url, prompt=prompt))
        )
        if not result.ok:
            err = result.error
            return f"DENIED: {err.code if err else 'policy_failure'} — {err.detail if err else ''}"
        return json.dumps(
            {"status": result.response.status_code if result.response else 0},
            default=str,
        )

    async def purchase_async(url: str, prompt: str) -> str:
        result = await client.fetch_with_x402(RequestAttempt(url=url, prompt=prompt))
        if not result.ok:
            err = result.error
            return f"DENIED: {err.code if err else 'policy_failure'} — {err.detail if err else ''}"
        return json.dumps(
            {"status": result.response.status_code if result.response else 0},
            default=str,
        )

    def budget() -> str:
        return json.dumps(
            {
                "agentKey": signer.agent_key,
                "ledger": [
                    {
                        "merchant": entry.merchant,
                        "sessionTotalUsd": format_micro_usd(entry.cumulative_amount),
                    }
                    for entry in signer.ledger_snapshot()
                ],
                "remainingAllowanceUsd": format_micro_usd(parse_usd_to_micro("20")),
            }
        )

    return [
        structured_tool(
            name="paythos_purchase",
            description=(
                "Execute a x402 purchase through Paythos: GOFER gate → cumulative "
                "EIP-712 voucher → retry. Tier-2 spends fail closed."
            ),
            func=purchase_sync,
            coroutine=purchase_async,
            args_schema=PurchaseInput,
        ),
        structured_tool(
            name="paythos_budget",
            description="Report signer ledger and remaining rolling allowance.",
            func=budget,
        ),
    ]
