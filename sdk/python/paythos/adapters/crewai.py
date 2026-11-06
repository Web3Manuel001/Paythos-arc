"""CrewAI adapter (docs/ARCHITECTURE.md Module 5).

Emits CrewAI-style tools backed by :class:`PaythosClient`. Imported lazily so
the core SDK never hard-depends on ``crewai``.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from ..client import PaythosClient, RequestAttempt
from ..signer import AgentVoucherSigner
from ..types import format_micro_usd, parse_usd_to_micro


def make_crewai_tools(
    client: PaythosClient,
    signer: AgentVoucherSigner,
    *,
    base_tool: type | None = None,
) -> list[Any]:
    """Build CrewAI tools. ``base_tool`` defaults to ``crewai.tools.BaseTool``."""
    if base_tool is None:
        from crewai.tools import BaseTool  # noqa: PLC0415 — lazy optional dep

        base_tool = BaseTool

    def _purchase(url: str, prompt: str) -> str:
        import asyncio  # noqa: PLC0415

        result = asyncio.run(
            client.fetch_with_x402(RequestAttempt(url=url, prompt=prompt))
        )
        if not result.ok:
            err = result.error
            return f"DENIED: {err.code if err else 'policy_failure'} — {err.detail if err else ''}"
        return json.dumps(
            {
                "status": result.response.status_code if result.response else 0,
                "voucher": result.voucher.model_dump() if result.voucher else None,  # type: ignore[union-attr]
            },
            default=str,
        )

    class PaythosPurchaseTool(base_tool):  # type: ignore[misc, valid-type]
        name: str = "paythos_purchase"
        description: str = (
            "Execute a x402 purchase through Paythos: GOFER gate → cumulative "
            "EIP-712 voucher → retry. Tier-2 spends fail closed without a human gate."
        )

        def _run(self, url: str, prompt: str) -> str:
            return _purchase(url, prompt)

    class PaythosBudgetTool(base_tool):  # type: ignore[misc, valid-type]
        name: str = "paythos_budget"
        description: str = "Report signer ledger and remaining rolling allowance."

        def _run(self) -> str:
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

    return [PaythosPurchaseTool(), PaythosBudgetTool()]
