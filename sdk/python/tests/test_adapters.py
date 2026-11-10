"""Gate-4 Python adapter conformance (docs/ARCHITECTURE.md Module 5).

Both adapters import their host framework lazily; tests inject a minimal
duck-typed stand-in so the shapes CrewAI / LangChain consume are verified
without the heavy optional dependencies.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from paythos import AgentVoucherSigner, SigningDomainArgs
from paythos.adapters import make_crewai_tools, make_langchain_tools
from paythos.client import ExecutedResult
from paythos.types import PolicyEvaluatedFailure

from conftest import TEST_VAULT, TESTNET, ephemeral_private_key


def make_signer() -> AgentVoucherSigner:
    return AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
        epoch=1,
    )


class FakeClient:
    def __init__(self, outcome: ExecutedResult) -> None:
        self.outcome = outcome
        self.calls: list[Any] = []

    async def fetch_with_x402(self, attempt: Any) -> ExecutedResult:
        self.calls.append(attempt)
        return self.outcome


class FakeStructuredTool:
    def __init__(self, *, name: str, description: str, func: Any, coroutine: Any = None, args_schema: Any = None) -> None:
        self.name = name
        self.description = description
        self.func = func
        self.coroutine = coroutine
        self.args_schema = args_schema


class FakeBaseTool:
    def _run(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - overridden
        raise NotImplementedError


def test_langchain_tools_shapes_and_execution():
    signer = make_signer()
    client = FakeClient(ExecutedResult(ok=True, response=httpx.Response(200)))
    tools = make_langchain_tools(client, signer, structured_tool=FakeStructuredTool)

    assert [t.name for t in tools] == ["paythos_purchase", "paythos_budget"]
    purchase, budget = tools
    assert callable(purchase.func) and callable(purchase.coroutine)
    assert purchase.args_schema is not None

    paid = json.loads(purchase.func("https://api.example.com/premium", "article"))
    assert paid["status"] == 200
    assert len(client.calls) == 1
    assert client.calls[0].url == "https://api.example.com/premium"
    assert client.calls[0].prompt == "article"

    snapshot = json.loads(budget.func())
    assert snapshot["agentKey"] == signer.agent_key
    assert snapshot["ledger"] == []
    assert snapshot["remainingAllowanceUsd"] == "20"


def test_langchain_denials_surface_as_typed_strings():
    signer = make_signer()
    client = FakeClient(
        ExecutedResult(
            ok=False,
            error=PolicyEvaluatedFailure(code="human_approval_required", detail="tier 2"),
        )
    )
    purchase = make_langchain_tools(client, signer, structured_tool=FakeStructuredTool)[0]
    text = purchase.func("https://api.example.com/premium", "article")
    assert text.startswith("DENIED: human_approval_required")


def test_crewai_tools_shapes_and_execution():
    signer = make_signer()
    client = FakeClient(ExecutedResult(ok=True, response=httpx.Response(200)))
    tools = make_crewai_tools(client, signer, base_tool=FakeBaseTool)

    assert [t.name for t in tools] == ["paythos_purchase", "paythos_budget"]
    purchase, budget = tools
    assert isinstance(purchase, FakeBaseTool)
    assert "GOFER" in purchase.description

    paid = json.loads(purchase._run("https://api.example.com/premium", "article"))
    assert paid["status"] == 200
    assert client.calls[0].url == "https://api.example.com/premium"

    snapshot = json.loads(budget._run())
    assert snapshot["agentKey"] == signer.agent_key
    assert snapshot["remainingAllowanceUsd"] == "20"
