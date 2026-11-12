"""Math/Core/Types unit tests: agentic payments red team (R4/R5/R6)."""

import asyncio
import base64
import json

import httpx
import pytest
from eth_account import Account

from paythos import (
    AgentVoucherSigner,
    HoldLedger,
    PaythosClient,
    RequestAttempt,
    SigningDomainArgs,
    StreamHooks,
    format_micro_usd,
    metering_canonical,
    parse_metering_report,
    parse_usd_to_micro,
    recover_metering_signer,
    sign_metering_report,
    stream_id_for,
)
from paythos.metering import MeteringReport

from conftest import AR_NATIVE_USDC, TEST_VAULT, TESTNET, ephemeral_private_key

MERCHANT_ACCT = Account.from_key(ephemeral_private_key())
MERCHANT = MERCHANT_ACCT.address.lower()


def upto_challenge(max_amount: str) -> dict:
    return {
        "x402Version": 2,
        "scheme": "upto",
        "network": TESTNET,
        "asset": AR_NATIVE_USDC,
        "payTo": MERCHANT,
        "max": max_amount,
        "resource": "https://m.example.com/stream",
    }


def challenge_response(challenge: dict) -> httpx.Response:
    encoded = base64.b64encode(json.dumps(challenge).encode()).decode()
    return httpx.Response(402, headers={"payment-required": encoded}, text="payment required")


def make_client(handler, **options):
    transport = httpx.MockTransport(handler)
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
        epoch=1,
    )
    client = PaythosClient(
        signer,
        network=TESTNET,
        allowlist={MERCHANT},
        http=httpx.AsyncClient(transport=transport),
        **options,
    )
    return client, signer


async def run_stream(handler, hooks=None, prompt="yopo test", close_on_return=True, **options):
    transport = httpx.MockTransport(handler)
    signer = AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
        epoch=1,
    )
    client = PaythosClient(
        signer,
        network=TESTNET,
        allowlist={MERCHANT},
        http=httpx.AsyncClient(transport=transport),
        **options,
    )
    result = await client.stream_with_x402(
        RequestAttempt(url="https://m.example.com/stream", prompt=prompt),
        hooks or StreamHooks(),
    )
    if close_on_return:
        await client.aclose()
    return client, signer, result


def failing_handler_factory(challenge, response_parts):
    state = {"phase": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            pytest.fail("completion call must never fire on a failed stream")
        state["phase"] += 1
        if state["phase"] == 1:
            return challenge_response(challenge)
        if state["phase"] == 2:
            async def stream():
                for part in response_parts:
                    yield part.encode()
            return httpx.Response(200, content=stream())
        pytest.fail("unexpected extra request")

    return handler


def metered_terminal(account: Account, consumed: str):
    """Build a terminal metering frame bound to the actual client stream id."""

    def build(stream_id: str) -> str:
        report = sign_metering_report(
            account,
            MeteringReport(
                scheme="upto", units="USD", stream_id=stream_id, consumed=consumed, signature=""
            ),
        )
        return json.dumps(
            {
                "scheme": "upto",
                "units": "USD",
                "streamId": report.stream_id,
                "consumed": report.consumed,
                "signature": report.signature,
            }
        )

    return build


def completion_handler_factory(challenge, terminal_line, collected, chunks=None):
    """challenge first, stream second, completion third (recorded in `collected`)."""
    state = {"phase": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            collected.append(
                {
                    "stream_header": request.headers.get("x-paythos-stream"),
                    "body": request.content.decode(),
                    "envelope": json.loads(request.headers["payment-signature"]),
                }
            )
            return httpx.Response(200, json={"settled": True})
        state["phase"] += 1
        if state["phase"] == 1:
            return challenge_response(challenge)
        if state["phase"] == 2:
            payload = chunks or ["data with ", "no payment\n$(TERMINAL)\n"]
            stream_id = request.headers.get("x-paythos-stream", "")
            line = terminal_line(stream_id) if callable(terminal_line) else terminal_line

            async def stream():
                for piece in payload:
                    yield piece.replace("$(TERMINAL)", line).encode()
            return httpx.Response(200, content=stream())
        pytest.fail("unexpected extra request")

    return handler


# ---------------------------------------------------------------------------
# HoldLedger unit invariants
# ---------------------------------------------------------------------------


def test_hold_ledger_lock_settle_lifecycle():
    ledger = HoldLedger()
    sid = stream_id_for("https://x", "p", 1)
    ledger.lock(sid, MERCHANT, 10_000)
    assert ledger.active_hold_micro(MERCHANT) == 10_000
    assert ledger.active_hold_micro("0x0000000000000000000000000000000000000001") == 0
    ledger.settle(sid, 3_400)
    entry = ledger.get(sid)
    assert entry is not None and entry.state == "settled" and entry.settled_micro == 3_400
    assert ledger.active_hold_micro(MERCHANT) == 0  # settled holds free the budget


def test_hold_ledger_release_is_yopo_and_idempotent():
    ledger = HoldLedger()
    sid = stream_id_for("https://x", "p", 2)
    ledger.lock(sid, MERCHANT, 10_000)
    ledger.release(sid)
    assert ledger.get(sid).state == "released"
    assert ledger.active_hold_micro() == 0
    ledger.release(sid)  # idempotent
    assert ledger.get(sid).state == "released"


def test_hold_ledger_refuses_bad_operations():
    ledger = HoldLedger()
    sid = stream_id_for("https://x", "p", 3)
    with pytest.raises(ValueError, match="positive"):
        ledger.lock(sid, MERCHANT, 0)
    ledger.lock(sid, MERCHANT, 5_000)
    with pytest.raises(ValueError, match="already active"):
        ledger.lock(sid, MERCHANT, 5_000)
    with pytest.raises(ValueError, match="unknown hold"):
        ledger.settle("0xunknown", 1)
    ledger.settle(sid, 2_000)
    with pytest.raises(ValueError, match="already settled"):
        ledger.settle(sid, 2_000)


def test_stream_id_deterministic_and_distinct():
    assert stream_id_for("a", "b", 1) == stream_id_for("a", "b", 1)
    assert stream_id_for("a", "b", 1) != stream_id_for("a", "b", 2)


# ---------------------------------------------------------------------------
# Metering attestation
# ---------------------------------------------------------------------------


def test_metering_sign_recover_round_trip():
    report = MeteringReport(
        scheme="upto", units="USD", stream_id="0xabc", consumed="0.0034", signature=""
    )
    attested = sign_metering_report(MERCHANT_ACCT, report)
    assert recover_metering_signer(attested) == MERCHANT


def test_metering_canonical_stable():
    report = MeteringReport(
        scheme="upto", units="USD", stream_id="s", consumed="0.1", signature=""
    )
    assert metering_canonical(report) == "upto|s|0.1|USD"
    acc = sign_metering_report(MERCHANT_ACCT, report)
    acc = MeteringReport(scheme="upto", units="USD", stream_id="s", consumed="9.9", signature=acc.signature)
    assert recover_metering_signer(acc) != MERCHANT


def test_metering_rejects_malformed():
    with pytest.raises(Exception, match="must be"):
        recover_metering_signer(
            MeteringReport(scheme="exact", units="USD", stream_id="s", consumed="1", signature="0x" + "11" * 65)
        )
    with pytest.raises(Exception, match="65-byte"):
        recover_metering_signer(
            MeteringReport(scheme="upto", units="USD", stream_id="s", consumed="1", signature="not-a-sig")
        )
    assert parse_metering_report('{"metering": {"scheme": "upto", "units": "USD", "streamId": "s", "consumed": "1", "signature": "0x' + "11" * 65 + '"}}') is not None
    assert parse_metering_report('{"scheme": "exact"}') is None
    assert parse_metering_report("plain chunks") is None


# ---------------------------------------------------------------------------
# stream_with_x402 — YOPO lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_happy_path_settles_exact_voucher():
    completions: list[dict] = []
    handler = completion_handler_factory(
        upto_challenge("0.01"),
        metered_terminal(MERCHANT_ACCT, "0.0034"),
        completions,
        chunks=["hello ", "streamed ", "world\n$(TERMINAL)\n"],
    )
    observed: list[str] = []
    client, signer, result = await run_stream(
        handler, hooks=StreamHooks(on_chunk=lambda _d, acc: observed.append(acc))
    )

    assert result.ok is True
    assert result.consumed_micro == 3400
    assert result.consumed_usd == format_micro_usd(3400)
    assert result.voucher is not None and result.voucher.cumulative_amount == 3400  # EXACT, not the ceiling
    assert signer.ledger_snapshot() and signer.ledger_snapshot()[0].cumulative_amount == 3400
    assert observed[0] == "hello " and observed[1] == "hello streamed " and observed[2].startswith("hello streamed world\n")
    assert client.holds.get(result.stream_id).state == "settled"
    assert len(completions) == 1
    completion = completions[0]
    assert completion["envelope"]["voucher"]["cumulativeAmount"] == "3400"
    assert completion["stream_header"] == result.stream_id
    assert json.loads(completion["body"])["streamId"] == result.stream_id


@pytest.mark.asyncio
async def test_stream_break_releases_and_signs_nothing():
    state = {"phase": 0}

    async def broken_stream():
        yield b"partial "
        raise httpx.RemoteProtocolError("socket reset")

    def wrap(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            pytest.fail("completion must never fire after a break")
        state["phase"] += 1
        if state["phase"] == 1:
            return challenge_response(upto_challenge("0.01"))
        return httpx.Response(200, content=broken_stream())

    client, signer, result = await run_stream(wrap)
    assert result.ok is False
    assert result.error.code == "network_error"
    assert result.hold_state == "released"
    assert signer.ledger_snapshot() == []
    assert client.holds.active_hold_micro() == 0


@pytest.mark.asyncio
async def test_stream_without_metering_frame_released_unpaid():
    handler = failing_handler_factory(upto_challenge("0.01"), ["payload with no metering trailer\n"])
    client, signer, result = await run_stream(handler)
    assert result.ok is False
    assert result.error.code == "policy_ambiguous"
    assert result.hold_state == "released"
    assert signer.ledger_snapshot() == []


@pytest.mark.asyncio
async def test_stream_attestation_by_intruder_refused():
    intruder = Account.from_key(ephemeral_private_key())
    completions: list[dict] = []
    handler = completion_handler_factory(
        upto_challenge("0.01"), metered_terminal(intruder, "0.009"), completions
    )
    client, signer, result = await run_stream(handler)
    assert result.ok is False
    assert result.error.code == "policy_ambiguous"
    assert result.hold_state == "released"
    assert signer.ledger_snapshot() == []


@pytest.mark.asyncio
async def test_stream_over_ceiling_refused():
    completions: list[dict] = []
    handler = completion_handler_factory(
        upto_challenge("0.01"), metered_terminal(MERCHANT_ACCT, "0.02"), completions
    )
    client, signer, result = await run_stream(handler)
    assert result.ok is False
    assert result.error.code == "policy_failure"
    assert result.hold_state == "released"
    assert signer.ledger_snapshot() == []


@pytest.mark.asyncio
async def test_stream_zero_consumed_released_unpaid():
    completions: list[dict] = []
    handler = completion_handler_factory(
        upto_challenge("0.01"), metered_terminal(MERCHANT_ACCT, "0"), completions
    )
    client, signer, result = await run_stream(handler)
    assert result.ok is False
    assert result.hold_state == "released"
    assert signer.ledger_snapshot() == []


@pytest.mark.asyncio
async def test_stream_exact_scheme_routes_to_fetch_path():
    completions: list[dict] = []
    handler = completion_handler_factory({**upto_challenge("0.01"), "scheme": "exact"}, "", completions)
    client, signer, result = await run_stream(handler)
    assert result.ok is False
    assert result.error.code == "policy_ambiguous"
    assert result.hold_state == "unset"
    assert signer.ledger_snapshot() == []
    assert completions == []


@pytest.mark.asyncio
async def test_stream_insufficient_allowance_pre_lock():
    client, signer, result = await run_stream(
        failing_handler_factory(upto_challenge("0.40"), []), allowance_micro=100_000  # $0.10
    )
    assert result.ok is False
    assert "insufficient allowance" in result.error.detail
    assert result.hold_state == "unset"


@pytest.mark.asyncio
async def test_stream_active_holds_consume_budget():
    completions: list[dict] = []
    handler = completion_handler_factory(
        upto_challenge("0.40"), metered_terminal(MERCHANT_ACCT, "0.40"), completions
    )
    client, signer, a = await run_stream(handler, allowance_micro=500_000, close_on_return=False)
    assert a.ok is True
    assert client.holds.active_hold_micro() == 0

    # Active hold injected mid-session: budget shrinks to $0.10 — $0.20 ceiling refused.
    manual = stream_id_for("manual", "m", 1)
    client.holds.lock(manual, MERCHANT, 400_000)
    handler2 = failing_handler_factory(upto_challenge("0.20"), [])
    await client._http.aclose()  # swap in a fresh transport so C gets its own script
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler2))
    c = await client.stream_with_x402(RequestAttempt(url="https://m.example.com/stream", prompt="session C"))
    await client.aclose()
    assert c.ok is False
    assert "insufficient allowance" in c.error.detail
    assert c.hold_state == "unset"
    assert manual in (h.stream_id for h in client.holds.snapshot())


@pytest.mark.asyncio
async def test_stream_rejects_replayed_metering_report():
    """Reviewer N2: an attestation for stream A must not settle stream B."""
    completions: list[dict] = []
    a = await run_stream(
        completion_handler_factory(
            upto_challenge("0.01"), metered_terminal(MERCHANT_ACCT, "0.001"), completions
        ),
        prompt="stream A",
    )
    assert a[2].ok is True

    stale = sign_metering_report(
        MERCHANT_ACCT,
        MeteringReport(scheme="upto", units="USD", stream_id="stale-stream-A", consumed="0.001", signature=""),
    )
    terminal = json.dumps(
        {
            "scheme": "upto",
            "units": "USD",
            "streamId": stale.stream_id,
            "consumed": stale.consumed,
            "signature": stale.signature,
        }
    )
    client, signer, b = await run_stream(
        completion_handler_factory(upto_challenge("0.01"), terminal, []), prompt="stream B"
    )
    assert b.ok is False
    assert b.error.code == "policy_ambiguous"
    assert "different stream" in b.error.detail
    assert b.hold_state == "released"
    assert len(signer.ledger_snapshot()) == 0


@pytest.mark.asyncio
async def test_concurrent_holds_cannot_exceed_budget_while_approval_pending():
    """Reviewer N3: lock BEFORE awaiting human approval; release on decline."""
    approval_calls: list[dict] = []
    release = asyncio.Event()

    async def gate(summary: dict) -> bool:
        approval_calls.append(summary)
        await release.wait()
        return False

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            pytest.fail("no completion may fire when approval is declined")
        return challenge_response(upto_challenge("15.00"))

    client, signer = make_client(handler, allowance_micro=20_000_000, approve_with_human=gate)
    first = asyncio.create_task(
        client.stream_with_x402(RequestAttempt(url="https://m.example.com/stream", prompt="hold A"))
    )
    for _ in range(200):
        if approval_calls:
            break
        await asyncio.sleep(0.001)
    assert approval_calls, "tier-2 approval was never requested"
    assert client.holds.active_hold_micro() == 15_000_000

    second = await client.stream_with_x402(
        RequestAttempt(url="https://m.example.com/stream", prompt="hold B")
    )
    assert second.ok is False
    assert "insufficient allowance" in second.error.detail
    assert client.holds.active_hold_micro() == 15_000_000

    release.set()
    declined = await first
    assert declined.ok is False
    assert declined.hold_state == "released"
    assert client.holds.active_hold_micro() == 0
    assert signer.ledger_snapshot() == []
    await client.aclose()
