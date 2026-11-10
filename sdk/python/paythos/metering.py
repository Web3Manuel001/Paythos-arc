"""
Metering-report attestation (docs/PROTOCOL.md §4.2). The server's terminal
stream frame is ``MeteringReport`` JSON carrying a signature over the canonical
report bytes. The client verifies the signer recovers to the challenge
``payTo`` destination — a MITM or lying midpoint cannot inflate the bill
without the merchant's key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Protocol

from eth_account import Account
from eth_account.messages import encode_defunct

from .errors import PaythosError


@dataclass(frozen=True)
class MeteringReport:
    scheme: str
    units: str
    stream_id: str
    #: Decimal USDC actually consumed, e.g. "0.0034".
    consumed: str
    #: Merchant attestation over the canonical report bytes (recovery = payTo).
    signature: str


class _CanSign(Protocol):
    def sign_message(self, message: object) -> object: ...


def metering_canonical(report: object) -> str:
    """``scheme|streamId|consumed|units`` — the ONLY bytes ever attested."""
    return (
        f"{report.scheme}|{report.stream_id}|{report.consumed}|{report.units}"  # type: ignore[attr-defined]
    )


def sign_metering_report(account: Account, report: MeteringReport) -> MeteringReport:
    """Merchant-side helper: attest a finished stream (client repair/refund base)."""
    signed = account.sign_message(encode_defunct(text=metering_canonical(report)))
    signature = signed.signature.hex()  # type: ignore[attr-defined]
    return MeteringReport(
        scheme=report.scheme,
        units=report.units,
        stream_id=report.stream_id,
        consumed=report.consumed,
        signature=signature if signature.startswith("0x") else "0x" + signature,
    )


def recover_metering_signer(report: MeteringReport) -> str:
    """Recover the attestation signer; the CALLER compares against ``payTo``."""
    if report.scheme != "upto" or report.units != "USD":
        raise PaythosError("invalid_challenge", 'metering report must be {scheme:"upto", units:"USD"}')
    sig = report.signature or ""
    if not (len(sig) == 132 and sig.startswith("0x")):
        raise PaythosError("invalid_challenge", "metering signature is not a 65-byte hex ECDSA sig")
    if not report.stream_id or not report.consumed:
        raise PaythosError(
            "invalid_challenge",
            f"metering report missing {'streamId' if not report.stream_id else 'consumed'}",
        )
    recovered = Account.recover_message(encode_defunct(text=metering_canonical(report)), signature=sig)
    return recovered.lower()


def parse_metering_report(raw: str) -> Optional[MeteringReport]:
    """Parse a terminal stream chunk into a MeteringReport (``None`` when not metering).

    Accepts either the raw JSON object or one wrapped in ``{ "metering": {...} }``.
    """
    candidate = raw.strip()
    if not candidate.startswith("{"):
        return None
    try:
        parsed = json.loads(candidate)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    inner = parsed.get("metering") if isinstance(parsed.get("metering"), dict) else parsed
    if not isinstance(inner, dict):
        return None
    if inner.get("scheme") != "upto" or inner.get("units") != "USD" or not isinstance(inner.get("signature"), str):
        return None
    return MeteringReport(
        scheme="upto",
        units="USD",
        stream_id=str(inner["streamId"]),
        consumed=str(inner["consumed"]),
        signature=inner["signature"],
    )


__all__ = ["MeteringReport", "metering_canonical", "sign_metering_report", "recover_metering_signer", "parse_metering_report"]
