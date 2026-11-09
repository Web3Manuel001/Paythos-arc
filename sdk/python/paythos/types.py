"""
Paythos Protocol — canonical Python types (docs/PROTOCOL.md is the source of truth).
TypeScript mirror: sdk/typescript/src/types.ts — keep both in 1:1 lockstep.
AGENTS.md: all amounts are atomic micro-USDC (USDC = 6 decimals).

IMPORTANT — chain registry lockstep (PROTOCOL OPEN-Q1):
``arc:mainnet`` chain-ID is UNVERIFIED; the SDK refuses it until resolved.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

PaythosNetwork = Literal["eip155:5042002", "arc:mainnet"]

#: Arc Testnet native-USDC precompile (verified by the prior demo deploy).
ARC_TESTNET_USDC = "0x3600000000000000000000000000000000000000"
ARC_TESTNET_CHAIN_ID = 5_042_002

MICRO_USDC_DECIMALS = 6

PAYMENT_REQUIRED_HEADER = "payment-required"
PAYMENT_SIGNATURE_HEADER = "payment-signature"
X_PAYTHOS_VOUCHER_HEADER = "x-paythos-voucher"
X_PAYTHOS_SIGNATURE_HEADER = "x-paythos-signature"


class ChainRegistryEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    network: PaythosNetwork
    chain_id: int | None  # None = UNVERIFIED (fail closed)
    native_usdc: str | None  # None = UNVERIFIED
    verified: bool


CHAIN_REGISTRY: dict[PaythosNetwork, ChainRegistryEntry] = {
    "eip155:5042002": ChainRegistryEntry(
        network="eip155:5042002",
        chain_id=ARC_TESTNET_CHAIN_ID,
        native_usdc=ARC_TESTNET_USDC,
        verified=True,
    ),
    "arc:mainnet": ChainRegistryEntry(
        network="arc:mainnet",
        # docs.arc.io: Arc mainnet chain ID = 5042 (0x13b2), RPC https://rpc.mainnet.arc.io
        chain_id=5042,
        # Mainnet USDC address still unverified → remain fail closed (PROTOCOL-OPEN-Q1).
        native_usdc=None,
        verified=False,
    ),
}


class Voucher(BaseModel):
    """EIP-712 voucher (docs/PROTOCOL.md §1.1). ALWAYS cumulative."""

    model_config = ConfigDict(frozen=True)

    agent_key: str
    merchant: str
    token: str
    cumulative_amount: int = Field(ge=0)
    valid_until: int = Field(ge=0)  # unix seconds
    #: Delegation epoch (INV-6, PROTOCOL v3): binds the voucher to one
    #: authorizeAgent generation; vault reverts on mismatch.
    epoch: int = Field(ge=1)
    memo: str  # bytes32 hex ("0x" + 64 chars)


class Policy(BaseModel):
    """Per-ephemeral-key policy (docs/PROTOCOL.md §2)."""

    daily_limit: int
    max_per_tx: int
    expires_at: int


class PaymentChallenge(BaseModel):
    """x402 v2 challenge carried in the base64 ``PAYMENT-REQUIRED`` header."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel)

    x402_version: Literal[2] = 2
    scheme: Literal["exact", "upto"]
    network: PaythosNetwork
    asset: str
    pay_to: str
    max: str  # decimal USDC string, e.g. "0.01"
    resource: str
    description: str | None = None
    mime_type: str | None = None
    memo_required: bool = False


class PolicyEvaluatedFailure(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: Literal[
        "daily_limit_exceeded",
        "max_per_tx_exceeded",
        "policy_ambiguous",
        "policy_failure",
        "invalid_voucher",
        "network_error",
        "unauthorized_merchant",
        "counterparty_blocked",
        "session_expired",
        "human_approval_required",
        "rate_limited",
    ]
    detail: str


class PreFlightReport(BaseModel):
    will_succeed: bool
    reason: str
    remaining_allowance_micro: int
    requires_human_approval: bool
    tier: Literal[1, 2, 3] | None


class LedgerEntry(BaseModel):
    merchant: str
    cumulative_amount: int
    last_signed_at: float


def parse_usd_to_micro(amount: str) -> int:
    """Parse a decimal USDC string ("0.01" | "3.4") into atomic micro units."""
    import re

    if not re.fullmatch(r"\d+(\.\d{1,6})?", amount):
        raise ValueError(f"invalid USDC amount: {amount}")
    whole, _, frac = amount.partition(".")
    padded = (frac + "000000")[:MICRO_USDC_DECIMALS]
    return int(whole + padded)


def format_micro_usd(micro: int) -> str:
    """Format atomic micro-USDC back into a decimal string."""
    neg = micro < 0
    abs_micro = -micro if neg else micro
    whole, frac = divmod(abs_micro, 1_000_000)
    frac_str = f"{frac:06d}".rstrip("0")
    body = str(whole) if frac_str == "" else f"{whole}.{frac_str}"
    return f"-{body}" if neg else body
