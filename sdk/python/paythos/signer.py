"""
AgentVoucherSigner (docs/ARCHITECTURE.md Module 2.1).
EIP-712 cumulative voucher signing, fully in-memory, zero gas, <5ms target.
The ledger is monotonic per merchant — INV-1 is enforced CLIENT-SIDE here and
BACKED by the vault contract. Ledger state never farms downward.
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Literal

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

from .errors import PaythosError
from .types import (
    CHAIN_REGISTRY,
    X_PAYTHOS_SIGNATURE_HEADER,
    X_PAYTHOS_VOUCHER_HEADER,
    LedgerEntry,
    PaythosNetwork,
    Voucher,
)

VOUCHER_TYPES: dict[str, list[dict[str, str]]] = {
    "Voucher": [
        {"name": "agentKey", "type": "address"},
        {"name": "merchant", "type": "address"},
        {"name": "token", "type": "address"},
        {"name": "cumulativeAmount", "type": "uint256"},
        {"name": "validUntil", "type": "uint256"},
        {"name": "memo", "type": "bytes32"},
    ],
}

EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

_MEMO_RE = re.compile(r"^0x[0-9a-f]{64}$", re.IGNORECASE)


@dataclass(frozen=True)
class SigningDomainArgs:
    network: PaythosNetwork
    vault_address: str
    #: Only for tests or explicit chain-ID overrides (fail-closed by default).
    chain_id_override: int | None = None


@dataclass(frozen=True)
class VoucherSigned:
    ok: bool
    voucher: Voucher | None = None
    signature: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    error: dict[str, str] | None = None


def domain_for(args: SigningDomainArgs) -> dict[str, object]:
    """Build the ``Paythos Protocol`` v2 EIP-712 domain, fail-closed on unverified chains."""
    entry = CHAIN_REGISTRY[args.network]
    if not entry.verified or entry.chain_id is None:
        # PROTOCOL-OPEN-Q1: fail closed on unverified chains (AGENTS.md rule 3).
        raise PaythosError("chain_unverified", f"chain {args.network} not verified in registry")
    if args.chain_id_override is not None and entry.chain_id != args.chain_id_override:
        raise PaythosError(
            "chain_unverified",
            f"chainIdOverride {args.chain_id_override} disagrees with registry",
        )
    return {
        "name": "Paythos Protocol",
        "version": "2",
        "chainId": entry.chain_id,
        "verifyingContract": to_checksum_address(args.vault_address),
    }


def _settlement_token_for_chain(chain_id: int) -> str | None:
    for entry in CHAIN_REGISTRY.values():
        if entry.chain_id == chain_id and entry.verified:
            return entry.native_usdc
    return None


class AgentVoucherSigner:
    def __init__(
        self,
        *,
        private_key: str,
        domain: SigningDomainArgs,
        voucher_ttl_seconds: int = 3600,
        ledger: dict[str, LedgerEntry] | None = None,
    ) -> None:
        #: Ephemeral key from PAYTHOS_EPHEMERAL_KEY (AGENTS.md secrets hygiene).
        self._account = Account.from_key(private_key)
        self._ledger: dict[str, LedgerEntry] = ledger if ledger is not None else {}
        self._ttl = voucher_ttl_seconds
        self._domain = domain_for(domain)

    @property
    def agent_key(self) -> str:
        return to_checksum_address(self._account.address)

    @property
    def domain(self) -> dict[str, object]:
        return dict(self._domain)

    def rebind(self, domain: SigningDomainArgs) -> None:
        """(Re)bind the EIP-712 domain after e.g. a vault redeploy."""
        self._domain = domain_for(domain)

    def record_and_sign(
        self,
        merchant: str,
        delta_micro: int,
        memo: str,
        valid_until: int | None = None,
    ) -> VoucherSigned:
        """
        Sign the session-total voucher for ``merchant`` covering an ADDITIONAL
        ``delta_micro`` (micro-USDC). INV-1: strictly monotonic, never downward.
        The ledger only advances AFTER a successful sign.
        """
        if delta_micro <= 0:
            return VoucherSigned(
                ok=False,
                error={"code": "policy_ambiguous", "detail": "voucher delta must be positive"},
            )
        if not _MEMO_RE.match(memo):
            return VoucherSigned(
                ok=False,
                error={"code": "policy_ambiguous", "detail": "memo must be bytes32 hex"},
            )
        lower = merchant.lower()
        entry = self._ledger.get(lower)
        now = int(time.time())
        next_total = (entry.cumulative_amount if entry else 0) + delta_micro
        token = _settlement_token_for_chain(int(self._domain["chainId"]))  # type: ignore[arg-type]
        if token is None:
            return VoucherSigned(
                ok=False,
                error={
                    "code": "policy_ambiguous",
                    "detail": "no verified settlement token for the bound chain",
                },
            )
        voucher = Voucher(
            agent_key=self.agent_key,
            merchant=to_checksum_address(merchant),
            token=token,
            cumulative_amount=next_total,
            valid_until=valid_until if valid_until is not None else now + self._ttl,
            memo=memo,
        )
        try:
            signature = sign_voucher(self._account, self._domain, voucher)
        except Exception as exc:  # noqa: BLE001 — signing failures map to typed results
            return VoucherSigned(
                ok=False,
                error={"code": "policy_ambiguous", "detail": f"signing failed: {exc}"},
            )
        self._ledger[lower] = LedgerEntry(
            merchant=to_checksum_address(merchant),
            cumulative_amount=next_total,
            last_signed_at=time.time(),
        )
        return VoucherSigned(
            ok=True,
            voucher=voucher,
            signature=signature,
            headers=build_voucher_headers(voucher, signature),
        )

    def reset_merchant(self, merchant: str) -> None:
        """Mark a merchant's ledger settled (post-flush); the next claim starts fresh."""
        self._ledger.pop(merchant.lower(), None)

    def ledger_snapshot(self) -> list[LedgerEntry]:
        return list(self._ledger.values())


def typed_data_message(domain: dict[str, object], voucher: Voucher) -> dict[str, object]:
    """The full eth-account ``full_message`` object for encode/recover/sign."""
    return {
        "types": {
            "EIP712Domain": EIP712_DOMAIN_TYPE,
            "Voucher": VOUCHER_TYPES["Voucher"],
        },
        "primaryType": "Voucher",
        "domain": domain,
        "message": {
            "agentKey": voucher.agent_key,
            "merchant": voucher.merchant,
            "token": voucher.token,
            "cumulativeAmount": voucher.cumulative_amount,
            "validUntil": voucher.valid_until,
            "memo": voucher.memo,
        },
    }


def sign_voucher(account: Account, domain: dict[str, object], voucher: Voucher) -> str:
    full = typed_data_message(domain, voucher)
    signed = Account.sign_typed_data(account.key, full_message=full)
    signature = signed.signature
    sig_hex = signature.hex() if not isinstance(signature, str) else signature
    return sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"


def build_voucher_headers(voucher: Voucher, signature: str) -> dict[str, str]:
    """Wire headers (docs/PROTOCOL.md §1.3) — base64 JSON voucher + hex signature."""
    payload = base64.b64encode(
        json.dumps(
            {
                "agentKey": voucher.agent_key,
                "merchant": voucher.merchant,
                "token": voucher.token,
                "cumulativeAmount": str(voucher.cumulative_amount),
                "validUntil": str(voucher.valid_until),
                "memo": voucher.memo,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    return {
        X_PAYTHOS_VOUCHER_HEADER: payload,
        X_PAYTHOS_SIGNATURE_HEADER: signature,
    }


def recover_voucher_signer(domain: dict[str, object], voucher: Voucher, signature: str) -> str:
    """Recover the EIP-712 signer address (merchant-side, memory only)."""
    full = typed_data_message(domain, voucher)
    encoded = encode_typed_data(full_message=full)
    recovered = Account.recover_message(encoded, signature=signature)
    return recovered.lower()


__all__ = [
    "VOUCHER_TYPES",
    "EIP712_DOMAIN_TYPE",
    "SigningDomainArgs",
    "VoucherSigned",
    "AgentVoucherSigner",
    "domain_for",
    "sign_voucher",
    "build_voucher_headers",
    "recover_voucher_signer",
    "Literal",
]
