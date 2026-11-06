"""Typed error routing (AGENTS.md: route errors as typed results, never strings)."""

from __future__ import annotations

from typing import Literal

PaythosErrorCode = Literal[
    "chain_unverified",
    "invalid_challenge",
    "invalid_voucher",
    "policy_failure",
    "rate_limited",
    "network_error",
    "config_missing",
]


class PaythosError(Exception):
    def __init__(self, code: PaythosErrorCode, message: str, detail: object | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.detail = detail
