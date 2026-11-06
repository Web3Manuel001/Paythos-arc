"""Shared helpers for the Paythos Python SDK tests."""

from __future__ import annotations

import os

TESTNET = "eip155:5042002"
TEST_VAULT = "0xa9d5525BE440831c64695d30c915DF303E0151EF"
AR_NATIVE_USDC = "0x3600000000000000000000000000000000000000"
TEST_MERCHANT = "0x1234567890123456789012345678901234567890"


def ephemeral_private_key() -> str:
    return "0x" + os.urandom(32).hex()
