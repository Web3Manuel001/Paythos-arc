from __future__ import annotations

import re

import pytest

from paythos import AgentVoucherSigner, SigningDomainArgs, domain_for, format_micro_usd, parse_usd_to_micro
from paythos.signer import recover_voucher_signer

from conftest import AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeral_private_key


def make_signer() -> AgentVoucherSigner:
    return AgentVoucherSigner(
        private_key=ephemeral_private_key(),
        domain=SigningDomainArgs(network=TESTNET, vault_address=TEST_VAULT),
    )


def test_signs_cumulative_voucher_recoverable_to_agent() -> None:
    signer = make_signer()
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.25"), "0x" + "11" * 32)
    assert signed.ok and signed.voucher is not None and signed.signature is not None
    recovered = recover_voucher_signer(signer.domain, signed.voucher, signed.signature)
    assert recovered == signer.agent_key.lower()


def test_ledger_only_advances_after_success_and_never_downward() -> None:
    signer = make_signer()
    bad = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), "garbage")
    assert not bad.ok
    assert signer.ledger_snapshot() == []

    signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), "0x" + "22" * 32)
    signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.10"), "0x" + "33" * 32)
    assert signer.ledger_snapshot()[0].cumulative_amount == parse_usd_to_micro("0.20")

    delta = signer.record_and_sign(TEST_MERCHANT, 0, "0x" + "44" * 32)
    assert not delta.ok


def test_binds_arc_native_usdc_and_expiry() -> None:
    signer = make_signer()
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.01"), "0x" + "55" * 32)
    assert signed.ok and signed.voucher is not None
    assert signed.voucher.token.lower() == AR_NATIVE_USDC.lower()
    assert signed.voucher.valid_until > 0


def test_fails_closed_on_unverified_mainnet() -> None:
    with pytest.raises(Exception, match="not verified"):
        domain_for(SigningDomainArgs(network="arc:mainnet", vault_address=TEST_VAULT))


def test_headers_carry_base64_voucher_and_signature() -> None:
    import base64
    import json

    signer = make_signer()
    signed = signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.05"), "0x" + "66" * 32)
    assert signed.ok
    payload = json.loads(base64.b64decode(signed.headers["x-paythos-voucher"]))
    assert payload["cumulativeAmount"] == "50000"
    assert signed.headers["x-paythos-signature"].startswith("0x")


def test_micro_usdc_roundtrip() -> None:
    micro = parse_usd_to_micro("3.141592")
    assert micro == 3_141_592
    assert format_micro_usd(micro) == "3.141592"
    assert format_micro_usd(parse_usd_to_micro("25")) == "25"


def test_reset_merchant_clears_ledger() -> None:
    signer = make_signer()
    signer.record_and_sign(TEST_MERCHANT, parse_usd_to_micro("0.5"), "0x" + "77" * 32)
    signer.reset_merchant(TEST_MERCHANT)
    assert signer.ledger_snapshot() == []
