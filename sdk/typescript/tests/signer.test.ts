import { describe, expect, it } from "vitest";
import { verifyTypedData, formatEther } from "ethers";
import { AgentVoucherSigner, VOUCHER_TYPES, domainFor } from "../src/signer/voucherSigner.js";
import { parseUsdToMicro, formatMicroUsd } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";

function makeSigner(): AgentVoucherSigner {
  return new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
  });
}

describe("AgentVoucherSigner", () => {
  it("signs a cumulative voucher that recovers to the agent address", async () => {
    const signer = makeSigner();
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.25"), "0x" + "11".repeat(32));
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;
    const recovered = verifyTypedData(
      domainFor({ network: TESTNET, vaultAddress: TEST_VAULT }),
      VOUCHER_TYPES,
      {
        agentKey: signed.voucher.agentKey,
        merchant: signed.voucher.merchant,
        token: signed.voucher.token,
        cumulativeAmount: signed.voucher.cumulativeAmount,
        validUntil: signed.voucher.validUntil,
        memo: signed.voucher.memo,
      },
      signed.signature,
    );
    expect(recovered).toBe(signer.agentKey);
  });

  it("ledger only advances after a successful sign and never downward", async () => {
    const signer = makeSigner();
    const bad = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "garbage");
    expect(bad.ok).toBe(false);
    expect(signer.ledgerSnapshot()).toHaveLength(0); // failed sign → zero side effects

    await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "22".repeat(32));
    await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "33".repeat(32));
    const entry = signer.ledgerSnapshot()[0]!;
    expect(entry.cumulativeAmount).toBe(parseUsdToMicro("0.20"));

    const delta = await signer.recordAndSign(TEST_MERCHANT, 0n, "0x" + "44".repeat(32));
    expect(delta.ok).toBe(false);
  });

  it("binds the Arc native-USDC precompile as voucher token (testnet registry)", async () => {
    const signer = makeSigner();
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.01"), "0x" + "55".repeat(32));
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;
    expect(signed.voucher.token.toLowerCase()).toBe("0x3600000000000000000000000000000000000000");
  });

  it("fails closed on the unverified arc:mainnet chain id (PROTOCOL-OPEN-Q1)", () => {
    expect(() => domainFor({ network: "arc:mainnet", vaultAddress: TEST_VAULT })).toThrow(/not verified/);
  });

  it("resetMerchant clears the session ledger for the merchant", async () => {
    const signer = makeSigner();
    await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.5"), "0x" + "66".repeat(32));
    signer.resetMerchant(TEST_MERCHANT);
    expect(signer.ledgerSnapshot()).toHaveLength(0);
  });
});

describe("micro-USDC conversions", () => {
  it("round-trip", () => {
    const micro = parseUsdToMicro("3.141592");
    expect(formatMicroUsd(micro)).toBe("3.141592");
    expect(micro).toBe(3_141_592n);
  });

  it("parses whole-dollar values", () => {
    expect(formatMicroUsd(parseUsdToMicro("25"))).toBe("25");
    expect(formatMicroUsd(0n)).toBe("0");
  });
});
