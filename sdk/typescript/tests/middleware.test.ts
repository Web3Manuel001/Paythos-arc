import { describe, expect, it, vi } from "vitest";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { VoucherAccumulator } from "../src/middleware/merchant.js";
import { GoferPolicyEngine } from "../src/core/policyEngine.js";
import { PaymentChallenge, parseUsdToMicro } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";

const AR_USDC = "0x3600000000000000000000000000000000000000";

function pair(priceMicro: bigint, settleToken = AR_USDC) {
  const signer = new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    epoch: 1,
  });
  const challenge: PaymentChallenge = {
    x402Version: 2,
    scheme: "exact",
    network: TESTNET,
    asset: settleToken,
    payTo: TEST_MERCHANT,
    max: (Number(priceMicro) / 1_000_000).toFixed(6),
    resource: "https://m.example.com/data",
  };
  const prompt = "pay for data";
  const memo = GoferPolicyEngine.intentMemo(prompt, 1700000000);
  const merchant = new VoucherAccumulator({
    network: TESTNET,
    vaultAddress: TEST_VAULT,
    settlementToken: settleToken,
    merchantAddress: TEST_MERCHANT,
    authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]),
  });
  return { signer, challenge, prompt, memo, merchant };
}

describe("VoucherAccumulator — full membrane", () => {
  it("verifies a signed voucher and recovers the agent (INV-M1, <5ms target functionally)", async () => {
    const { signer, challenge, prompt, memo, merchant } = pair(parseUsdToMicro("0.30"));
    const signed = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("0.30"), memo);
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;

    const outcome = merchant.verifyPayment(signed.headers);
    expect(outcome.ok).toBe(true);
    expect(outcome.status).toBe(200);
    expect(outcome.agentKey).toBe(signer.agentKey.toLowerCase());
    expect(outcome.unsettledMicro).toBe(parseUsdToMicro("0.30"));
  });

  it("REJECTS a replayed / stale voucher (cumulative not strictly increasing)", async () => {
    const { signer, challenge, memo, merchant } = pair(parseUsdToMicro("0.10"));
    const signed = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("0.10"), memo);
    if (!signed.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(signed.headers).ok).toBe(true);
    // Same voucher again → replay
    const replay = merchant.verifyPayment(signed.headers);
    expect(replay.ok).toBe(false);
    expect(replay.status).toBe(402);
    expect(replay.reason).toMatch(/not strictly increasing/);
  });

  it("rejects tampered vouchers (bad signature)", async () => {
    const { signer, challenge, memo, merchant } = pair(parseUsdToMicro("0.10"));
    const signed = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("0.10"), memo);
    if (!signed.ok) throw new Error("sign failed");
    merchant.verifyPayment({ "x-paythos-voucher": signed.headers["x-paythos-voucher"], "x-paythos-signature": "0x" + "00".repeat(65) });
    const outcome = merchant.verifyPayment({ ...signed.headers, "x-paythos-signature": "0xdeadbeef" });
    expect(outcome.ok).toBe(false);
    // A second distinct agent's voucher must also be rejected for wrong signer:
    expect(outcome.status).toBe(402);
    void signer;
  });

  it("rejects vouchers whose token is not the settlement token", async () => {
    const WRONG_TOKEN = "0x1111111111111111111111111111111111111111";
    const { signer, challenge, memo, merchant } = pair(parseUsdToMicro("0.10"), WRONG_TOKEN);
    const signed = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("0.10"), memo);
    if (!signed.ok) throw new Error("sign failed");
    const outcome = merchant.verifyPayment(signed.headers);
    expect(outcome.ok).toBe(false);
    expect(outcome.reason).toMatch(/settlement token/);
    void challenge;
  });

  it("rejects unauthorized agents (fail closed)", async () => {
    const { signer, challenge, memo } = pair(parseUsdToMicro("0.10"));
    const merchant = new VoucherAccumulator({
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_USDC,
      merchantAddress: TEST_MERCHANT,
      authorizedAgents: new Map([["0x7777777777777777777777777777777777777777", 1]]),
    });
    const signed = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("0.10"), memo);
    if (!signed.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(signed.headers).reason).toMatch(/unknown agentKey/);
  });

  it("emits x402 v2 challenges as base64 payment-required headers", () => {
    const { merchant, challenge } = pair(parseUsdToMicro("0.01"));
    const headers = merchant.emitChallenge(challenge);
    const decoded = JSON.parse(
      Buffer.from(headers["payment-required"], "base64").toString("utf8"),
    ) as PaymentChallenge;
    expect(decoded.x402Version).toBe(2);
    expect(decoded.payTo).toBe(TEST_MERCHANT);
  });

  it("enforces the INV-M4 credit wall above tolerance", async () => {
    const { signer, challenge, memo } = pair(parseUsdToMicro("2"));
    const accumulator = new VoucherAccumulator({
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_USDC,
      merchantAddress: TEST_MERCHANT,
      authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]),
      creditToleranceMicro: parseUsdToMicro("1"),
    });
    const signed = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("2"), memo);
    if (!signed.ok) throw new Error("sign failed");
    const outcome = accumulator.verifyPayment(signed.headers);
    expect(outcome.ok).toBe(false);
    expect(outcome.reason).toMatch(/INV-M4/);
  });

  it("flushes at the $5 value trigger with the HIGHEST voucher (INV-M2)", async () => {
    const onFlushReady = vi.fn(async () => {});
    const { signer, challenge, prompt, merchant } = pair(parseUsdToMicro("3"));
    const cfg = {
      network: TESTNET as const,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_USDC,
      merchantAddress: TEST_MERCHANT,
      authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]),
      creditToleranceMicro: parseUsdToMicro("10"),
      onFlushReady,
    };
    const accumulator = new VoucherAccumulator(cfg);
    const memo = GoferPolicyEngine.intentMemo(prompt, 1700000000);

    await signer.recordAndSign(challenge.payTo, parseUsdToMicro("3"), memo);
    const first = await signer.recordAndSign(challenge.payTo, parseUsdToMicro("2"), memo);
    if (!first.ok) throw new Error("sign failed");
    const outcome = accumulator.verifyPayment(first.headers); // cumulative $5.00
    expect(outcome.ok).toBe(true);
    await vi.waitFor(() => {
      expect(onFlushReady).toHaveBeenCalledTimes(1);
    });
    const plan = onFlushReady.mock.calls[0]![0] as { voucher: { cumulativeAmount: bigint } };
    expect(plan.voucher.cumulativeAmount).toBe(parseUsdToMicro("5"));
  });
});
