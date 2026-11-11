/**
 * Regression suite for the external code review (REV-* findings).
 * Each test pins one reviewer-confirmed bug to its fixed behavior:
 *   REV-1  epoch replay across re-authorization      → INV-6 epoch binding
 *   REV-2  fixed window                             → contract-side (SlidingWindow)
 *   REV-3  allowlist survived re-auth               → contract-side (_clearAllowlist)
 *   REV-4  middleware passed traffic through        → 402 challenge gating
 *   REV-5  client/merchant wire mismatch            → both wire formats verified
 *   REV-6  flush unreachable under defaults         → effective threshold ≤ wall
 *   REV-6b resetMerchant produced rejected vouchers → settleMerchant monotonicity
 *   REV-7  GOFER inverted $10–$25 band              → human gate tier 3
 *   REV-15 no end-to-end test                       → client↔express HTTP integration
 */
import { describe, expect, it, vi, afterEach } from "vitest";
import type { AddressInfo } from "node:net";
import express from "express";
import type { Server } from "node:http";
import { AgentVoucherSigner, VOUCHER_TYPES, domainFor } from "../src/signer/voucherSigner.js";
import { VoucherAccumulator } from "../src/middleware/merchant.js";
import { paythosMerchant } from "../src/middleware/express.js";
import { GoferPolicyEngine } from "../src/core/policyEngine.js";
import { PaythosClient, serializeVoucher } from "../src/client/paythosClient.js";
import { PaymentChallenge, parseUsdToMicro, PAYMENT_SIGNATURE_HEADER } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET, AR_NATIVE_USDC, ephemeralPrivateKey } from "./helpers.js";

function makeSigner(epoch = 1): AgentVoucherSigner {
  return new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    epoch,
  });
}

function accumulatorFor(
  signer: AgentVoucherSigner,
  epoch: number,
  extra: Partial<ConstructorParameters<typeof VoucherAccumulator>[0]> = {},
): VoucherAccumulator {
  return new VoucherAccumulator({
    network: TESTNET,
    vaultAddress: TEST_VAULT,
    settlementToken: AR_NATIVE_USDC,
    merchantAddress: TEST_MERCHANT,
    authorizedAgents: new Map([[signer.agentKey.toLowerCase(), epoch]]),
    ...extra,
  });
}

function challenge(max: string): PaymentChallenge {
  return {
    x402Version: 2,
    scheme: "exact",
    network: TESTNET,
    asset: AR_NATIVE_USDC,
    payTo: TEST_MERCHANT,
    max,
    resource: "https://m.example.com/paid",
  };
}

function envelopeHeaders(voucher: unknown, signature: string): Record<string, string> {
  return { [PAYMENT_SIGNATURE_HEADER]: JSON.stringify({ voucher, signature }) };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("REV-1/INV-6 — delegation epoch binding", () => {
  it("rejects a perfectly-signed voucher from a STALE epoch (fail closed)", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 2); // agent re-authorized → epoch bumped
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "11".repeat(32));
    if (!signed.ok) throw new Error("sign failed");

    const outcome = merchant.verifyPayment(signed.headers);
    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe(402);
    expect(outcome.reason).toMatch(/epoch/);
  });

  it("accepts the voucher once the epoch matches the active delegation", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "22".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(signed.headers).ok).toBe(true);
  });

  it("setEpoch rotation (post re-auth) makes the next voucher acceptable", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const first = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.05"), "0x" + "33".repeat(32));
    if (!first.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(first.headers).ok).toBe(true);

    // Owner re-authorizes on-chain → epoch 1 → 2; signer rotates; merchant sees 2.
    signer.setEpoch(2);
    expect(signer.epoch).toBe(2);
    accumulatorFor(signer, 2);
    const merchant2 = accumulatorFor(signer, 2);
    const second = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.06"), "0x" + "44".repeat(32));
    if (!second.ok) throw new Error("sign failed");
    expect(second.voucher.epoch).toBe(2);
    expect(merchant2.verifyPayment(second.headers).ok).toBe(true);
  });

  it("setEpoch refuses garbage (fail closed)", () => {
    const signer = makeSigner(1);
    expect(() => signer.setEpoch(0)).toThrow(/positive integer/);
    expect(() => signer.setEpoch(1.5)).toThrow(/positive integer/);
  });
});

describe("REV-5 — wire-format coherence (both header families)", () => {
  it("verifies the x402 PAYMENT-SIGNATURE JSON envelope the client actually sends", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.25"), "0x" + "55".repeat(32));
    if (!signed.ok) throw new Error("sign failed");

    const outcome = merchant.verifyPayment(envelopeHeaders(serializeVoucher(signed.voucher), signed.signature));
    expect(outcome.ok).toBe(true);
    expect(outcome.agentKey).toBe(signer.agentKey.toLowerCase());
    expect(outcome.unsettledMicro).toBe(parseUsdToMicro("0.25"));
  });

  it("verifies the native x-paythos-voucher/-signature pair too", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.30"), "0x" + "66".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(signed.headers).ok).toBe(true);
  });

  it("rejects a malformed PAYMENT-SIGNATURE envelope (fail closed)", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const outcome = merchant.verifyPayment({ [PAYMENT_SIGNATURE_HEADER]: "{not json" });
    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe(402);
  });

  it("an envelope voucher with a stripped epoch never verifies", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "77".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    const noEpoch = { ...serializeVoucher(signed.voucher) };
    delete (noEpoch as Record<string, unknown>)["epoch"];
    expect(merchant.verifyPayment(envelopeHeaders(noEpoch, signed.signature)).ok).toBe(false);
  });
});

describe("REV-4 — express membrane gates instead of passing through", () => {
  interface RunResult {
    status: number;
    headers: Record<string, string>;
    body: unknown;
    reachedHandler: boolean;
  }

  async function runExpress(
    config: Partial<ConstructorParameters<typeof paythosMerchant>[0]> & { withChallenge: boolean },
    opts: { headers?: Record<string, string> } = {},
  ): Promise<RunResult> {
    const app = express();
    const cfg = {
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_NATIVE_USDC,
      merchantAddress: TEST_MERCHANT,
      authorizedAgents: new Map<string, number>(),
      ...(config.withChallenge
        ? { challengeFor: () => challenge("0.10") }
        : {}),
      ...Object.fromEntries(Object.entries(config).filter(([k]) => k !== "withChallenge")),
    };
    let reachedHandler = false;
    app.get("/paid", paythosMerchant(cfg as never), (_req, res) => {
      reachedHandler = true;
      res.status(200).json({ ok: true });
    });

    const server: Server = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      const port = (server.address() as AddressInfo).port;
      const res = await fetch(`http://127.0.0.1:${port}/paid`, { headers: opts.headers ?? {} });
      const text = await res.text();
      let body: unknown = undefined;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return { status: res.status, headers, body, reachedHandler };
    } finally {
      await new Promise((r) => server.close(r));
    }
  }

  it("no payment headers + challengeFor → 402 with an x402 challenge (NOT a free pass)", async () => {
    const result = await runExpress({ withChallenge: true });
    expect(result.status).toBe(402);
    expect(result.reachedHandler).toBe(false);
    expect(result.headers["payment-required"]).toBeDefined();
    expect(result.headers["accept-payment"]).toBe("PAYTHOS/x402v2");
    const challengeB64 = Buffer.from(result.headers["payment-required"], "base64").toString("utf8");
    const decoded = JSON.parse(challengeB64) as PaymentChallenge;
    expect(decoded.x402Version).toBe(2);
    expect(decoded.payTo.toLowerCase()).toBe(TEST_MERCHANT.toLowerCase());
    expect((result.body as { error: string }).error).toBe("payment_required");
  });

  it("no payment headers + legacy mount (no challengeFor) fails closed — never a free pass", async () => {
    const result = await runExpress({ withChallenge: false });
    expect(result.status).toBe(402);
    expect(result.reachedHandler).toBe(false);
    expect((result.body as { error: string }).error).toBe("payment_required");
    expect(result.headers["payment-required"]).toBeUndefined(); // cannot price the route
  });

  it("valid native payment headers reach the handler with req.paythos pinned", async () => {
    const signer = makeSigner(1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "88".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    const result = await runExpress(
      { withChallenge: false, authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]) },
      { headers: signed.headers },
    );
    expect(result.status).toBe(200);
    expect(result.reachedHandler).toBe(true);
  });

  it("tampered signature → 402 + re-challenge (never 500, never 200)", async () => {
    const signer = makeSigner(1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "99".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    const tampered = { ...signed.headers, "x-paythos-signature": "0x" + "ab".repeat(65) };
    const result = await runExpress(
      { withChallenge: true, authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]) },
      { headers: tampered },
    );
    expect(result.status).toBe(402);
    expect(result.reachedHandler).toBe(false);
    expect(result.headers["payment-required"]).toBeDefined();
  });

describe("REV-8 — payee binding + epoch-scoped merchant ledger (reviewer 2026-11)", () => {
  it("rejects a voucher made out to a DIFFERENT merchant (never unlocks this payee)", async () => {
    const signer = makeSigner(1);
    const merchant = accumulatorFor(signer, 1);
    const otherMerchant = "0x00000000000000000000000000000000deadbeef";
    const signed = await signer.recordAndSign(otherMerchant, parseUsdToMicro("0.50"), "0x" + "b1".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    const outcome = merchant.verifyPayment(signed.headers);
    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe(402);
    expect(outcome.reason).toMatch(/payee/);
    expect(merchant.highest(signer.agentKey)).toBeUndefined();
  });

  it("refuses to construct without a valid merchantAddress (fail closed)", () => {
    const signer = makeSigner(1);
    expect(
      () =>
        new VoucherAccumulator({
          network: TESTNET,
          vaultAddress: TEST_VAULT,
          settlementToken: AR_NATIVE_USDC,
          authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]),
        } as never),
    ).toThrow(/merchantAddress/);
  });

  it("re-authorization clean slate: lower new-epoch voucher is accepted and exposure resets", async () => {
    const signer = makeSigner(1);
    const agents = new Map([[signer.agentKey.toLowerCase(), 1]]);
    const plans: unknown[] = [];
    const merchant = new VoucherAccumulator({
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_NATIVE_USDC,
      merchantAddress: TEST_MERCHANT,
      authorizedAgents: agents,
      flushThresholdMicro: 400_000n,
      onFlushReady: async (plan) => {
        plans.push(plan);
      },
    });
    const oldEpoch = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("1.50"), "0x" + "b2".repeat(32));
    if (!oldEpoch.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(oldEpoch.headers).ok).toBe(true);
    expect(merchant.unsettledFor(signer.agentKey)).toBe(parseUsdToMicro("1.50"));

    // Owner re-authorizes on-chain (epoch 1 → 2): active map rotates and the
    // signer's ledger resets. The SAME accumulator must accept the lower value.
    signer.setEpoch(2);
    agents.set(signer.agentKey.toLowerCase(), 2);
    const newEpoch = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.50"), "0x" + "b3".repeat(32));
    if (!newEpoch.ok) throw new Error("sign failed");
    expect(newEpoch.voucher.epoch).toBe(2);
    const outcome = merchant.verifyPayment(newEpoch.headers);
    expect(outcome.ok).toBe(true);
    expect(outcome.unsettledMicro).toBe(parseUsdToMicro("0.50"));

    // A late settlement report from the superseded epoch must not mask it.
    merchant.markSettled(signer.agentKey, parseUsdToMicro("1.50"), 1);
    expect(merchant.unsettledFor(signer.agentKey)).toBe(parseUsdToMicro("0.50"));
    // Settling the live epoch clears exposure; the flush plan carries epoch 2.
    merchant.markSettled(signer.agentKey, parseUsdToMicro("0.50"), 2);
    expect(merchant.unsettledFor(signer.agentKey)).toBe(0n);
    expect((plans.at(-1) as { voucher: { epoch: number } }).voucher.epoch).toBe(2);
  });
});
});

describe("REV-6 — flush fires before the credit wall traps the session", () => {
  it("on DEFAULTS ($2 wall, $5 threshold) a $2 voucher both passes the wall and queues a flush", async () => {
    const signer = makeSigner(1);
    const plans: unknown[] = [];
    const merchant = accumulatorFor(signer, 1, {
      onFlushReady: async (plan) => {
        plans.push(plan);
      },
    });
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("2.00"), "0x" + "a1".repeat(32));
    if (!signed.ok) throw new Error("sign failed");

    const outcome = merchant.verifyPayment(signed.headers); // default config: no overrides
    expect(outcome.ok).toBe(true); // accepted at exactly the wall (≤)
    expect(plans).toHaveLength(1); // flush queued at/under the wall, never after it
  });

  it("the effective flush threshold can never exceed the wall minus 1¢", async () => {
    const signer = makeSigner(1);
    const plans: unknown[] = [];
    const merchant = accumulatorFor(signer, 1, {
      flushThresholdMicro: 5_000_000n, // explicitly-wanted $5 flush
      onFlushReady: async (plan) => {
        plans.push(plan);
      },
    });
    // $1.99: under both configured $5 and under the effective min($5, wall−1¢)
    const a = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("1.99"), "0x" + "a2".repeat(32));
    if (!a.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(a.headers).ok).toBe(true);
    expect(plans).toHaveLength(0); // below effective threshold (1.999999) — no premature flush

    // Crosses the effective min($5, wall−1¢) = 1.999999 threshold, still under the wall.
    const b = await signer.recordAndSign(TEST_MERCHANT, 9_999n, "0x" + "a3".repeat(32)); // 1.99 → 1.999999
    if (!b.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(b.headers).ok).toBe(true);
    expect(plans).toHaveLength(1);
  });

  it("age-based trigger: unsettled > 0 for ≥ flushInterval flushes even below threshold", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-09T12:00:00Z"));
    const signer = makeSigner(1);
    const plans: unknown[] = [];
    const merchant = accumulatorFor(signer, 1, {
      onFlushReady: async (plan) => {
        plans.push(plan);
      },
    });

    const first = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.50"), "0x" + "b1".repeat(32));
    if (!first.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(first.headers).ok).toBe(true);
    expect(plans).toHaveLength(0); // just accepted — timer starts now

    vi.setSystemTime(new Date("2026-11-09T15:00:00Z")); // +3h > default 2h interval
    const second = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.01"), "0x" + "b2".repeat(32));
    if (!second.ok) throw new Error("sign failed");
    expect(merchant.verifyPayment(second.headers).ok).toBe(true);
    expect(plans).toHaveLength(1); // byTime trigger fired
  });
});

describe("REV-7 — GOFER human gate covers the whole $1–$25 band", () => {
  it("$15 (the $10–$25 band) requires a human — never auto-allows", () => {
    const decision = new GoferPolicyEngine().evaluate({
      merchant: TEST_MERCHANT.toLowerCase(),
      amountMicro: parseUsdToMicro("15"),
      allowlist: new Set([TEST_MERCHANT.toLowerCase()]),
      counterpartyApproved: true,
      remainingAllowanceMicro: parseUsdToMicro("100"),
    } as never);
    expect(decision.action).toBe("human_approval_required");
    expect(decision.tier).toBe(3);
  });

  it("dryRun reports tier 3 + requiresHumanApproval for the $10–$25 band", () => {
    const signer = makeSigner(1);
    const client = new PaythosClient(signer, {
      signer,
      network: TESTNET,
      allowlist: new Set([TEST_MERCHANT.toLowerCase()]),
    });
    const report = client.dryRun(challenge("15.00"));
    expect(report.willSucceed).toBe(true);
    expect(report.requiresHumanApproval).toBe(true);
    expect(report.tier).toBe(3);
  });

  it("$25.01 remains a hard deny", () => {
    const signer = makeSigner(1);
    const client = new PaythosClient(signer, {
      signer,
      network: TESTNET,
      allowlist: new Set([TEST_MERCHANT.toLowerCase()]),
    });
    const report = client.dryRun(challenge("25.01"));
    expect(report.willSucceed).toBe(false);
    expect(report.requiresHumanApproval).toBe(false);
    expect(report.tier).toBe(3);
  });
});

describe("REV-15 — client ↔ express merchant over real HTTP (x402 lifecycle)", () => {
  it("402 challenge → GOFER gate → epoch-bound voucher → 200", async () => {
    const signer = makeSigner(1);
    const mountConfig = {
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_NATIVE_USDC,
      merchantAddress: TEST_MERCHANT,
      authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]),
      challengeFor: () => challenge("0.25"),
    };
    const app = express();
    app.get("/premium", paythosMerchant(mountConfig), (_req, res) => {
      res.status(200).json({ article: "premium-content" });
    });
    const server: Server = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });

    try {
      const port = (server.address() as AddressInfo).port;
      const client = new PaythosClient(signer, {
        signer,
        network: TESTNET,
        allowlist: new Set([TEST_MERCHANT.toLowerCase()]),
      });

      const result = await client.fetchWithX402({ url: `http://127.0.0.1:${port}/premium`, prompt: "read article" });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const body = (await result.data.json()) as { article: string };
      expect(body.article).toBe("premium-content");
      expect(signer.ledgerSnapshot()[0]?.cumulativeAmount).toBe(parseUsdToMicro("0.25"));
    } finally {
      await new Promise((r) => server.close(r));
    }
  });
});

describe("REV-5b — EIP-712 domain/schema parity (TS ↔ contract)", () => {
  it("VOUCHER_TYPES carries epoch between validUntil and memo, matching VoucherTypes.sol", () => {
    expect(VOUCHER_TYPES["Voucher"]).toEqual([
      { name: "agentKey", type: "address" },
      { name: "merchant", type: "address" },
      { name: "token", type: "address" },
      { name: "cumulativeAmount", type: "uint256" },
      { name: "validUntil", type: "uint256" },
      { name: "epoch", type: "uint64" },
      { name: "memo", type: "bytes32" },
    ]);
  });

  it("domain version is 3 (PROTOCOL_VERSION)", () => {
    const domain = domainFor({ network: TESTNET, vaultAddress: TEST_VAULT });
    expect(domain.version).toBe("3");
    expect(domain.name).toBe("Paythos Protocol");
  });

  it("the signature must embed epoch — verifyTypedData fails without it", async () => {
    const { verifyTypedData } = await import("ethers");
    const signer = makeSigner(1);
    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.10"), "0x" + "c1".repeat(32));
    if (!signed.ok) throw new Error("sign failed");
    const domain = domainFor({ network: TESTNET, vaultAddress: TEST_VAULT });
    const v = signed.voucher;
    expect(() =>
      verifyTypedData(
        domain,
        VOUCHER_TYPES,
        {
          agentKey: v.agentKey,
          merchant: v.merchant,
          token: v.token,
          cumulativeAmount: v.cumulativeAmount,
          validUntil: v.validUntil,
          memo: v.memo,
        },
        signed.signature,
      ),
    ).toThrow(); // epoch missing from the struct → different digest → recovery mismatch
  });
});
