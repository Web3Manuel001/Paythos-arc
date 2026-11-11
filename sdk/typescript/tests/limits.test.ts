/**
 * INV-M6 transport throttling (docs/PROTOCOL.md §5, Gate-2 acceptance).
 * A 500-request burst in ~2s must throttle with 429 + Retry-After at the
 * merchant boundary — zero backend hits for throttled requests.
 */
import { describe, expect, it } from "vitest";
import { TokenBucket } from "../src/core/tokenBucket.js";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { VoucherAccumulator } from "../src/middleware/merchant.js";
import { paythosMerchant } from "../src/middleware/express.js";
import { serializeVoucher } from "../src/client/paythosClient.js";
import { PAYMENT_SIGNATURE_HEADER } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET, AR_NATIVE_USDC, ephemeralPrivateKey } from "./helpers.js";

const BURST = 500;
const LIMIT = { capacity: 20, refillPerSecond: 1 };

function makeSigner(epoch = 1): AgentVoucherSigner {
  return new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    epoch,
  });
}

async function signedBurstHeaders(signer: AgentVoucherSigner): Promise<Record<string, string>[]> {
  const headers: Record<string, string>[] = [];
  let cumulative = 0n;
  for (let i = 0; i < BURST; i++) {
    cumulative += 1_000n; // strictly increasing lifetime vouchers
    const signed = await signer.recordAndSign(TEST_MERCHANT, cumulative, "0x" + "11".repeat(32));
    if (!signed.ok) throw new Error(`signing burst voucher #${i} failed: ${signed.error.detail}`);
    headers.push({
      [PAYMENT_SIGNATURE_HEADER]: JSON.stringify({
        voucher: serializeVoucher(signed.voucher),
        signature: signed.signature,
      }),
    });
  }
  return headers;
}

function accumulatorFor(signer: AgentVoucherSigner): VoucherAccumulator {
  return new VoucherAccumulator({
    network: TESTNET,
    vaultAddress: TEST_VAULT,
    settlementToken: AR_NATIVE_USDC,
    authorizedAgents: new Map([[signer.agentKey.toLowerCase(), signer.epoch]]),
    rateLimit: LIMIT,
  });
}

describe("TokenBucket — fail-closed configuration", () => {
  it("rejects non-positive capacity or refill", () => {
    expect(() => new TokenBucket({ capacity: 0, refillPerSecond: 1 })).toThrow(/capacity/);
    expect(() => new TokenBucket({ capacity: 10, refillPerSecond: 0 })).toThrow(/refill/);
    expect(() => new TokenBucket({ capacity: 10, refillPerSecond: Number.NaN })).toThrow(/refill/);
  });
});

describe("INV-M6 — merchant-boundary burst throttling", () => {
  it("500 in-memory verifications in a burst throttle past the bucket with 429", { timeout: 30_000 }, async () => {
    const signer = makeSigner();
    const headers = await signedBurstHeaders(signer);
    const accumulator = accumulatorFor(signer);

    const started = Date.now();
    const outcomes = headers.map((h) => accumulator.verifyPayment(h));
    const elapsed = Date.now() - started;

    const allowed = outcomes.filter((o) => o.status !== 429);
    const throttled = outcomes.filter((o) => o.status === 429);
    expect(throttled.length).toBeGreaterThanOrEqual(BURST - LIMIT.capacity - 10);
    expect(allowed.length).toBeLessThanOrEqual(LIMIT.capacity + 10);
    for (const outcome of throttled) {
      expect(outcome.ok).toBe(false);
      expect(outcome.reason).toContain("rate limit");
      expect(outcome.retryAfterSeconds).toBeGreaterThan(0);
      expect(outcome.retryAfterSeconds!).toBeLessThanOrEqual(2); // 1 token / 1 per second
    }
    expect(elapsed).toBeLessThan(2_000); // the whole burst lands inside the 2s window
  });

  it("burst 429s never consume allowance or reach monotonicity checks", { timeout: 30_000 }, async () => {
    const signer = makeSigner();
    const headers = await signedBurstHeaders(signer);
    const accumulator = accumulatorFor(signer);

    let backendHits = 0;
    for (const h of headers) {
      const outcome = accumulator.verifyPayment(h);
      if (outcome.status === 200) backendHits++;
    }
    expect(backendHits).toBeLessThanOrEqual(LIMIT.capacity + 10);
    // highest() proves only the allowed prefix mutated merchant state.
    expect(accumulator.highest(signer.agentKey)).toBeDefined();
  });

  it("express mount emits 429 + Retry-After with zero backend hits on throttled loops", { timeout: 60_000 }, async () => {
    const signer = makeSigner();
    const headers = await signedBurstHeaders(signer);
    let backendHits = 0;
    const app = express();
    app.get(
      "/paid",
      paythosMerchant({
        network: TESTNET,
        vaultAddress: TEST_VAULT,
        settlementToken: AR_NATIVE_USDC,
        authorizedAgents: new Map([[signer.agentKey.toLowerCase(), signer.epoch]]),
        rateLimit: LIMIT,
        challengeFor: () => ({
          x402Version: 2,
          scheme: "exact",
          network: TESTNET,
          asset: AR_NATIVE_USDC,
          payTo: TEST_MERCHANT,
          max: "0.01",
          resource: "https://m.example.com/paid",
        }),
      } as never),
      (_req, res) => {
        backendHits++;
        res.status(200).json({ ok: true });
      },
    );
    const server: Server = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      const port = (server.address() as AddressInfo).port;
      const started = Date.now();
      const responses = await Promise.all(
        headers.map((h) => fetch(`http://127.0.0.1:${port}/paid`, { headers: h })),
      );
      const elapsed = Date.now() - started;
      const throttled = responses.filter((r) => r.status === 429);
      expect(throttled.length).toBeGreaterThanOrEqual(BURST - LIMIT.capacity - 10);
      expect(backendHits).toBeLessThanOrEqual(LIMIT.capacity + 10);
      for (const r of throttled) {
        expect(r.headers.get("retry-after")).toMatch(/^\d+$/);
        expect(Number(r.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
        expect(r.headers.get("payment-required")).toBeNull(); // no re-challenge on throttle
        await r.arrayBuffer();
      }
      for (const r of responses.filter((x) => x.status !== 429)) await r.arrayBuffer();
      expect(elapsed).toBeLessThan(10_000); // localhost burst completes promptly
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  it("unknown agentKey floods return 402 without allocating limiter state", { timeout: 30_000 }, async () => {
    const authorized = makeSigner();
    const stranger = makeSigner(); // valid keypair, NOT in authorizedAgents
    const headers = await signedBurstHeaders(stranger);
    const accumulator = accumulatorFor(authorized);

    const statuses = headers.map((h) => accumulator.verifyPayment(h).status);
    expect(statuses.every((s) => s === 402)).toBe(true);
    expect(statuses.some((s) => s === 429)).toBe(false); // no bucket for strangers
  });

  it("throttling is per-agent: one runaway agent cannot starve another", { timeout: 30_000 }, async () => {
    const noisy = makeSigner();
    const quiet = makeSigner();
    const noisyHeaders = await signedBurstHeaders(noisy);
    const accumulator = new VoucherAccumulator({
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_NATIVE_USDC,
      authorizedAgents: new Map([
        [noisy.agentKey.toLowerCase(), noisy.epoch],
        [quiet.agentKey.toLowerCase(), quiet.epoch],
      ]),
      rateLimit: LIMIT,
    });
    for (const h of noisyHeaders) accumulator.verifyPayment(h);
    expect(accumulator.verifyPayment(noisyHeaders[0]!).status).toBe(429);

    const quietSigned = await quiet.recordAndSign(TEST_MERCHANT, 1_000n, "0x" + "22".repeat(32));
    if (!quietSigned.ok) throw new Error("quiet signing failed");
    const quietHeaders = {
      [PAYMENT_SIGNATURE_HEADER]: JSON.stringify({
        voucher: serializeVoucher(quietSigned.voucher),
        signature: quietSigned.signature,
      }),
    };
    expect(accumulator.verifyPayment(quietHeaders).status).toBe(200);
  });
});
