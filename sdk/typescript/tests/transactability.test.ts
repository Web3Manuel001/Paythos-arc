/**
 * Transactability Index (docs/ARCHITECTURE.md Module 4.2, SECURITY.md §3).
 * Measured merchant health: uptime · validity · latency · 5xx rate.
 * Pay-then-fail vendors hit the validity floor and get blocked.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_TRANSACTABILITY_CONFIG,
  InMemoryTransactabilityRegistry,
  TransactabilityIndex,
  isTransactabilityIndex,
} from "../src/client/transactability.js";
import { PaythosClient } from "../src/client/paythosClient.js";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { PaymentChallenge } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET, AR_NATIVE_USDC, ephemeralPrivateKey } from "./helpers.js";

const MERCHANT = TEST_MERCHANT.toLowerCase();

const healthy = { ok: true, latencyMs: 0, status: 200, valid: true };

describe("TransactabilityIndex — scoring", () => {
  it("all-healthy history scores 100 and allows", () => {
    const index = new TransactabilityIndex();
    for (let i = 0; i < 5; i++) index.record(MERCHANT, healthy);
    const score = index.score(MERCHANT);
    expect(score.score).toBe(100);
    expect(score.verdict).toBe("allow");
    expect(score.source).toBe("local");
    expect(index.approve(MERCHANT)).toBe(true);
  });

  it("pay-then-fail (unattested completions) hits the validity floor and blocks", () => {
    const index = new TransactabilityIndex();
    for (let i = 0; i < 4; i++) index.record(MERCHANT, { ok: true, latencyMs: 50, status: 200, valid: false });
    const score = index.score(MERCHANT);
    expect(score.validity).toBe(0);
    expect(score.verdict).toBe("block");
    expect(index.approve(MERCHANT)).toBe(false);
  });

  it("mixed uptime/validity yields a downgrade (still pays, catalog-filtered)", () => {
    const index = new TransactabilityIndex();
    for (let i = 0; i < 3; i++) index.record(MERCHANT, healthy);
    for (let i = 0; i < 3; i++) index.record(MERCHANT, { ok: false, latencyMs: 50, valid: false });
    const score = index.score(MERCHANT);
    expect(score.samples).toBe(6);
    expect(score.uptime).toBeCloseTo(0.5);
    expect(score.verdict).toBe("downgrade");
    expect(index.approve(MERCHANT)).toBe(true); // downgrade ≠ block
  });

  it("5xx rates feed the score and drive the verdict down", () => {
    const index = new TransactabilityIndex();
    for (let i = 0; i < 2; i++) index.record(MERCHANT, healthy);
    for (let i = 0; i < 2; i++) {
      index.record(MERCHANT, { ok: false, latencyMs: 50, status: 503, valid: false });
    }
    const score = index.score(MERCHANT);
    expect(score.errorRate5xx).toBeCloseTo(0.5);
    expect(score.verdict).toBe("downgrade");
  });

  it("only the rolling window counts", () => {
    const index = new TransactabilityIndex({ config: { windowSize: 2 } });
    for (let i = 0; i < 10; i++) index.record(MERCHANT, { ok: false, latencyMs: 10, valid: false });
    index.record(MERCHANT, healthy);
    index.record(MERCHANT, healthy);
    const score = index.score(MERCHANT);
    expect(score.samples).toBe(2);
    expect(score.score).toBe(100);
    expect(score.verdict).toBe("allow");
  });

  it("latency beyond the budget zeroes only the latency component", () => {
    const index = new TransactabilityIndex();
    for (let i = 0; i < 4; i++) index.record(MERCHANT, { ...healthy, latencyMs: 10_000 });
    const score = index.score(MERCHANT);
    expect(score.latencyMs).toBe(10_000);
    expect(score.score).toBe(80); // 0.35 + 0.35 + 0.20·0 + 0.10
    expect(score.verdict).toBe("allow");
  });

  it("unknown merchants allow by default (allowlist is the fail-closed boundary)", () => {
    const index = new TransactabilityIndex();
    const score = index.score("0x00000000000000000000000000000000000000aa");
    expect(score.source).toBe("empty");
    expect(score.verdict).toBe("allow");
  });

  it("unknown merchants block when unknownVerdict is 'block'", () => {
    const index = new TransactabilityIndex({ config: { unknownVerdict: "block" } });
    expect(index.approve("0x00000000000000000000000000000000000000aa")).toBe(false);
  });
});

describe("TransactabilityIndex — pluggable registry", () => {
  it("seeds unknown merchants from a published attestation", () => {
    const registry = new InMemoryTransactabilityRegistry();
    registry.publish({
      merchant: MERCHANT,
      score: 30,
      uptime: 0.3,
      validity: 0.2,
      latencyMs: 900,
      errorRate5xx: 0.4,
      samples: 10,
      updatedAt: Date.now(),
    });
    const index = new TransactabilityIndex({ registry });
    const score = index.score(MERCHANT);
    expect(score.source).toBe("registry");
    expect(score.verdict).toBe("block"); // 30 < blockBelow
    expect(index.approve(MERCHANT)).toBe(false);
  });

  it("publishes fresh attestations on every observation", () => {
    const registry = new InMemoryTransactabilityRegistry();
    const index = new TransactabilityIndex({ registry });
    index.record(MERCHANT, healthy);
    const published = registry.lookup(MERCHANT);
    expect(published).toBeDefined();
    expect(published!.samples).toBe(1);
    expect(published!.score).toBe(100);
    expect(registry.snapshot()).toHaveLength(1);
  });

  it("local measurements take precedence over the registry", () => {
    const registry = new InMemoryTransactabilityRegistry();
    registry.publish({
      merchant: MERCHANT,
      score: 10,
      uptime: 0.1,
      validity: 0.1,
      latencyMs: 5_000,
      errorRate5xx: 0.9,
      samples: 20,
      updatedAt: Date.now(),
    });
    const index = new TransactabilityIndex({ registry });
    index.record(MERCHANT, healthy);
    const score = index.score(MERCHANT);
    expect(score.source).toBe("local");
    expect(score.verdict).toBe("allow");
  });

  it("isTransactabilityIndex discriminates plain oracles", () => {
    expect(isTransactabilityIndex(new TransactabilityIndex())).toBe(true);
    expect(isTransactabilityIndex({ approve: () => true })).toBe(false);
    expect(isTransactabilityIndex(undefined)).toBe(false);
  });

  it("defaults are the documented spec defaults", () => {
    expect(DEFAULT_TRANSACTABILITY_CONFIG).toMatchObject({
      windowSize: 64,
      latencyBudgetMs: 2_000,
      downgradeBelow: 75,
      blockBelow: 50,
      validityFloor: 0.5,
      minSamples: 4,
      unknownVerdict: "allow",
    });
  });
});

describe("PaythosClient — Transactability wiring", () => {
  function uptoChallenge(): PaymentChallenge {
    return {
      x402Version: 2,
      scheme: "upto",
      network: TESTNET,
      asset: AR_NATIVE_USDC,
      payTo: MERCHANT,
      max: "0.01",
      resource: "https://m.example.com/stream",
    };
  }

  function makeClient(index: TransactabilityIndex) {
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const scripted: Array<() => Response> = [];
    const fetchFn = (async () => {
      const next = scripted.shift();
      if (!next) throw new Error("unexpected fetch — script exhausted");
      return next();
    }) as unknown as typeof fetch;
    const client = new PaythosClient(signer, {
      signer,
      network: TESTNET,
      allowlist: new Set([MERCHANT]),
      transactability: index,
      fetch: fetchFn,
    });
    return { client, scripted };
  }

  function challengeResponse(): Response {
    return new Response("payment required", {
      status: 402,
      headers: {
        "payment-required": Buffer.from(JSON.stringify(uptoChallenge()), "utf8").toString("base64"),
      },
    });
  }

  it("repeated unattested streams block the merchant before the next hold", async () => {
    const index = new TransactabilityIndex();
    const { client, scripted } = makeClient(index);

    for (let i = 0; i < 4; i++) {
      scripted.push(challengeResponse);
      scripted.push(() => new Response("rendered but NO metering trailer\n", { status: 200 }));
      const failed = await client.streamWithX402({ url: "https://m.example.com/stream", prompt: `p${i}` });
      expect(failed.ok).toBe(false);
    }
    expect(index.score(MERCHANT).verdict).toBe("block");

    // Next attempt: gate denies BEFORE the hold — only the 402 round-trip fires.
    scripted.push(challengeResponse);
    const blocked = await client.streamWithX402({ url: "https://m.example.com/stream", prompt: "p-final" });
    expect(blocked.ok).toBe(false);
    if (blocked.ok) return;
    expect(blocked.error.detail).toMatch(/Transactability Index/);
    expect(blocked.holdState).toBe("unset");
    expect(scripted).toHaveLength(0);
    expect(client.holds.activeHoldMicro()).toBe(0n);
  });

  it("a fresh index allows the merchant before any traffic", () => {
    const index = new TransactabilityIndex();
    expect(index.approve(MERCHANT)).toBe(true);
    expect(index.score(MERCHANT).source).toBe("empty");
  });
});
