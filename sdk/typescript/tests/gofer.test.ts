import { describe, expect, it } from "vitest";
import { GoferPolicyEngine, DEFAULT_TIERS } from "../src/core/policyEngine.js";
import { parseUsdToMicro } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT } from "./helpers.js";

const merchant = TEST_MERCHANT.toLowerCase();
const ALLOWED = new Set([merchant]);

function ctx(amount: string, overrides: Partial<Parameters<GoferPolicyEngine["evaluate"]>[0]> = {}) {
  return {
    amountMicro: parseUsdToMicro(amount),
    remainingAllowanceMicro: parseUsdToMicro("20"),
    merchant,
    allowlist: ALLOWED,
    counterpartyApproved: true,
    ...overrides,
  };
}

describe("GoferPolicyEngine — 3-tier matrix", () => {
  it("tier 1: sub-$1 auto-executes", () => {
    const decision = new GoferPolicyEngine().evaluate(ctx("0.75"));
    expect(decision).toMatchObject({ action: "allow", tier: 1 });
  });

  it("tier 2: $1–$10 requires human approval", () => {
    const decision = new GoferPolicyEngine().evaluate(ctx("3.50"));
    expect(decision).toMatchObject({ action: "human_approval_required", tier: 2 });
  });

  it("tier 3: above the $25 ceiling is a hard deny even with allowance", () => {
    const decision = new GoferPolicyEngine().evaluate(ctx("25.01"));
    expect(decision).toMatchObject({ action: "deny" });
    expect(decision.failure?.detail).toMatch(/Tier-3 hard policy ceiling/);
  });

  it("denies non-allowlisted merchant (fail closed)", () => {
    const decision = new GoferPolicyEngine().evaluate(
      ctx("0.10", { merchant: "0x9999999999999999999999999999999999999999" }),
    );
    expect(decision).toMatchObject({ action: "deny" });
  });

  it("denies when counterparty blocked by Transactability oracle", () => {
    const decision = new GoferPolicyEngine().evaluate(ctx("0.10", { counterpartyApproved: false }));
    expect(decision).toMatchObject({ action: "deny" });
  });

  it("denies when spend exceeds the rolling allowance before tiering", () => {
    const decision = new GoferPolicyEngine().evaluate(ctx("15", { remainingAllowanceMicro: parseUsdToMicro("12") }));
    expect(decision.action).toBe("deny");
  });

  it("denies non-positive amounts (ambiguity → fail closed)", () => {
    const decision = new GoferPolicyEngine().evaluate(ctx("0.10", { amountMicro: 0n }));
    expect(decision).toMatchObject({ action: "deny" });
  });

  it("intentMemo is deterministic keccak256(prompt|ts)", () => {
    const memo = GoferPolicyEngine.intentMemo("buy flour", 1700000000);
    expect(memo).toMatch(/^0x[0-9a-f]{64}$/);
    expect(GoferPolicyEngine.intentMemo("buy flour", 1700000000)).toBe(memo);
    expect(GoferPolicyEngine.intentMemo("buy flour", 1700000001)).not.toBe(memo);
  });
});

describe("DEFAULT_TIERS", () => {
  it("match spec defaults $1 / $10 / $25", () => {
    expect(DEFAULT_TIERS.microAutoExecMicro).toBe(1_000_000n);
    expect(DEFAULT_TIERS.humanApprovalUpperMicro).toBe(10_000_000n);
    expect(DEFAULT_TIERS.hardCeilingMicro).toBe(25_000_000n);
  });
});
