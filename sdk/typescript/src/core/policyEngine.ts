/**
 * GOFER — Governing Financial Objectives Runtime (docs/ARCHITECTURE.md Module 4).
 * The 3-Tier Enterprise Safety Threshold + destination allowlist + verifiable intent.
 * Fail closed: EVERY ambiguous input denies.
 */
import { keccak256, toUtf8Bytes } from "ethers";
import { Policy, PolicyEvaluatedFailure, PreFlightReport, parseUsdToMicro } from "../types.js";

/** Threshold defaults are spec defaults (docs/AGENTS.md); override per deployment. */
export interface TierThresholds {
  /** Tier 1 below this clears autonomously. Default $1.00 in micro. */
  microAutoExecMicro: bigint;
  /** Tier 2 below this routes to human review. Default $10.00 in micro. */
  humanApprovalUpperMicro: bigint;
  /** Tier 3 above this is a hard, un-overridable exception. Default $25.00 in micro. */
  hardCeilingMicro: bigint;
}

export const DEFAULT_TIERS: TierThresholds = {
  microAutoExecMicro: parseUsdToMicro("1"),
  humanApprovalUpperMicro: parseUsdToMicro("10"),
  hardCeilingMicro: parseUsdToMicro("25"),
};

export type PolicyDecision =
  | { action: "allow"; tier: 1 | 2 | 3; reason: string }
  | { action: "human_approval_required"; tier: 2; reason: string }
  | { action: "deny"; tier: 3 | null; failure: PolicyEvaluatedFailure };

export interface PolicyContext {
  amountMicro: bigint; // this call's cost (or `upto` ceiling)
  remainingAllowanceMicro: bigint;
  merchant: string;
  allowlist: ReadonlySet<string>;
  counterpartyApproved: boolean; // Transactability Index verdict
}

export class GoferPolicyEngine {
  constructor(private readonly tiers: TierThresholds = DEFAULT_TIERS) {}

  /**
   * Mastercard-grade Verifiable Intent (Module 4.4):
   * keccak256 over `prompt || timestamp` — stamped into the voucher `memo`.
   * The raw prompt NEVER leaves the local boundary; only its hash does.
   */
  static intentMemo(prompt: string, timestampSeconds: number): string {
    return keccak256(toUtf8Bytes(`${prompt}|${timestampSeconds}`));
  }

  /** 3-Tier evaluation. Never throws — and NEVER advises "allow" on ambiguity. */
  evaluate(ctx: PolicyContext): PolicyDecision {
    if (ctx.amountMicro <= 0n) {
      // Ambiguity/garbage → deny (fail closed, AGENTS.md rule 3).
      return {
        action: "deny",
        tier: null,
        failure: { code: "policy_ambiguous", detail: "amount is not a positive micro-USDC integer" },
      };
    }
    if (!ctx.allowlist.has(ctx.merchant.toLowerCase())) {
      return {
        action: "deny",
        tier: 3,
        failure: { code: "unauthorized_merchant", detail: `merchant ${ctx.merchant} not on destination allowlist` },
      };
    }
    if (!ctx.counterpartyApproved) {
      return {
        action: "deny",
        tier: 3,
        failure: { code: "counterparty_blocked", detail: "Transactability Index below vendor floor" },
      };
    }
    if (ctx.amountMicro > this.tiers.hardCeilingMicro) {
      return {
        action: "deny",
        tier: 3,
        failure: { code: "max_per_tx_exceeded", detail: "Tier-3 hard policy ceiling exceeded" },
      };
    }
    if (ctx.amountMicro > ctx.remainingAllowanceMicro) {
      return {
        action: "deny",
        tier: null,
        failure: { code: "daily_limit_exceeded", detail: "insufficient rolling-24h allowance" },
      };
    }
    if (ctx.amountMicro > this.tiers.microAutoExecMicro && ctx.amountMicro <= this.tiers.humanApprovalUpperMicro) {
      return {
        action: "human_approval_required",
        tier: 2,
        reason: "Tier 2: spend sits in the human review band",
      };
    }
    const tier: 1 | 3 = ctx.amountMicro > this.tiers.humanApprovalUpperMicro ? 3 : 1;
    return { action: "allow", tier, reason: "within policy" };
  }

  /** Structured dryRun report (Module 4.1) — pure, moves no capital. */
  preFlight(ctx: PolicyContext): PreFlightReport {
    const decision = this.evaluate(ctx);
    switch (decision.action) {
      case "allow":
        return {
          willSucceed: true,
          reason: decision.reason,
          remainingAllowanceMicro: ctx.remainingAllowanceMicro - ctx.amountMicro,
          requiresHumanApproval: false,
          tier: decision.tier,
        };
      case "human_approval_required":
        return {
          willSucceed: true,
          reason: decision.reason,
          remainingAllowanceMicro: ctx.remainingAllowanceMicro - ctx.amountMicro,
          requiresHumanApproval: true,
          tier: 2,
        };
      case "deny":
        return {
          willSucceed: false,
          reason: decision.failure.detail,
          remainingAllowanceMicro: ctx.remainingAllowanceMicro,
          requiresHumanApproval: false,
          tier: decision.tier,
        };
    }
  }
}
