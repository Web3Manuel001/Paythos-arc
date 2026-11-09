/**
 * AutoGen / OpenAI function-spec adapter (docs/ARCHITECTURE.md Module 5).
 * Emits the OpenAI `tools` JSON schema (the format AutoGen + most agent
 * frameworks consume) plus a dispatch table wiring names → SDK methods.
 */
import { PaythosClient, DEFAULT_ALLOWANCE_MICRO } from "../client/paythosClient.js";
import { AgentVoucherSigner } from "../signer/voucherSigner.js";
import { PaymentChallenge, formatMicroUsd } from "../types.js";

export interface OpenAiFunctionSpec {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, unknown>;
      required?: string[];
    };
  };
}

const CHALLENGE_JSON_SCHEMA = {
  type: "object",
  description: "x402 v2 PAYMENT-REQUIRED challenge (x402Version=2, payTo, max, resource).",
  properties: {
    x402Version: { type: "integer", const: 2 },
    scheme: { type: "string", enum: ["exact", "upto"] },
    network: { type: "string" },
    asset: { type: "string" },
    payTo: { type: "string" },
    max: { type: "string", description: "decimal USDC, e.g. 0.01" },
    resource: { type: "string", description: "https URL of the paywalled resource" },
  },
  required: ["x402Version", "scheme", "network", "asset", "payTo", "max", "resource"],
};

export function makeAutoGenSpecs(): OpenAiFunctionSpec[] {
  return [
    {
      type: "function",
      function: {
        name: "paythos_dry_run",
        description: "Simulate a x402 purchase through Paythos GOFER; capital never moves.",
        parameters: {
          type: "object",
          properties: { challenge: CHALLENGE_JSON_SCHEMA },
          required: ["challenge"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "paythos_purchase",
        description: "Execute a x402 purchase: GOFER gate → cumulative EIP-712 voucher → retry. Tier-2 spends fail closed without a human gate.",
        parameters: {
          type: "object",
          properties: {
            url: { type: "string", description: "https URL of the paywalled resource" },
            challenge: CHALLENGE_JSON_SCHEMA,
            prompt: { type: "string", description: "verifiable-intent prompt text; only its hash leaves the boundary" },
          },
          required: ["url", "challenge", "prompt"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "paythos_budget",
        description: "Report remaining rolling allowance and signer ledger snapshot.",
        parameters: { type: "object", properties: {} },
      },
    },
  ];
}

/** Dispatch table: wire into AutoGen register_for_llm / function_map. */
export function makeAutoGenHandlers(
  client: PaythosClient,
  signer: AgentVoucherSigner,
): Record<string, (args: Record<string, unknown>) => Promise<unknown>> {
  return {
    paythos_dry_run: async (args) => {
      const report = client.dryRun(args["challenge"] as PaymentChallenge);
      return JSON.parse(JSON.stringify(report, (_, value) => (typeof value === "bigint" ? value.toString() : value)));
    },
    paythos_purchase: async (args) => {
      const result = await client.fetchWithX402({
        url: args["url"] as string,
        prompt: args["prompt"] as string,
      });
      if (!result.ok) return { denied: result.error };
      return { status: result.data.status, voucher: result.voucher ? serialize(result.voucher) : null };
    },
    paythos_budget: async () => {
      return {
        agentKey: signer.agentKey,
        remainingAllowanceUsd: formatMicroUsd(DEFAULT_ALLOWANCE_MICRO),
        ledger: signer.ledgerSnapshot().map((e) => ({
          merchant: e.merchant,
          sessionTotalUsd: formatMicroUsd(e.cumulativeAmount),
        })),
      };
    },
  };
}

function serialize(v: { agentKey: string; merchant: string; token: string; cumulativeAmount: bigint; validUntil: bigint; epoch: number; memo: string }) {
  return {
    agentKey: v.agentKey,
    merchant: v.merchant,
    token: v.token,
    cumulativeAmount: v.cumulativeAmount.toString(),
    validUntil: v.validUntil.toString(),
    epoch: v.epoch,
    memo: v.memo,
  };
}
