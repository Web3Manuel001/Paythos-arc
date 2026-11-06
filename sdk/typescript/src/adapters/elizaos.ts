/**
 * ElizaOS plugin adapter (docs/ARCHITECTURE.md Module 5).
 * ElizaOS plugins expose `actions` with a `validate` + `handler`, and
 * `providers` returning runtime context. Duck-typed again for portability.
 */
import { PaythosClient } from "../client/paythosClient.js";
import { AgentVoucherSigner } from "../signer/voucherSigner.js";
import { PaymentChallenge, formatMicroUsd } from "../types.js";

export interface ElizaMemory {
  content: { text: string; source?: string };
}

export interface ElizaRuntime {
  agentId: string;
  getMemoryById?(id: string): Promise<ElizaMemory | null>;
  composeState?(message: ElizaMemory): Promise<Record<string, unknown>>;
}

export interface ElizaAction {
  name: string;
  description: string;
  /** Returns false → action unavailable, agent falls through (fail closed). */
  validate(runtime: ElizaRuntime, message: ElizaMemory): Promise<boolean>;
  handler(runtime: ElizaRuntime, message: ElizaMemory): Promise<{ success: boolean; text: string }>;
  similes: string[];
  examples: Array<{ user: string; content: { text: string } }>;
}

export interface PaythosElizaPlugin {
  name: "paythos";
  description: string;
  actions: ElizaAction[];
}

/** Boolean-like parser used in examples/runtime text. */
function parseChallengeFromText(text: string): PaymentChallenge | undefined {
  try {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return undefined;
    const parsed = JSON.parse(match[0]) as Partial<PaymentChallenge>;
    if (parsed.x402Version !== 2 || typeof parsed.payTo !== "string" || typeof parsed.max !== "string") {
      return undefined;
    }
    return parsed as PaymentChallenge;
  } catch {
    return undefined;
  }
}

export function makeElizaPlugin(client: PaythosClient, signer: AgentVoucherSigner): PaythosElizaPlugin {
  return {
    name: "paythos",
    description: "Enterprise spend-guardrail layer: budgeted x402 errands via GOFER policy.",
    actions: [
      {
        name: "PAYTHOS_DRY_RUN",
        description: "Simulate a x402 spend through GOFER without moving capital.",
        similes: ["simulate spend", "check affordability"],
        examples: [
          {
            user: "user",
            content: {
              text: 'Simulate this spend: {"x402Version":2,"payTo":"0x…","max":"0.75"}',
            },
          },
        ],
        async validate(_runtime, message) {
          return parseChallengeFromText(message.content.text) !== undefined;
        },
        async handler(_runtime, message) {
          const challenge = parseChallengeFromText(message.content.text);
          if (!challenge) {
            return { success: false, text: "no x402 v2 challenge found in message" };
          }
          const report = client.dryRun(challenge);
          return {
            success: report.willSucceed,
            text: report.willSucceed
              ? `Will succeed (tier ${report.tier}). Remaining allowance after: ${formatMicroUsd(report.remainingAllowanceMicro)} USDC.`
              : `Policy denial: ${report.reason}`,
          };
        },
      },
      {
        name: "PAYTHOS_PURCHASE",
        description: "Buy a x402 resource through the Paythos client (GOFER gate → voucher → retry).",
        similes: ["purchase", "buy now", "pay this endpoint"],
        examples: [],
        async validate(runtime, message) {
          void runtime;
          return /paythos:buy/i.test(message.content.text) && parseChallengeFromText(message.content.text) !== undefined;
        },
        async handler(runtime, message) {
          void runtime;
          const challenge = parseChallengeFromText(message.content.text);
          if (!challenge || !/^https:\/\//.test(challenge.resource)) {
            return { success: false, text: "challenge incomplete: need a https resource URL" };
          }
          const prompt = message.content.text.slice(0, 512);
          const result = await client.fetchWithX402({ url: challenge.resource, prompt });
          if (!result.ok) {
            return { success: false, text: `DENIED: ${result.error.code} — ${result.error.detail}` };
          }
          return {
            success: true,
            text: `Purchased ${challenge.resource} (HTTP ${result.data.status}). Signer session total now ${formatMicroUsd(signer.ledgerSnapshot()[0]?.cumulativeAmount ?? 0n)} USDC.`,
          };
        },
      },
    ],
  };
}
