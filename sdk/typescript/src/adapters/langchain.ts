/**
 * LangChain.js adapter (docs/ARCHITECTURE.md Module 5).
 * Exposes budgeted x402 actions as duck-typed LangChain tools (`DynamicStructuredTool`
 * shape: name/description/schema/func — no direct dependency on @langchain/core).
 * The wallet and the GOFER engine stay owned by the injected PaythosClient.
 */
import { z } from "zod";
import { PaythosClient, DEFAULT_ALLOWANCE_MICRO } from "../client/paythosClient.js";
import { AgentVoucherSigner } from "../signer/voucherSigner.js";
import { PaymentChallenge, formatMicroUsd } from "../types.js";

export interface PaythosLangChainTool {
  name: string;
  description: string;
  schema: z.ZodTypeAny;
  func(args: Record<string, unknown>): Promise<string>;
}

/** One-shot challenge from a x402 response body the caller already holds. */
const ChallengeSchema = z.object({
  x402Version: z.literal(2),
  scheme: z.enum(["exact", "upto"]),
  network: z.string(),
  asset: z.string(),
  payTo: z.string(),
  max: z.string(),
  resource: z.string(),
  description: z.string().optional(),
  mimetype: z.string().optional(),
  mimeType: z.string().optional(),
});

export function makeLangChainTools(client: PaythosClient, signer: AgentVoucherSigner): PaythosLangChainTool[] {
  return [
    {
      name: "paythos_dry_run",
      description:
        "Pre-execution financial simulation of a x402 purchase through Paythos GOFER. Never moves capital. Run before paythos_purchase.",
      schema: ChallengeSchema,
      async func(args) {
        const challenge = normalizeChallenge(args);
        const report = client.dryRun(challenge);
        return JSON.stringify(report, (_, value) =>
          typeof value === "bigint" ? value.toString() : value,
        );
      },
    },
    {
      name: "paythos_purchase",
      description:
        "Execute a x402 purchase for a challenge through the Paythos client: GOFER gate → EIP-712 cumulative voucher → retry. Tier-2 spends fail closed without a human gate.",
      schema: z.object({
        url: z.string().describe("https:// resource URL that returned the challenge"),
        challenge: ChallengeSchema,
        prompt: z.string().describe("verifiable-intent prompt text; only its hash is stamped into the voucher memo"),
      }),
      async func(args) {
        const result = await client.fetchWithX402({
          url: args.url as string,
          prompt: args.prompt as string,
        });
        if (!result.ok) return `DENIED: ${result.error.code} — ${result.error.detail}`;
        const text = await result.data.clone().text();
        const voucher = result.voucher
          ? {
              ...result.voucher,
              cumulativeAmount: result.voucher.cumulativeAmount.toString(),
              validUntil: result.voucher.validUntil.toString(),
            }
          : null;
        return JSON.stringify(
          { status: result.data.status, body: text.slice(0, 4096), voucher },
          null,
          2,
        );
      },
    },
    {
      name: "paythos_budget",
      description: "Report signer ledger and remaining rolling allowance. No side effects.",
      schema: z.object({}),
      async func() {
        return JSON.stringify({
          agentKey: signer.agentKey,
          ledger: signer.ledgerSnapshot().map((e) => ({
            merchant: e.merchant,
            sessionTotalUsd: formatMicroUsd(e.cumulativeAmount),
          })),
          remainingAllowanceUsd: formatMicroUsd(DEFAULT_ALLOWANCE_MICRO),
        });
      },
    },
  ];
}

function normalizeChallenge(args: Record<string, unknown>): PaymentChallenge {
  const challenge: PaymentChallenge = {
    x402Version: 2,
    scheme: "exact",
    network: args.network as never,
    asset: args.asset as string,
    payTo: args.payTo as string,
    max: args.max as string,
    resource: args.resource as string,
    memoRequired: false,
  };
  if (typeof args.description === "string") challenge.description = args.description;
  const mime = typeof args.mimeType === "string" ? args.mimeType : typeof args.mimetype === "string" ? args.mimetype : undefined;
  if (mime !== undefined) challenge.mimeType = mime;
  return challenge;
}
