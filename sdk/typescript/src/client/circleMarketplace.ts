/**
 * Circle Agent Marketplace / x402 v2 buyer adapter (docs/CIRCLE-INTEGRATION.md).
 *
 * Marketplace services speak the STANDARD x402 v2 wire format:
 *   `PAYMENT-REQUIRED: base64({ x402Version, resource, accepts[], error, extensions })`
 * Paythos' own merchant protocol uses a flat `PaymentChallenge`; this module
 * bridges the two without changing the vault-settled voucher path.
 *
 * Settlement rail: Circle Gateway batching (`extra.name === "GatewayWalletBatched"`)
 * when offered, otherwise standard `exact` EIP-3009. The signer is the same
 * agent key used for vouchers, so Circle Dev Wallet / HSM signers stay external.
 */
import { x402Client, x402HTTPClient } from "@x402/core/client";
import type { PaymentRequired, PaymentRequirements } from "@x402/core/types";
import { registerBatchScheme } from "@circle-fin/x402-batching/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import type { ClientEvmSigner } from "@x402/evm";
import { getAddress, type TypedDataDomain } from "ethers";
import { PaymentChallenge, PaythosNetwork, formatMicroUsd } from "../types.js";
import { PaythosError } from "../core/errors.js";

/** Arc Testnet CAIP-2 + native USDC precompile (verified, AGENTS.md). */
export const CIRCLE_MARKETPLACE_ARC_TESTNET = "eip155:5042002";
export const ARC_TESTNET_USDC = "0x3600000000000000000000000000000000000000";

export interface CircleMarketplaceSigner {
  readonly address: string;
  signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<{ name: string; type: string }>>,
    value: Record<string, unknown>,
  ): Promise<string>;
}

export interface CircleMarketplaceConfig {
  /** CAIP-2 networks Paythos will pay on. Default: Arc Testnet only. */
  networks?: readonly string[];
  /** Settlement assets accepted per network. Default: Arc native USDC only. */
  assets?: readonly string[];
}

export interface CircleMarketplaceX402 {
  readonly client: x402Client;
  readonly http: x402HTTPClient;
}

const DEFAULT_NETWORKS = [CIRCLE_MARKETPLACE_ARC_TESTNET] as const;
const DEFAULT_ASSETS = [ARC_TESTNET_USDC] as const;

/**
 * The standard SDK's `x402Client` add-ons expect viem's `signTypedData({ domain,
 * types, primaryType, message })` shape; Paythos/Ethers uses positional args.
 * This adapter keeps the agent key inside `AgentVoucherSigner` (or a remote
 * Circle signer) and never exposes a private key.
 */
export function toX402ClientEvmSigner(signer: CircleMarketplaceSigner): ClientEvmSigner {
  return {
    address: getAddress(signer.address) as `0x${string}`,
    signTypedData: async ({ domain, types, message }) => {
      const signature = await signer.signTypedData(
        domain as TypedDataDomain,
        types as Record<string, Array<{ name: string; type: string }>>,
        message,
      );
      return signature as `0x${string}`;
    },
  };
}

/**
 * Build a standard x402 client that can pay Circle Gateway batched services
 * and fall back to exact EIP-3009. Spend controls are disabled because the
 * caller's GOFER gate (tier limits + allowlist + rolling allowance) runs in
 * `onBeforePaymentCreation`; a second, hidden $1 cap would silently shadow it.
 */
export function createCircleMarketplaceX402(
  signer: CircleMarketplaceSigner,
  config: CircleMarketplaceConfig = {},
): CircleMarketplaceX402 {
  const evmSigner = toX402ClientEvmSigner(signer);
  const networks = new Set(config.networks ?? DEFAULT_NETWORKS);
  const assets = new Set((config.assets ?? DEFAULT_ASSETS).map((a) => a.toLowerCase()));
  const client = new x402Client();
  client.setSpendControls(false);

  registerBatchScheme(client, {
    signer: evmSigner,
    networks: [...networks],
    fallbackScheme: new ExactEvmScheme(evmSigner),
  });

  // Fail closed on everything outside the verified Arc settlement path. The
  // call to `createPaymentPayload` then throws "no matching requirements"
  // instead of signing for an unknown chain/token.
  client.registerPolicy((_version, requirements) =>
    requirements.filter(
      (r) =>
        networks.has(r.network) &&
        assets.has(r.asset.toLowerCase()) &&
        r.scheme === "exact",
    ),
  );

  return { client, http: new x402HTTPClient(client) };
}

/**
 * Convert the selected marketplace requirement into the Paythos challenge
 * shape used by `PaythosClient.gate()`. `max` is decimal USD; `amount` keeps
 * the x402 atomic integer. Any malformed/unknown chain fails closed.
 */
export function challengeFromRequirement(
  paymentRequired: PaymentRequired,
  requirement: PaymentRequirements,
  fallbackResource: string,
): PaymentChallenge {
  if (paymentRequired.x402Version !== 2) {
    throw new PaythosError(
      "invalid_challenge",
      `unsupported x402Version ${paymentRequired.x402Version}`,
    );
  }
  if (requirement.network !== CIRCLE_MARKETPLACE_ARC_TESTNET) {
    throw new PaythosError(
      "invalid_challenge",
      `marketplace network ${requirement.network} is not an enabled Paythos network`,
    );
  }
  if (!/^\d+$/.test(requirement.amount) || BigInt(requirement.amount) <= 0n) {
    throw new PaythosError(
      "invalid_challenge",
      `invalid atomic amount ${String(requirement.amount)}`,
    );
  }
  if (!requirement.payTo || !requirement.asset) {
    throw new PaythosError("invalid_challenge", "marketplace requirement missing payTo/asset");
  }

  const amountMicro = BigInt(requirement.amount);
  return {
    x402Version: 2,
    scheme: "exact",
    network: requirement.network as PaythosNetwork,
    asset: requirement.asset,
    payTo: requirement.payTo,
    max: formatMicroUsd(amountMicro),
    amount: requirement.amount,
    resource: paymentRequired.resource?.url ?? fallbackResource,
    ...(paymentRequired.resource?.description !== undefined
      ? { description: paymentRequired.resource.description }
      : {}),
    ...(paymentRequired.resource?.mimeType !== undefined
      ? { mimeType: paymentRequired.resource.mimeType }
      : {}),
  };
}

/**
 * Node 18 ships WebCrypto on `node:crypto` but not always on `globalThis`
 * (the default landed in Node 19). x402 generates 32-byte nonces via
 * `globalThis.crypto`; alias it when absent instead of raising the Node floor.
 */
export async function ensureWebCrypto(): Promise<void> {
  if (typeof globalThis.crypto?.getRandomValues === "function") return;
  const { webcrypto } = await import("node:crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
  });
}
