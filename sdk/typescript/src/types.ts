/**
 * Paythos Protocol — canonical types (docs/PROTOCOL.md is the source of truth).
 * Python mirror: sdk/python/paythos/types.py — keep both in 1:1 lockstep.
 * AGENTS.md: all amounts are atomic micro-USDC (USDC = 6 decimals).
 *
 * IMPORTANT — chain registry lockstep (PROTOCOL OPEN-Q1):
 * `arc:mainnet` chain-ID is UNVERIFIED; the SDK refuses it until resolved.
 */

/** CAIP-2 network identifiers accepted by this SDK build (Arc L1 only). */
export type PaythosNetwork = "eip155:5042002" | "arc:mainnet";

export interface ChainRegistryEntry {
  readonly network: PaythosNetwork;
  readonly chainId: number | null; // null = UNVERIFIED (fail closed)
  readonly nativeUsdc: string | null; // null = UNVERIFIED
  readonly verified: boolean;
}

export const CHAIN_REGISTRY: Readonly<Record<PaythosNetwork, ChainRegistryEntry>> = {
  "eip155:5042002": {
    network: "eip155:5042002",
    chainId: 5042002,
    // Arc Testnet native-USDC precompile (verified on-chain by the prior demo deploy)
    nativeUsdc: "0x3600000000000000000000000000000000000000",
    verified: true,
  },
  "arc:mainnet": {
    network: "arc:mainnet",
    // docs.arc.io: Arc mainnet chain ID = 5042 (0x13b2), RPC https://rpc.mainnet.arc.io
    chainId: 5042,
    // Mainnet USDC address still unverified → remain fail closed (PROTOCOL-OPEN-Q1).
    nativeUsdc: null,
    verified: false,
  },
};

/** EIP-712 voucher (docs/PROTOCOL.md §1.1). ALWAYS cumulative. */
export interface Voucher {
  agentKey: string; // EIP-55 address of the delegated ephemeral key
  merchant: string;
  token: string;
  cumulativeAmount: bigint;
  validUntil: bigint; // unix seconds
  memo: string; // bytes32 hex ("0x" + 64 chars)
}

/** Per-ephemeral-key policy (docs/PROTOCOL.md §2). */
export interface Policy {
  dailyLimit: bigint;
  maxPerTx: bigint;
  expiresAt: bigint;
}

/** x402 v2 challenge carried in the base64 `PAYMENT-REQUIRED` header. */
export interface PaymentChallenge {
  x402Version: 2;
  scheme: "exact" | "upto";
  network: PaythosNetwork;
  asset: string;
  payTo: string;
  max: string; // decimal USDC string, e.g. "0.01"
  resource: string;
  description?: string;
  mimeType?: string;
  memoRequired?: boolean;
}

/** Frames the SDK sends on the retry after challenge evaluation. */
export const PAYMENT_REQUIRED_HEADER = "payment-required";
export const PAYMENT_SIGNATURE_HEADER = "payment-signature";
export const X_PAYTHOS_VOUCHER_HEADER = "x-paythos-voucher";
export const X_PAYTHOS_SIGNATURE_HEADER = "x-paythos-signature";

export type PaymentSchemeResult =
  | { ok: true; voucher: Voucher; signature: string }
  | { ok: false; error: PolicyEvaluatedFailure };

export interface PolicyEvaluatedFailure {
  code:
    | "daily_limit_exceeded"
    | "max_per_tx_exceeded"
    | "policy_ambiguous"
    | "policy_failure"
    | "invalid_voucher"
    | "network_error"
    | "unauthorized_merchant"
    | "counterparty_blocked"
    | "session_expired"
    | "human_approval_required"
    | "rate_limited";
  detail: string;
}

export interface PreFlightReport {
  willSucceed: boolean;
  reason: string;
  remainingAllowanceMicro: bigint;
  requiresHumanApproval: boolean;
  tier: 1 | 2 | 3 | null;
}

export interface LedgerEntry {
  merchant: string;
  cumulativeAmount: bigint;
  lastSignedAt: number;
}

export const MICRO_USDC_DECIMALS = 6;

/** Parse a decimal USDC string ("0.01" | "3.4") into atomic micro units. */
export function parseUsdToMicro(amount: string): bigint {
  if (!/^\d+(\.\d{1,6})?$/.test(amount)) {
    throw new Error(`invalid USDC amount: ${amount}`);
  }
  const [whole, frac = ""] = amount.split(".");
  const paddedFrac = (frac + "0".repeat(MICRO_USDC_DECIMALS)).slice(0, MICRO_USDC_DECIMALS);
  return BigInt(whole + paddedFrac);
}

/** Format atomic micro-USDC back into a decimal string. */
export function formatMicroUsd(micro: bigint): string {
  const neg = micro < 0n;
  const abs = neg ? -micro : micro;
  const whole = abs / 1_000_000n;
  const frac = abs % 1_000_000n;
  const fracStr = frac.toString().padStart(6, "0").replace(/0+$/, "");
  const body = fracStr === "" ? whole.toString() : `${whole}.${fracStr}`;
  return neg ? `-${body}` : body;
}
