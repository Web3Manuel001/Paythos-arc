/**
 * Circle Developer-Controlled Wallets EIP-712 signer.
 *
 * The agent's private key never enters the SDK or this process: Circle holds the
 * key in its MPC/HSM custody and returns an EIP-712 signature over the Paythos
 * voucher. This keeps AGENTS.md rule 1 (non-custodial for the human owner) intact
 * because the wallet is still owner-controlled in Circle, not by Paythos.
 *
 * EOA wallets return a recoverable ECDSA signature; SCA wallets return an
 * ERC-1271 signature. PaythosVault uses OpenZeppelin `SignatureChecker`, which
 * accepts both.
 */
import type { TypedDataDomain } from "ethers";
import { getAddress } from "ethers";
import { PaythosError } from "../core/errors.js";
import type { LedgerEntry } from "../types.js";
import {
  AgentVoucherSigner,
  type EIP712TypedDataSigner,
  type SigningDomainArgs,
} from "./voucherSigner.js";

/** Minimal surface of Circle's developer-controlled wallet client (v10.x). */
export interface CircleWalletClientLike {
  signTypedData(input: {
    walletId: string;
    data: string;
    memo?: string;
  }): Promise<{ data?: { signature?: string } }>;
}

export interface CircleWalletSignerOptions {
  client: CircleWalletClientLike;
  walletId: string;
  /** On-chain address of the Circle wallet (from getWallet/createWallets). */
  walletAddress: string;
  domain: SigningDomainArgs;
  epoch: number;
  ledger?: Map<string, LedgerEntry>;
  voucherTtlSeconds?: number;
  /** Human-readable Circle audit memo; never contains secrets. */
  memo?: string;
}

const EIP712_DOMAIN_TYPES = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
] as const;

/**
 * Build an `AgentVoucherSigner` whose EIP-712 signatures come from Circle.
 * The address can be EOA or SCA; VOUCHER_TYPES/domain are identical either way.
 */
export function createCircleWalletVoucherSigner(options: CircleWalletSignerOptions): AgentVoucherSigner {
  const walletAddress = getAddress(options.walletAddress);
  const externalSigner: EIP712TypedDataSigner = {
    address: walletAddress,
    async signTypedData(
      domain: TypedDataDomain,
      types: Record<string, Array<{ name: string; type: string }>>,
      value: Record<string, unknown>,
    ): Promise<string> {
      const payload = {
        types: { EIP712Domain: EIP712_DOMAIN_TYPES, ...types },
        primaryType: "Voucher",
        domain,
        message: toJsonSafe(value),
      };
      const response = await options.client.signTypedData({
        walletId: options.walletId,
        data: JSON.stringify(payload),
        memo: options.memo ?? `Paythos voucher epoch ${options.epoch}`,
      });
      const signature = response.data?.signature;
      if (signature === undefined || signature.length === 0) {
        throw new PaythosError("policy_failure", "Circle signTypedData returned no signature");
      }
      return signature;
    },
  };

  return new AgentVoucherSigner({
    externalSigner,
    domain: options.domain,
    epoch: options.epoch,
    ...(options.ledger === undefined ? {} : { ledger: options.ledger }),
    ...(options.voucherTtlSeconds === undefined ? {} : { voucherTtlSeconds: options.voucherTtlSeconds }),
  });
}

/** EIP-712 payloads are JSON; bigint uint256 fields must become decimal strings. */
export function toJsonSafe(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(toJsonSafe);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, toJsonSafe(entry)]),
    );
  }
  return value;
}

