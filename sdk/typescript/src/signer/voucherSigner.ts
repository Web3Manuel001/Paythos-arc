/**
 * AgentVoucherSigner (docs/ARCHITECTURE.md Module 2.1).
 * EIP-712 cumulative voucher signing, fully in-memory, zero gas, <5ms target.
 * The ledger is monotonic per (merchant) — INV-1 is enforced CLIENT-SIDE here
 * and BACKED by the vault contract. Ledger state never farms downward.
 */
import {
  CHAIN_REGISTRY,
  LedgerEntry,
  PaythosNetwork,
  Voucher,
  X_PAYTHOS_SIGNATURE_HEADER,
  X_PAYTHOS_VOUCHER_HEADER,
} from "../types.js";
import { Wallet, getAddress, type TypedDataDomain } from "ethers";
import { PaythosError } from "../core/errors.js";

export const VOUCHER_TYPES: Record<string, Array<{ name: string; type: string }>> = {
  Voucher: [
    { name: "agentKey", type: "address" },
    { name: "merchant", type: "address" },
    { name: "token", type: "address" },
    { name: "cumulativeAmount", type: "uint256" },
    { name: "validUntil", type: "uint256" },
    { name: "epoch", type: "uint64" },
    { name: "memo", type: "bytes32" },
  ],
};

export interface SigningDomainArgs {
  network: PaythosNetwork;
  vaultAddress: string;
  /** Only for tests or explicit chain-ID overrides (fail-closed by default). */
  chainIdOverride?: number;
}

export interface AgentVoucherSignerConfig {
  /** Ephemeral key from PAYTHOS_EPHEMERAL_KEY (AGENTS.md secrets hygiene). */
  privateKey: string;
  domain: SigningDomainArgs;
  /**
   * Delegation epoch to embed in every voucher (INV-6). The agent service
   * reads it from `VaultReader.epochOf(agentKey)` right after authorizeAgent
   * and after every re-authorization. Mandatory — fail closed on omission.
   */
  epoch: number;
  /** Ledger persistence (memory-only when absent — see README restart caveat). */
  ledger?: Map<string, LedgerEntry>;
  /** Session TTL default: vouchers expire in 1 hour unless overridden. */
  voucherTtlSeconds?: number;
}

export type VoucherSigned =
  | { ok: true; voucher: Voucher; signature: string; headers: Record<string, string> }
  | { ok: false; error: { code: "policy_ambiguous"; detail: string } };

const MEMO_RE = /^0x[0-9a-f]{64}$/i;

export class AgentVoucherSigner {
  readonly #wallet: Wallet;
  readonly #ledger: Map<string, LedgerEntry>;
  readonly #ttl: number;
  #domain: TypedDataDomain;
  #epoch: number;

  constructor(cfg: AgentVoucherSignerConfig) {
    this.#wallet = new Wallet(cfg.privateKey);
    this.#ledger = cfg.ledger ?? new Map();
    this.#ttl = cfg.voucherTtlSeconds ?? 3600;
    this.#epoch = cfg.epoch;
    this.#domain = domainFor(cfg.domain);
  }

  /** Agent address — for budget telemetry (MCP `get_vault_budget`). */
  get agentKey(): string {
    return getAddress(this.#wallet.address);
  }

  /** (Re)bind the EIP-712 domain after e.g. a vault redeploy. */
  rebind(domain: SigningDomainArgs): void {
    this.#domain = domainFor(domain);
  }

  /**
   * Rotate the delegation epoch (INV-6): required after a re-authorization —
   * the NEXT voucher must carry the new epoch or the vault reverts with
   * `SessionEpochMismatch`. Also resets the local cumulative ledger (the
   * vault zeros claimed totals on the epoch bump).
   */
  setEpoch(epoch: number): void {
    if (!Number.isInteger(epoch) || epoch <= 0) {
      throw new PaythosError("policy_failure", `epoch must be a positive integer, got ${String(epoch)}`);
    }
    this.#epoch = epoch;
    this.#ledger.clear();
  }

  /** The epoch embedded in every voucher this signer produces (INV-6 people can audit). */
  get epoch(): number {
    return this.#epoch;
  }

  get domain(): Readonly<TypedDataDomain> {
    return this.#domain;
  }

  /**
   * Sign the session-total voucher for `merchant` covering an ADDITIONAL
   * `deltaMicro` (micro-USDC). INV-1: strictly monotonic, never downward.
   * The ledger only advances AFTER a successful sign — failure never corrupts it.
   */
  async recordAndSign(merchant: string, deltaMicro: bigint, memo: string, validUntil?: bigint): Promise<VoucherSigned> {
    if (deltaMicro <= 0n) {
      return { ok: false, error: { code: "policy_ambiguous", detail: "voucher delta must be positive" } };
    }
    if (!MEMO_RE.test(memo)) {
      return { ok: false, error: { code: "policy_ambiguous", detail: "memo must be bytes32 hex" } };
    }
    const lower = merchant.toLowerCase();
    const entry = this.#ledger.get(lower);
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nextTotal = (entry?.cumulativeAmount ?? 0n) + deltaMicro;
    const token = settlementTokenForDomain(this.#domain);
    if (token === undefined) {
      return { ok: false, error: { code: "policy_ambiguous", detail: "no verified settlement token for the bound chain" } };
    }
    const voucher: Voucher = {
      agentKey: getAddress(this.#wallet.address),
      merchant: getAddress(merchant),
      token,
      cumulativeAmount: nextTotal,
      validUntil: validUntil ?? now + BigInt(this.#ttl),
      epoch: this.#epoch,
      memo,
    };
    try {
      const signature = await signVoucher(this.#wallet, this.#domain, voucher);
      this.#ledger.set(lower, {
        merchant: getAddress(merchant),
        cumulativeAmount: nextTotal,
        lastSignedAt: Date.now(),
      });
      return { ok: true, voucher, signature, headers: buildVoucherHeaders(voucher, signature) };
    } catch (err) {
      return { ok: false, error: { code: "policy_ambiguous", detail: `signing failed: ${String(err)}` } };
    }
  }

  /**
   * Pin the ledger to an on-chain settlement (post-flush, INV-1): the vault
   * compares `cumulativeAmount` against `claimed` FOREVER — it never resets.
   * The old `resetMerchant()` deleted the entry, restarted cumulative at 0,
   * and every later claim reverted (reviewer catch). This only ever RAISES
   * the baseline to what the chain has actually recorded as claimed.
   */
  settleMerchant(merchant: string, claimedTotal: bigint): void {
    if (claimedTotal < 0n) {
      throw new PaythosError("policy_failure", "claimedTotal must be non-negative");
    }
    const lower = merchant.toLowerCase();
    const entry = this.#ledger.get(lower);
    if (entry && entry.cumulativeAmount >= claimedTotal) return; // ledger already ahead (signed but unclaimed)
    this.#ledger.set(lower, {
      merchant: getAddress(merchant),
      cumulativeAmount: claimedTotal,
      lastSignedAt: Date.now(),
    });
  }

  /** Current session ledger (MCP `get_vault_budget`, debugging). */
  ledgerSnapshot(): LedgerEntry[] {
    return [...this.#ledger.values()];
  }
}

/* ---------- domain + crypto helpers ---------- */

export function domainFor(args: SigningDomainArgs): TypedDataDomain {
  const registryEntry = CHAIN_REGISTRY[args.network];
  if (!registryEntry.verified || registryEntry.chainId === null) {
    // PROTOCOL-OPEN-Q1: fail closed on unverified chains (AGENTS.md rule 3).
    throw new PaythosError("chain_unverified", `chain ${args.network} not verified in registry`);
  }
  if (args.chainIdOverride !== undefined && registryEntry.chainId !== args.chainIdOverride) {
    throw new PaythosError("chain_unverified", `chainIdOverride ${args.chainIdOverride} disagrees with registry`);
  }
  return {
    name: "Paythos Protocol",
    version: "3", // PROTOCOL v3 — epoch-bound vouchers (INV-6); matches VoucherTypes.PROTOCOL_VERSION
    chainId: registryEntry.chainId,
    verifyingContract: getAddress(args.vaultAddress),
  };
}

/** The settlement token binding: Arc native-USDC from the (verified) registry.
 *  Gate 2.5 will add confirmConfig() on-chain reads; the registry is the single
 *  source of truth until then (docs/PROTOCOL.md §7). */
function settlementTokenForDomain(domain: TypedDataDomain): string | undefined {
  for (const entry of Object.values(CHAIN_REGISTRY)) {
    if (entry.chainId === domain.chainId && entry.verified) {
      return entry.nativeUsdc ? entry.nativeUsdc : undefined;
    }
  }
  return undefined;
}

export async function signVoucher(wallet: Wallet, domain: TypedDataDomain, voucher: Voucher): Promise<string> {
  return wallet.signTypedData(domain, VOUCHER_TYPES, {
    agentKey: voucher.agentKey,
    merchant: voucher.merchant,
    token: voucher.token,
    cumulativeAmount: voucher.cumulativeAmount,
    validUntil: voucher.validUntil,
    epoch: voucher.epoch,
    memo: voucher.memo,
  });
}

/** Wire headers (docs/PROTOCOL.md §1.3). */
export function buildVoucherHeaders(voucher: Voucher, signature: string): Record<string, string> {
  const payload = Buffer.from(JSON.stringify(voucherStringMap(voucher)), "utf8").toString("base64");
  return {
    [X_PAYTHOS_VOUCHER_HEADER]: payload,
    [X_PAYTHOS_SIGNATURE_HEADER]: signature,
  };
}

function voucherStringMap(v: Voucher): Record<string, string> {
  return {
    agentKey: v.agentKey,
    merchant: v.merchant,
    token: v.token,
    cumulativeAmount: v.cumulativeAmount.toString(),
    validUntil: v.validUntil.toString(),
    epoch: v.epoch.toString(),
    memo: v.memo,
  };
}

