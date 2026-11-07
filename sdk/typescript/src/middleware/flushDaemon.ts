/**
 * Flush daemon (docs/ARCHITECTURE.md Module 3, docs/SECURITY.md INV-M3).
 * Consumes FlushPlans from the VoucherAccumulator and settles them on-chain.
 * Receipts are persisted ONLY after chain confirmation (INV-M3: exactly-once
 * pattern); replays of already-settled vouchers are detected and recorded as
 * no-ops — the vault's own monotonicity guard (INV-1) is the backstop.
 */
import { Contract, type Provider, type Signer } from "ethers";

import paythosVaultAbi from "../abi/paythosVault.json";
import { Voucher } from "../types.js";
import { FlushPlan, MerchantVerifierConfig, VoucherAccumulator } from "./merchant.js";

export interface FlushReceipt {
  agentKey: string;
  merchant: string;
  cumulativeAmount: string;
  txHash: string | null;
  settledAt: number;
  /** True when the voucher was already settled on-chain (no-op flush). */
  alreadySettled: boolean;
}

export interface ReceiptStore {
  load(): Promise<Map<string, FlushReceipt>>;
  save(receipt: FlushReceipt): Promise<void>;
}

export class MemoryReceiptStore implements ReceiptStore {
  readonly #receipts = new Map<string, FlushReceipt>();
  async load(): Promise<Map<string, FlushReceipt>> {
    return new Map(this.#receipts);
  }
  async save(receipt: FlushReceipt): Promise<void> {
    this.#receipts.set(receiptKey(receipt), receipt);
  }
}

/** JSON-file store with atomic (tmp+rename) writes — crash-safe INV-M3. */
export class JsonReceiptStore implements ReceiptStore {
  readonly #path: string;
  #loaded: Map<string, FlushReceipt> | undefined;

  constructor(path: string) {
    this.#path = path;
  }

  async load(): Promise<Map<string, FlushReceipt>> {
    if (this.#loaded) return new Map(this.#loaded);
    const map = new Map<string, FlushReceipt>();
    try {
      const raw = await import("node:fs/promises").then((fs) => fs.readFile(this.#path, "utf8"));
      const parsed = JSON.parse(raw) as Record<string, FlushReceipt>;
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v?.agentKey === "string" && typeof v?.cumulativeAmount === "string") {
          map.set(k, v);
        }
      }
    } catch {
      /* missing or corrupt file starts from empty — fail-safe */
    }
    this.#loaded = map;
    return new Map(map);
  }

  async save(receipt: FlushReceipt): Promise<void> {
    const fs = await import("node:fs/promises");
    const map = this.#loaded ?? (await this.load());
    map.set(receiptKey(receipt), receipt);
    const doc: Record<string, FlushReceipt> = {};
    for (const [k, v] of map) doc[k] = v;
    const tmp = `${this.#path}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(doc, null, 2), "utf8");
    await fs.rename(tmp, this.#path);
  }
}

export function receiptKey(agentKeyOrReceipt: string | FlushReceipt): string {
  if (typeof agentKeyOrReceipt === "string") return agentKeyOrReceipt;
  const r = agentKeyOrReceipt;
  return `${r.agentKey.toLowerCase()}:${r.merchant.toLowerCase()}`;
}

type SubmitResult = { kind: "submitted"; txHash: string } | { kind: "already_settled" };

export interface VaultSubmitter {
  claim(voucher: Voucher, signature: string): Promise<SubmitResult>;
}

/** Real submitter: ethers Signer + the deployed PaythosVault ABI. */
interface VaultContractLike {
  claimed(agentKey: string, merchant: string): Promise<bigint>;
  connect(signer: Signer): {
    claimVoucher(voucher: unknown, signature: string): Promise<{ wait(): Promise<{ status: number } | null>; hash: string }>;
  };
}

export class EthersVaultSubmitter implements VaultSubmitter {
  readonly #wallet: Signer;
  readonly #contract: VaultContractLike;

  constructor(wallet: Signer, vaultAddress: string, provider: Provider) {
    this.#wallet = wallet;
    const walletProvider = (wallet as { provider?: Provider }).provider ?? provider;
    this.#contract = new Contract(vaultAddress, paythosVaultAbi as unknown as [], walletProvider) as unknown as VaultContractLike;
  }

  async claim(voucher: Voucher, signature: string): Promise<SubmitResult> {
    const already = await this.#contract.claimed(voucher.agentKey, voucher.merchant);
    if (already >= voucher.cumulativeAmount) return { kind: "already_settled" };
    const tx = await this.#contract.connect(this.#wallet).claimVoucher(
      {
        agentKey: voucher.agentKey,
        merchant: voucher.merchant,
        token: voucher.token,
        cumulativeAmount: voucher.cumulativeAmount,
        validUntil: voucher.validUntil,
        memo: voucher.memo,
      },
      signature,
    );
    const receipt = (await tx.wait()) as { status: number; hash: string } | null;
    if (!receipt || receipt.status !== 1) {
      throw new Error(`flush transaction reverted (tx ${tx.hash})`);
    }
    return { kind: "submitted", txHash: receipt.hash };
  }
}

export interface FlushDaemonOptions {
  submitter: VaultSubmitter;
  receipts: ReceiptStore;
  onError?: (err: unknown, plan: FlushPlan) => void;
}

/**
 * Subscribes to an accumulator's onFlushReady and performs exactly-once
 * on-chain settlement with persisted receipts (INV-M3).
 */
export class FlushDaemon {
  readonly #opts: FlushDaemonOptions;
  #accumulator: VoucherAccumulator | undefined;
  #received: Map<string, FlushReceipt> | undefined;
  readonly #inFlight = new Set<string>();

  constructor(opts: FlushDaemonOptions) {
    this.#opts = opts;
  }

  /** Replace the accumulator's flush trigger with daemon settlement handling. */
  attach(cfg: MerchantVerifierConfig | VoucherAccumulator): this {
    const acc = cfg instanceof VoucherAccumulator ? cfg : new VoucherAccumulator(cfg);
    const config: MerchantVerifierConfig = (acc as unknown as { cfg: MerchantVerifierConfig }).cfg;
    config.onFlushReady = (plan) => this.settle(plan, acc);
    this.#accumulator = acc;
    return this;
  }

  /** Install an accumulator for later settle() calls (CLI/ops wiring). */
  use(acc: VoucherAccumulator): this {
    this.#accumulator = acc;
    return this;
  }

  /** Test/ops visibility: receipts observed so far (loaded from store). */
  async receipts(): Promise<Map<string, FlushReceipt>> {
    return this.#loaded();
  }

  async #loaded(): Promise<Map<string, FlushReceipt>> {
    this.#received ??= await this.#opts.receipts.load();
    return this.#received;
  }

  async settle(plan: FlushPlan, acc?: VoucherAccumulator): Promise<void> {
    const accumulator = acc ?? this.#accumulator;
    const key = receiptKeyOfPlan(plan);
    if (this.#inFlight.has(key)) return;
    this.#inFlight.add(key);
    try {
      const received = await this.#loaded();
      const prior = received.get(key);
      if (prior && (prior.txHash !== null || prior.alreadySettled) && BigInt(prior.cumulativeAmount) >= plan.voucher.cumulativeAmount) {
        return; // INV-M3: exactly-once — already confirmed on-chain
      }
      const result = await this.#opts.submitter.claim(plan.voucher, plan.signature);
      const receipt: FlushReceipt = {
        agentKey: plan.agentKey,
        merchant: plan.merchant.toLowerCase(),
        cumulativeAmount: plan.voucher.cumulativeAmount.toString(),
        txHash: result.kind === "submitted" ? result.txHash : null,
        settledAt: Math.floor(Date.now() / 1000),
        alreadySettled: result.kind === "already_settled",
      };
      await this.#opts.receipts.save(receipt); // persisted ONLY after confirmation
      received.set(key, receipt);
      accumulator?.markSettled(plan.agentKey, plan.voucher.cumulativeAmount);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("InvalidVoucherAmount")) {
        // Vault rejected as stale ⇒ something settled it before us. Record
        // without a tx hash so the receipt still blocks re-submission.
        const receipt: FlushReceipt = {
          agentKey: plan.agentKey,
          merchant: plan.merchant.toLowerCase(),
          cumulativeAmount: plan.voucher.cumulativeAmount.toString(),
          txHash: null,
          settledAt: Math.floor(Date.now() / 1000),
          alreadySettled: true,
        };
        await this.#opts.receipts.save(receipt);
        (await this.#loaded()).set(key, receipt);
        accumulator?.markSettled(plan.agentKey, plan.voucher.cumulativeAmount);
        return;
      }
      const onError = this.#opts.onError ?? defaultOnError;
      onError(err, plan);
    } finally {
      this.#inFlight.delete(key);
    }
  }
}

function receiptKeyOfPlan(plan: FlushPlan): string {
  return `${plan.agentKey.toLowerCase()}:${plan.merchant.toLowerCase()}`;
}

function defaultOnError(err: unknown, plan: FlushPlan): void {
  console.error(`[paythos-flush] settlement failed for ${plan.agentKey}:`, err);
}
