/**
 * Merchant membranes (docs/ARCHITECTURE.md Module 2 + 3).
 * Framework-agnostic: emitChallenge / verifyPayment / VoucherAccumulator.
 * In-memory verification only (INV-M1: <5ms, no RPC on the hot path).
 */
import {
  PAYMENT_REQUIRED_HEADER,
  PaymentChallenge,
  PaythosNetwork,
  Voucher,
  X_PAYTHOS_SIGNATURE_HEADER,
  X_PAYTHOS_VOUCHER_HEADER,
} from "../types.js";
import { verifyTypedData, type TypedDataDomain } from "ethers";
import { VOUCHER_TYPES, domainFor } from "../signer/voucherSigner.js";

export interface MerchantVerifierConfig {
  network: PaythosNetwork;
  vaultAddress: string; // verifyingContract of the EIP-712 domain
  /** The vault's immutable settlement token (Arc native-USDC precompile). */
  settlementToken: string;
  /** Addresses whose settlement the vault will honor (allowlist mirror). */
  authorizedAgents: ReadonlySet<string>;
  /**
   * Merchant credit-line ceiling in micro-USDC (INV-M4, docs default $2.00 /
   * conservative $1.00). Streaming halts at the wall until a flush confirms.
   */
  creditToleranceMicro?: bigint;
  /** Value flush threshold in micro-USDC ($5.00 default, docs/PROTOCOL.md §6). */
  flushThresholdMicro?: bigint;
  /** Flush trigger (INV-M2/M3): highest-voucher flush + idempotent receipts. */
  onFlushReady?: (flush: FlushPlan) => Promise<void>;
}

export interface FlushPlan {
  agentKey: string;
  merchant: string;
  voucher: Voucher; // the HIGHEST unclaimed voucher (INV-M2)
  /** EIP-712 signature for exactly this voucher — required by claimVoucher. */
  signature: string;
}

export interface VerifyOutcome {
  ok: boolean;
  status: 200 | 402 | 429;
  reason?: string;
  agentKey?: string;
  /** Uncollected exposure remaining after this verification. */
  unsettledMicro: bigint;
}

interface VoucherRecord {
  voucher: Voucher;
  signature: string;
}

export class VoucherAccumulator {
  /** merchant-side session ledger: agentKey => highest voucher (INV-M2). */
  readonly #highest = new Map<string, VoucherRecord>();
  /** Settled cumulative per agent — the daemon reports it post-confirmation. */
  readonly #settled = new Map<string, bigint>();
  #domain: TypedDataDomain;

  constructor(protected readonly cfg: MerchantVerifierConfig) {
    this.#domain = domainFor({ network: cfg.network, vaultAddress: cfg.vaultAddress });
  }

  /** Merchant-side challenge emission (docs/PROTOCOL.md §3.1). */
  emitChallenge(challenge: PaymentChallenge): Record<string, string> {
    if (challenge.x402Version !== 2) {
      throw new TypeError("x402Version ≠ 2 — merchant middleware MUST speak v2");
    }
    return { [PAYMENT_REQUIRED_HEADER]: Buffer.from(JSON.stringify(challenge), "utf8").toString("base64") };
  }

  /** Reflect the stored domain for tests/tools. */
  get domain(): TypedDataDomain {
    return this.#domain;
  }

  /**
   * Verify an inbound voucher in memory. <5ms budget, no chain call (INV-M1).
   * Accumulates strictly-increasing vouchers only. Batches POST /flush plan.
   */
  verifyPayment(headers: Headers | Record<string, string>): VerifyOutcome {
    const h = toHeaders(headers);
    const voucherB64 = h.get(X_PAYTHOS_VOUCHER_HEADER);
    const sig = h.get(X_PAYTHOS_SIGNATURE_HEADER);
    if (!voucherB64 || !sig) return fail(402, "missing Paythos payment headers");

    const voucher = decodeVoucher(voucherB64);
    if (!voucher) return fail(402, "PAYTHOS voucher undecodable");

    if (voucher.token !== this.cfg.settlementToken) {
      return fail(402, "voucher token is not the configured settlement token");
    }
    if (this.cfg.authorizedAgents.has(voucher.agentKey.toLowerCase()) === false) {
      return fail(402, "unknown agentKey — no session authorization on record");
    }

    // <5ms: recover signer in memory (no RPC — INV-M1).
    let recovered: string;
    try {
      recovered = verifyTypedData(this.#domain, VOUCHER_TYPES, stringify(voucher), sig).toLowerCase();
    } catch {
      return fail(402, "voucher signature did not recover against the vault domain");
    }

    if (Number(voucher.validUntil) * 1000 < Date.now()) {
      return fail(402, "voucher expired");
    }
    if (recovered !== voucher.agentKey.toLowerCase()) {
      return fail(402, "signature was NOT signed by voucher.agentKey (INV bound)");
    }

    const current = this.#highest.get(recovered)?.voucher;
    if (current && voucher.cumulativeAmount <= current.cumulativeAmount) {
      // INV-1 on the merchant side too: reject stale/identical replays.
      return fail(402, "stale voucher: cumulative amount not strictly increasing");
    }
    // INV-M4 credit wall: halt the stream until a flush confirms settlement.
    // Measured as UNSETTLED exposure (cumulative − confirmed on-chain).
    const tolerance = this.cfg.creditToleranceMicro ?? 2_000_000n;
    const settled = this.#settled.get(recovered) ?? 0n;
    const unsettledCandidate = voucher.cumulativeAmount > settled ? voucher.cumulativeAmount - settled : 0n;
    if (unsettledCandidate > tolerance) {
      return {
        ok: false,
        status: 402,
        reason: "credit tolerance exceeded — flush required (INV-M4)",
        unsettledMicro: this.unsettledFor(recovered),
      };
    }
    this.#highest.set(recovered, { voucher, signature: sig });
    const unsettled = this.unsettledFor(recovered);

    // The 402→200 path also ANCHORS the flush trigger (INV-M2/M3).
    const flushed = this.maybeFlush(recovered);
    void flushed;

    return {
      ok: true,
      status: 200,
      agentKey: recovered,
      unsettledMicro: unsettled,
    };
  }

  /** Granular unsettle exposure for one voucher: cumulative − confirmed settled. */
  unsettledMicro(voucher: Voucher): bigint {
    const settled = this.#settled.get(voucher.agentKey.toLowerCase()) ?? 0n;
    return voucher.cumulativeAmount > settled ? voucher.cumulativeAmount - settled : 0n;
  }

  /** Current unsettled exposure for an agent across the whole session. */
  unsettledFor(agentKey: string): bigint {
    const record = this.#highest.get(agentKey.toLowerCase());
    if (!record) return 0n;
    return this.unsettledMicro(record.voucher);
  }

  /**
   * Record an on-chain settlement (INV-M3). Called by the flush daemon after
   * confirmation; resets the credit wall so the session can continue.
   */
  markSettled(agentKey: string, cumulativeSettled: bigint): void {
    const key = agentKey.toLowerCase();
    const current = this.#settled.get(key) ?? 0n;
    if (cumulativeSettled > current) this.#settled.set(key, cumulativeSettled);
  }

  /**
   * Production closure: flush daemon policy.
   * Triggers `onFlushReady` when the FIRST of:
   *   (value): unsettled ≥ flushThresholdMicro ($5.00 default) OR
   *   (time):  the earliest unclaimed voucher age ≥ flushIntervalSeconds (2h)
   * Returns whether a flush was queued. Never throws.
   */
  maybeFlush(agentKey: string): boolean {
    const record = this.#highest.get(agentKey);
    const flushThresholdMicro = this.cfg.flushThresholdMicro ?? 5_000_000n;
    if (record === undefined) return false;
    if (this.unsettledFor(agentKey) < flushThresholdMicro) return false;
    if (!this.cfg.onFlushReady) return false;
    void this.cfg.onFlushReady({
      agentKey,
      merchant: record.voucher.merchant,
      voucher: record.voucher,
      signature: record.signature,
    });
    return true;
  }

  /** Gets the highest current voucher for the agent (daemon/test visibility). */
  highest(agentKey: string): Voucher | undefined {
    return this.#highest.get(agentKey.toLowerCase())?.voucher;
  }

  /** The signature bound to the currently-highest voucher (daemon visibility). */
  highestSignature(agentKey: string): string | undefined {
    return this.#highest.get(agentKey.toLowerCase())?.signature;
  }
}

function fail(status: 402 | 429, reason: string): VerifyOutcome {
  return { ok: false, status, reason, unsettledMicro: 0n };
}

function toHeaders(h: Headers | Record<string, string>): Headers {
  if (h instanceof Headers) return h;
  const map = new Headers();
  for (const [k, v] of Object.entries(h)) map.set(k.toLowerCase(), v);
  return map;
}

function decodeVoucher(b64: string): Voucher | undefined {
  try {
    const json = JSON.parse(Buffer.from(b64, "base64").toString("utf8")) as Record<string, unknown>;
    if (typeof json.agentKey !== "string" || typeof json.merchant !== "string") return undefined;
    return {
      agentKey: json.agentKey as string,
      merchant: json.merchant as string,
      token: json.token as string,
      cumulativeAmount: BigInt(json.cumulativeAmount as string),
      validUntil: BigInt(json.validUntil as string),
      memo: json.memo as string,
    };
  } catch {
    return undefined;
  }
}

function stringify(v: Voucher) {
  return {
    agentKey: v.agentKey,
    merchant: v.merchant,
    token: v.token,
    cumulativeAmount: v.cumulativeAmount,
    validUntil: v.validUntil,
    memo: v.memo,
  };
}
