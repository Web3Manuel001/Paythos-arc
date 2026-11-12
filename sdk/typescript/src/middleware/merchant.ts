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
import { TokenBucket } from "../core/tokenBucket.js";

export interface MerchantChallengeContext {
  method: string;
  url: string;
}

export interface MerchantVerifierConfig {
  network: PaythosNetwork;
  vaultAddress: string; // verifyingContract of the EIP-712 domain
  /** The vault's immutable settlement token (Arc native-USDC precompile). */
  settlementToken: string;
  /**
   * Payee binding (fail closed): the ONLY merchant address this middleware
   * will accept vouchers for. Since vouchers settle `merchant → payee`, a
   * voucher for any other merchant must never unlock these resources (and
   * must never enter this payee's ledger).
   */
  merchantAddress: string;
  /**
   * ACTIVE delegation epochs per agentKey (lowercase ⇒ epoch, INV-6).
   * Voucher signatures bind to the epoch; stale-epoch vouchers are rejected
   * (fail closed) even when their EIP-712 signature verifies.
   */
  authorizedAgents: ReadonlyMap<string, number>;
  /**
   * x402 challenge factory (PROTOCOL.md §3.1). Requests WITHOUT payment
   * headers get a 402 PAYMENT-REQUIRED challenge instead of a free pass —
   * the middleware GATES (reviewer catch: it passed everything through).
   */
  challengeFor?: (ctx: MerchantChallengeContext) => PaymentChallenge;
  /**
   * Merchant credit-line ceiling in micro-USDC (INV-M4, docs default $2.00 /
   * conservative $1.00). Streaming halts at the wall until a flush confirms.
   */
  creditToleranceMicro?: bigint;
  /** Value flush threshold in micro-USDC ($5.00 default, docs/PROTOCOL.md §6). */
  flushThresholdMicro?: bigint;
  /** Age-based flush trigger: unsettled > 0 for ≥ N seconds (2h default). */
  flushIntervalSeconds?: number;
  /** Flush trigger (INV-M2/M3): highest-voucher flush + idempotent receipts. */
  onFlushReady?: (flush: FlushPlan) => Promise<void>;
  /**
   * INV-M6 transport limiter at the merchant boundary: a runaway loop is
   * throttled with 429 + Retry-After BEFORE any backend work. Per-agentKey
   * bucket; defaults 100 burst / 10 per second (spec default).
   */
  rateLimit?: { capacity: number; refillPerSecond: number };
  /**
   * Cheap pre-crypto limiter keyed by client IP / connection identity. Charged
   * BEFORE signature recovery so a flood of forged vouchers cannot burn CPU;
   * the per-agent bucket is charged only after the signature verifies.
   * Defaults 1000 burst / 100 per second (transport DDoS guard, not spend).
   */
  ipRateLimit?: { capacity: number; refillPerSecond: number };
  /** Hard cap on retained per-IP buckets (LRU-ish insertion eviction). Default 10_000. */
  maxIpBuckets?: number;
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
  /** Seconds until the next token (present only on 429 throttles). */
  retryAfterSeconds?: number;
}

interface VoucherRecord {
  voucher: Voucher;
  signature: string;
}

export class VoucherAccumulator {
  /** merchant-side session ledger: agentKey => highest voucher (INV-M2). */
  readonly #highest = new Map<string, VoucherRecord>();
  /**
   * Settled cumulative per agent, SCOPED to the delegation epoch: on-chain
   * claims reset to zero when the owner re-authorizes (INV-6 clean slate), so
   * a settlement reported for epoch N must never mask exposure in epoch N+1.
   */
  readonly #settled = new Map<string, { epoch: number; amount: bigint }>();
  /** Last activity per agent (voucher accepted or settlement confirmed). */
  readonly #lastActivityAt = new Map<string, number>();
  #domain: TypedDataDomain;

  readonly #buckets = new Map<string, TokenBucket>();
  /** Bounded per-client-IP buckets charged before any cryptographic work. */
  readonly #ipBuckets = new Map<string, TokenBucket>();

  readonly #merchant: string;
  readonly #maxIpBuckets: number;

  constructor(protected readonly cfg: MerchantVerifierConfig) {
    this.#domain = domainFor({ network: cfg.network, vaultAddress: cfg.vaultAddress });
    // Fail closed at construction: an unset/invalid payee would accept
    // vouchers settling to someone else.
    if (typeof cfg.merchantAddress !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(cfg.merchantAddress)) {
      throw new TypeError("merchantAddress must be a 20-byte hex address (payee binding, fail closed)");
    }
    this.#merchant = cfg.merchantAddress.toLowerCase();
    // Fail closed at construction: an invalid limiter config must not surface
    // as a runtime 500 under attack.
    const limit = cfg.rateLimit ?? { capacity: 100, refillPerSecond: 10 };
    if (!Number.isFinite(limit.capacity) || limit.capacity < 1) {
      throw new RangeError(`rateLimit.capacity must be >= 1 (got ${String(limit.capacity)})`);
    }
    if (!Number.isFinite(limit.refillPerSecond) || limit.refillPerSecond <= 0) {
      throw new RangeError(`rateLimit.refillPerSecond must be > 0 (got ${String(limit.refillPerSecond)})`);
    }
    const ipLimit = cfg.ipRateLimit ?? { capacity: 1_000, refillPerSecond: 100 };
    if (!Number.isFinite(ipLimit.capacity) || ipLimit.capacity < 1) {
      throw new RangeError(`ipRateLimit.capacity must be >= 1 (got ${String(ipLimit.capacity)})`);
    }
    if (!Number.isFinite(ipLimit.refillPerSecond) || ipLimit.refillPerSecond <= 0) {
      throw new RangeError(`ipRateLimit.refillPerSecond must be > 0 (got ${String(ipLimit.refillPerSecond)})`);
    }
    const maxIpBuckets = cfg.maxIpBuckets ?? 10_000;
    if (!Number.isInteger(maxIpBuckets) || maxIpBuckets < 1) {
      throw new RangeError(`maxIpBuckets must be an integer >= 1 (got ${String(maxIpBuckets)})`);
    }
    this.#maxIpBuckets = maxIpBuckets;
  }

  /** Merchant-side challenge emission (docs/PROTOCOL.md §3.1). */
  emitChallenge(challenge: PaymentChallenge): Record<string, string> {
    if (challenge.x402Version !== 2) {
      throw new TypeError("x402Version ≠ 2 — merchant middleware MUST speak v2");
    }
    this.assertPayee(challenge);
    return { [PAYMENT_REQUIRED_HEADER]: Buffer.from(JSON.stringify(challenge), "utf8").toString("base64") };
  }

  /**
   * Payee/pricing single source of truth: the emitted challenge MUST settle to
   * `merchantAddress`. Otherwise the voucher this middleware later accepts and
   * the destination it advertises silently drift apart (reviewer 2026-11).
   */
  assertPayee(challenge: PaymentChallenge): void {
    if (typeof challenge.payTo !== "string" || challenge.payTo.toLowerCase() !== this.#merchant) {
      throw new TypeError("challenge.payTo must equal merchantAddress (payee drift, fail closed)");
    }
  }

  /** Reflect the stored domain for tests/tools. */
  get domain(): TypedDataDomain {
    return this.#domain;
  }

  /**
   * Verify an inbound voucher in memory. <5ms budget, no chain call (INV-M1).
   * Accumulates strictly-increasing vouchers only. Batches POST /flush plan.
   */
  /**
   * Verify an inbound voucher in memory. <5ms budget, no chain call (INV-M1).
   * Accepts BOTH wire formats (reviewer catch: they were disjoint):
   *   - x402 v2 `PAYMENT-SIGNATURE` JSON envelope `{ voucher, signature }`
   *   - native `-paythos-voucher` (base64 JSON) + `-paythos-signature` pair
   * Accumulates strictly-increasing vouchers only. Batches POST /flush plan.
   */
  verifyPayment(headers: Headers | Record<string, string>, clientId?: string): VerifyOutcome {
    const h = toHeaders(headers);
    const envelope = h.get("payment-signature");
    let voucher: Voucher | undefined;
    let signature: string | undefined;

    if (envelope !== null) {
      // x402 v2 envelope (PROTOCOL.md §3): JSON `{ voucher, signature }`.
      const x402 = decodePaymentSignature(envelope);
      if (!x402) return fail(402, "PAYMENT-SIGNATURE envelope undecodable");
      voucher = x402.voucher;
      signature = x402.signature;
    } else {
      const voucherB64 = h.get(X_PAYTHOS_VOUCHER_HEADER);
      signature = h.get(X_PAYTHOS_SIGNATURE_HEADER) ?? undefined;
      if (!voucherB64 || !signature) return fail(402, "missing Paythos payment headers");
      voucher = decodeVoucher(voucherB64);
      if (!voucher) return fail(402, "PAYTHOS voucher undecodable");
    }
    return this.#verifyCore(voucher, signature, clientId);
  }

  /**
   * Per-client-IP transport bucket. Charged before signature recovery so a
   * forged-voucher flood cannot consume CPU; bounded so untrusted identities
   * cannot grow the map without limit.
   */
  #ipLimitFor(clientId: string): TokenBucket {
    let bucket = this.#ipBuckets.get(clientId);
    if (bucket === undefined) {
      if (this.#ipBuckets.size >= this.#maxIpBuckets) {
        const oldest = this.#ipBuckets.keys().next().value;
        if (oldest !== undefined) this.#ipBuckets.delete(oldest);
      }
      bucket = new TokenBucket(this.cfg.ipRateLimit ?? { capacity: 1_000, refillPerSecond: 100 });
      this.#ipBuckets.set(clientId, bucket);
    }
    return bucket;
  }

  /** Per-agent bucket (created lazily; config-driven with spec defaults). */
  #limitFor(agentKey: string): TokenBucket {
    const key = agentKey.toLowerCase();
    let bucket = this.#buckets.get(key);
    if (bucket === undefined) {
      bucket = new TokenBucket(this.cfg.rateLimit ?? { capacity: 100, refillPerSecond: 10 });
      this.#buckets.set(key, bucket);
    }
    return bucket;
  }

  /** Shared verification pipeline used by both wire formats. */
  #verifyCore(voucher: Voucher, signature: string, clientId?: string): VerifyOutcome {
    // Cheap transport first: charge the client identity before any crypto, so
    // forged-voucher floods cannot burn CPU or exhaust a real agent's bucket.
    if (clientId !== undefined) {
      const ipThrottle = this.#ipLimitFor(clientId).tryConsume();
      if (!ipThrottle.allowed) {
        return fail(
          429,
          `transport rate limit — retry in ${ipThrottle.retryAfterSeconds}s`,
          ipThrottle.retryAfterSeconds,
        );
      }
    }
    if (voucher.token !== this.cfg.settlementToken) {
      return fail(402, "voucher token is not the configured settlement token");
    }
    // Payee binding: this middleware may only redeem vouchers made out to it.
    // Keying the ledger by agent alone let a voucher for merchant B collide
    // with (and unlock) merchant A's resources (reviewer 2026-11).
    if (voucher.merchant.toLowerCase() !== this.#merchant) {
      return fail(402, "voucher merchant is not this middleware's payee");
    }
    const lowerKey = voucher.agentKey.toLowerCase();
    const authorizedEpoch = this.cfg.authorizedAgents.get(lowerKey);
    if (authorizedEpoch === undefined) {
      return fail(402, "unknown agentKey — no session authorization on record");
    }
    // INV-6: a voucher signed under a dead delegation epoch never settles
    // here, even though its EIP-712 signature verifies perfectly.
    if (voucher.epoch !== authorizedEpoch) {
      return fail(402, "voucher epoch does not match the agent's active delegation (INV-6)");
    }
    // <5ms: recover signer in memory (no RPC — INV-M1).
    let recovered: string;
    try {
      recovered = verifyTypedData(this.#domain, VOUCHER_TYPES, stringify(voucher), signature).toLowerCase();
    } catch {
      return fail(402, "voucher signature did not recover against the vault domain");
    }

    if (Number(voucher.validUntil) * 1000 < Date.now()) {
      return fail(402, "voucher expired");
    }
    if (recovered !== lowerKey) {
      return fail(402, "signature was NOT signed by voucher.agentKey (INV bound)");
    }
    // INV-M6: charge the per-agent bucket only AFTER the signature verifies.
    // Charging earlier let 150 forged vouchers drain a real agent's bucket
    // and turn its next valid request into a 429 (reviewer 2026-11).
    const throttle = this.#limitFor(recovered).tryConsume();
    if (!throttle.allowed) {
      return fail(
        429,
        `local rate limit — retry in ${throttle.retryAfterSeconds}s`,
        throttle.retryAfterSeconds,
      );
    }

    // INV-1 on the merchant side, EPOCH-SCOPED: re-authorization resets the
    // on-chain cumulative claim to zero, so a new-epoch voucher may restart at
    // a lower value — carrying the old high-water over would reject valid
    // sessions and under-count fresh exposure (reviewer 2026-11).
    const current = this.#highest.get(recovered)?.voucher;
    const epochChanged = current !== undefined && current.epoch !== voucher.epoch;
    if (!epochChanged && current && voucher.cumulativeAmount <= current.cumulativeAmount) {
      return fail(402, "stale voucher: cumulative amount not strictly increasing");
    }
    // INV-M4 credit wall: halt the stream until a flush confirms settlement.
    // Measured as UNSETTLED exposure (cumulative − confirmed on-chain).
    const tolerance = this.cfg.creditToleranceMicro ?? 2_000_000n;
    const settled = this.#settledFor(recovered, voucher.epoch);
    const unsettledCandidate = voucher.cumulativeAmount > settled ? voucher.cumulativeAmount - settled : 0n;
    if (unsettledCandidate > tolerance) {
      return {
        ok: false,
        status: 402,
        reason: "credit tolerance exceeded — flush required (INV-M4)",
        unsettledMicro: this.unsettledFor(recovered),
      };
    }
    this.#highest.set(recovered, { voucher, signature });
    const unsettled = this.unsettledFor(recovered);

    // The 402→200 path also ANCHORS the flush trigger (INV-M2/M3).
    // Evaluated BEFORE the activity stamp resets: byTime must measure the
    // idle window that just elapsed — stamping first made the age trigger
    // mathematically unreachable (reviewer catch on flush triggers).
    const flushed = this.maybeFlush(recovered);
    void flushed;
    this.#lastActivityAt.set(recovered, Math.floor(Date.now() / 1000));

    return {
      ok: true,
      status: 200,
      agentKey: recovered,
      unsettledMicro: unsettled,
    };
  }

  /** Settled amount valid ONLY for the voucher's own delegation epoch. */
  #settledFor(agentKey: string, epoch: number): bigint {
    const record = this.#settled.get(agentKey);
    return record !== undefined && record.epoch === epoch ? record.amount : 0n;
  }

  /** Granular unsettled exposure for one voucher: cumulative − confirmed settled. */
  unsettledMicro(voucher: Voucher): bigint {
    const settled = this.#settledFor(voucher.agentKey.toLowerCase(), voucher.epoch);
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
   * `epoch` defaults to the epoch of the highest known voucher for this agent.
   * Late reports from a SUPERSEDED epoch are ignored — they cannot reduce the
   * new epoch's exposure.
   */
  markSettled(agentKey: string, cumulativeSettled: bigint, epoch?: number): void {
    const key = agentKey.toLowerCase();
    const effectiveEpoch = epoch ?? this.#highest.get(key)?.voucher.epoch;
    if (effectiveEpoch === undefined) return; // nothing to scope the report to
    const current = this.#settled.get(key);
    if (current !== undefined && effectiveEpoch < current.epoch) return; // stale era
    const base = current !== undefined && current.epoch === effectiveEpoch ? current.amount : 0n;
    if (current === undefined || current.epoch !== effectiveEpoch || cumulativeSettled > base) {
      this.#settled.set(key, { epoch: effectiveEpoch, amount: cumulativeSettled > base ? cumulativeSettled : base });
    }
    this.#lastActivityAt.set(key, Math.floor(Date.now() / 1000));
  }

  /**
   * Production closure: flush daemon policy.
   * Triggers `onFlushReady` when the FIRST of:
   *   (value): unsettled ≥ effective flush threshold, OR
   *   (time):  unsettled > 0 and age ≥ flushIntervalSeconds (2h default)
   * Effective threshold = min(flushThresholdMicro, credit wall − 1¢): the
   * default $5 flush threshold is ABOVE the default $2 credit wall, which
   * made flushes unreachable on defaults (reviewer catch) — the flush MUST
   * fire before the wall trips. Never throws.
   */
  maybeFlush(agentKey: string): boolean {
    const record = this.#highest.get(agentKey);
    if (record === undefined) return false;
    if (!this.cfg.onFlushReady) return false;
    const tolerance = this.cfg.creditToleranceMicro ?? 2_000_000n;
    const configured = this.cfg.flushThresholdMicro ?? 5_000_000n;
    const effectiveThreshold = configured < tolerance ? configured : tolerance > 1n ? tolerance - 1n : tolerance;
    const unsettled = this.unsettledFor(agentKey);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const lastActivity = this.#lastActivityAt.get(agentKey) ?? nowSeconds;
    const interval = this.cfg.flushIntervalSeconds ?? 7_200;
    const byValue = unsettled >= effectiveThreshold;
    const byTime = unsettled > 0n && nowSeconds - lastActivity >= interval;
    if (!byValue && !byTime) return false;
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

function fail(status: 402 | 429, reason: string, retryAfterSeconds?: number): VerifyOutcome {
  return {
    ok: false,
    status,
    reason,
    unsettledMicro: 0n,
    ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
  };
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
    const epoch = typeof json.epoch === "number" ? json.epoch : Number(json.epoch ?? NaN);
    if (!Number.isInteger(epoch)) return undefined;
    return {
      agentKey: json.agentKey as string,
      merchant: json.merchant as string,
      token: json.token as string,
      cumulativeAmount: BigInt(json.cumulativeAmount as string),
      validUntil: BigInt(json.validUntil as string),
      epoch,
      memo: json.memo as string,
    };
  } catch {
    return undefined;
  }
}

/** x402 v2 `PAYMENT-SIGNATURE` wire: plain JSON `{ voucher: {...}, signature }`. */
function decodePaymentSignature(raw: string): { voucher: Voucher; signature: string } | undefined {
  try {
    const json = JSON.parse(raw) as Record<string, unknown>;
    const voucherJson = json.voucher as Record<string, unknown> | undefined;
    const signature = json.signature;
    if (typeof voucherJson !== "object" || typeof signature !== "string") return undefined;
    if (typeof voucherJson.agentKey !== "string" || typeof voucherJson.merchant !== "string") return undefined;
    const epoch = Number(voucherJson.epoch ?? NaN);
    if (!Number.isInteger(epoch)) return undefined;
    return {
      voucher: {
        agentKey: voucherJson.agentKey as string,
        merchant: voucherJson.merchant as string,
        token: voucherJson.token as string,
        cumulativeAmount: BigInt(voucherJson.cumulativeAmount as string),
        validUntil: BigInt(voucherJson.validUntil as string),
        epoch,
        memo: voucherJson.memo as string,
      },
      signature,
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
    epoch: v.epoch,
    memo: v.memo,
  };
}
