/**
 * PaythosClient — x402 v2 auto-negotiation (docs/ARCHITECTURE.md Module 3.2).
 * Intercepts HTTP 402 challenges, runs the GOFER policy gate, signs a
 * cumulative EIP-712 voucher, retries once with the payment headers.
 * YOPO for `upto` streams: tokens for unrendered output are NEVER signed.
 */
import {
  PAYMENT_SIGNATURE_HEADER,
  PaymentChallenge,
  PaythosNetwork,
  PolicyEvaluatedFailure,
  PreFlightReport,
  Voucher,
  formatMicroUsd,
  parseUsdToMicro,
  X_PAYTHOS_STREAM_HEADER,
} from "../types.js";
import { AgentVoucherSigner } from "../signer/voucherSigner.js";
import { GoferPolicyEngine, TierThresholds } from "../core/policyEngine.js";
import { TokenBucket } from "../core/tokenBucket.js";
import { PaythosError } from "../core/errors.js";
import { HoldLedger } from "./holdLedger.js";
import { MeteringReport, parseMeteringReport, recoverMeteringSigner } from "./metering.js";

export interface TransactabilityOracle {
  /** Counterparty risk verdict (Module 4.2). Real store lands Gate 3. */
  approve(merchant: string): boolean;
}

export const AlwaysApprove: TransactabilityOracle = { approve: () => true };

/** Spec-default rolling allowance until on-chain telemetry lands (Gate 2.5). */
export const DEFAULT_ALLOWANCE_MICRO = 20_000_000n;

export interface PaythosClientOptions {
  signer: AgentVoucherSigner;
  network: PaythosNetwork;
  /** Destination allowlist at the SDK boundary (defense in depth with vault). */
  allowlist: ReadonlySet<string>;
  transactability?: TransactabilityOracle;
  tiers?: TierThresholds;
  /** Outbound-loop limiter (INV-M6). Defaults: 100 burst / 10 per second. */
  rateLimit?: { capacity: number; refillPerSecond: number };
  /**
   * Tier-2 human gate. Return true ONLY after cryptographic confirmation
   * (webhook/chat callback). Fail closed: absent provider ⇒ Tier 2 denies.
   */
  approveWithHuman?: (summary: HumanApprovalSummary) => Promise<boolean>;
  fetch?: typeof fetch;
  /**
   * Full remaining rolling allowance override; DEFAULT_ALLOWANCE_MICRO when
   * omitted. Prefer `allowanceProvider` (below) for live vault telemetry.
   */
  allowanceMicro?: bigint;
  /**
   * Live on-chain telemetry hook (Gate 2.5): must resolve to the vault's
   * `remainingAllowance(agentKey)`. Sampled before each gated request.
   * Example: () => vaultReader.remainingAllowance(signer.address)
   */
  allowanceProvider?: () => Promise<bigint>;
}

export interface HumanApprovalSummary {
  amountUsd: string;
  merchant: string;
  memo: string;
  kind: "tier2_review";
}

export type ExecutedResult =
  | { ok: true; data: Response; voucher?: Voucher }
  | { ok: false; error: PolicyEvaluatedFailure; status?: number };

/** Result of a YOPO streaming run (INV-M5, docs/PROTOCOL.md §4.2). */
export type StreamedResult =
  | {
      ok: true;
      /** Reassembled stream body (settled variant includes the metering trailer). */
      data: Response | string;
      /** Settlement voucher — absent on free endpoints. */
      voucher?: Voucher;
      streamId?: string;
      consumedUsd?: string;
      consumedMicro?: bigint;
    }
  | {
      ok: false;
      error: PolicyEvaluatedFailure;
      /** Hold lifecycle at failure time: nothing locked / released unpaid / settled-but-unconfirmed. */
      holdState: "unset" | "released" | "settled";
      status?: number;
    };

export interface StreamHooks {
  /** Observe chunks as they land (progressive UI). */
  onChunk?: (delta: string, accumulated: string) => void;
  /**
   * Custom metering extraction. Default: the LAST line of the body is the
   * metering JSON (optionally wrapped as `{ "metering": {...} }`) —
   * docs/PROTOCOL.md §4.2 terminal frame.
   */
  extractMetering?: (response: Response, fullText: string) => MeteringReport | undefined;
}

export type GateDecision =
  | { ok: true; memo: string; amountMicro: bigint; needsHuman?: false }
  | { ok: true; needsHuman: true; reason: string; memo: string; amountMicro: bigint }
  | { ok: false; error: PolicyEvaluatedFailure };

export type HeaderBag = ConstructorParameters<typeof Headers>[0];

export interface RequestAttempt {
  url: string;
  method?: string;
  prompt?: string; // verifiable-intent source text
  body?: RequestInit["body"];
  headers?: HeaderBag;
}

export class PaythosClient {
  readonly #gofer: GoferPolicyEngine;
  readonly #bucket: TokenBucket;
  readonly #holds = new HoldLedger();
  #allowanceMicro: bigint;

  constructor(
    protected readonly signer: AgentVoucherSigner,
    protected readonly options: PaythosClientOptions,
  ) {
    this.#gofer = new GoferPolicyEngine(options.tiers);
    this.#bucket = new TokenBucket(options.rateLimit ?? { capacity: 100, refillPerSecond: 10 });
    this.#allowanceMicro = options.allowanceMicro ?? DEFAULT_ALLOWANCE_MICRO;
  }

  /** Active `upto` hold ledger (YOPO ceiling locks, never vouchers). */
  get holds(): HoldLedger {
    return this.#holds;
  }

  /**
   * Refresh the in-memory allowance from the on-chain provider (Gate 2.5).
   * No-op (resolve) without an `allowanceProvider`; failures are swallowed so
   * telemetry outages never block the gate — the stale local value holds.
   */
  async refreshAllowance(): Promise<void> {
    const provider = this.options.allowanceProvider;
    if (!provider) return;
    try {
      this.#allowanceMicro = await provider();
    } catch {
      /* keep last-known allowance — telemetry failure is not a spend error */
    }
  }

  /** dryRun(): structured pre-flight on a challenge, capital untouched (Module 4.1). */
  dryRun(challenge: PaymentChallenge): PreFlightReport {
    return this.#gofer.preFlight(this.contextFor(challenge));
  }

  /**
   * The x402-aware fetch. Typed failures, never thrown strings (AGENTS.md).
   * (1) plain attempt → (2) 402 → challenge — decode → GOFER gate → tier-2
   * review when signalled → cumulative voucher → retry once.
   */
  async fetchWithX402(attempt: RequestAttempt): Promise<ExecutedResult> {
    const first = await this.rawFetchBuilder(attempt);
    if (first.status !== 402) {
      if (first.ok) {
        // Free endpoint; nothing to sign.
        return { ok: true, data: first };
      }
      return networkFail(first.status);
    }

    const challenge = decodeChallenge(first);
    await this.refreshAllowance();
    const gate = this.gate(challenge, attempt.prompt ?? attempt.url);
    if (!gate.ok) return { ok: false, error: gate.error };

    if (gate.needsHuman) {
      const approved = await this.confirmTier2({
        amountUsd: formatMicroUsd(gate.amountMicro),
        merchant: challenge.payTo,
        memo: gate.memo,
      });
      if (!approved) {
        return { ok: false, error: humanApprovalFailure(gate.reason) };
      }
    }

    const signed = await this.signer.recordAndSign(challenge.payTo, gate.amountMicro, gate.memo);
    if (!signed.ok) return { ok: false, error: { code: "policy_failure", detail: signed.error.detail } };

    const retry = await this.rawFetchBuilder(attempt, signed.voucher, signed.signature);
    if (retry.status === 402) {
      // Merchant rejected the proof (epoch mismatch/stale accumulator state).
      return {
        ok: false,
        error: { code: "invalid_voucher", detail: "payment rejected on retry" },
        status: 402,
      };
    }
    if (retry.ok) return { ok: true, data: retry, voucher: signed.voucher };
    return networkFail(retry.status);
  }

  /**
   * YOPO streaming for `scheme: "upto"` challenges (docs/PROTOCOL.md §4.2,
   * INV-M5). Lifecycle, in order:
   *   1. 402 round-trip — challenge declares the OUTCOME CEILING (`max`).
   *   2. GOFER gate against the ceiling, tier-2 human review when signalled.
   *   3. HOLD: the ceiling is LOCKED internally — never a voucher. Holds
   *      count against the rolling budget until settle/release.
   *   4. The stream opens; chunks flow WITHOUT any payment proof.
   *   5. Terminal frame = scewer-attested MeteringReport; signature must
   *      recover to `payTo`; consumed must parse and stay ≤ ceiling.
   *   6. ONLY THEN does the client sign the EXACT cumulative voucher
   *      (previousTotal + consumed) and POST the completion call.
   *   Failure/break/bad attestation at ANY point ⇒ hold released, no
   *   voucher, nothing owed (YOPO: unrendered tokens are never signed).
   */
  async streamWithX402(attempt: RequestAttempt, hooks: StreamHooks = {}): Promise<StreamedResult> {
    const prompt = attempt.prompt ?? attempt.url;
    const first = await this.rawFetchBuilder(attempt);
    if (first.status !== 402) {
      if (first.ok) return { ok: true, data: first }; // free endpoint — nothing to hold or sign
      return { ok: false, error: { code: "network_error", detail: `upstream ${first.status}` }, holdState: "unset" };
    }

    const challenge = decodeChallenge(first);
    if (challenge.scheme !== "upto") {
      return {
        ok: false,
        error: {
          code: "policy_ambiguous",
          detail: `streamWithX402 requires scheme "upto" (got "${challenge.scheme}") — use fetchWithX402 for exact`,
        },
        holdState: "unset",
      };
    }

    await this.refreshAllowance();
    const ceiling = parseMaxMicro(challenge);
    const free = this.#allowanceMicro > this.#holds.activeHoldMicro()
      ? this.#allowanceMicro - this.#holds.activeHoldMicro()
      : 0n;
    if (free < ceiling) {
      return {
        ok: false,
        error: {
          code: "policy_failure",
          detail: `insufficient allowance for the ${formatMicroUsd(ceiling)} upto hold — ${formatMicroUsd(free)} free`,
        },
        holdState: "unset",
      };
    }

    const gate = this.gate(challenge, prompt);
    if (!gate.ok) return { ok: false, error: gate.error, holdState: "unset" };
    if (gate.needsHuman) {
      const approved = await this.confirmTier2({
        amountUsd: formatMicroUsd(gate.amountMicro),
        merchant: challenge.payTo,
        memo: gate.memo,
      });
      if (!approved) {
        return { ok: false, error: humanApprovalFailure(gate.reason), holdState: "unset" };
      }
    }

    // ---- HOLD (internal lock — the ceiling is NEVER signed here) ----
    const streamId = HoldLedger.streamIdFor(attempt.url, prompt, Date.now());
    this.#holds.lock(streamId, challenge.payTo, ceiling);

    // ---- 4. open the stream UNPAID ----
    let stream: Response;
    try {
      stream = await this.rawFetchBuilder(attempt);
    } catch (err) {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: { code: "network_error", detail: `stream open failed: ${String(err)}` },
        holdState: "released",
      };
    }
    if (!stream.ok || !stream.body) {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: { code: "network_error", detail: `stream refused: HTTP ${stream.status}` },
        holdState: "released",
      };
    }

    let fullText = "";
    try {
      const reader = stream.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const delta = decoder.decode(value, { stream: true });
        fullText += delta;
        try {
          hooks.onChunk?.(delta, fullText);
        } catch {
          /* observer errors MUST NOT kill the stream (progress UI is best-effort) */
        }
      }
    } catch (err) {
      // ---- YOPO: connection broke mid-stream ⇒ hold released, no voucher ----
      this.#holds.release(streamId);
      return {
        ok: false,
        error: { code: "network_error", detail: `stream broke before completion: ${String(err)}` },
        holdState: "released",
      };
    }

    // ---- 5. metering proof (attested, ≤ ceiling, recovering to payTo) ----
    let report = hooks.extractMetering
      ? hooks.extractMetering(stream, fullText)
      : defaultExtractMetering(stream, fullText);
    if (report === undefined) {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: { code: "policy_ambiguous", detail: "no metering report on the terminal frame — hold released unpaid (YOPO)" },
        holdState: "released",
      };
    }
    let recovered: string;
    try {
      recovered = recoverMeteringSigner(report);
    } catch (err) {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: {
          code: "policy_ambiguous",
          detail: `metering attestation malformed: ${String(err)}`,
        },
        holdState: "released",
      };
    }
    if (recovered !== challenge.payTo.toLowerCase()) {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: {
          code: "policy_ambiguous",
          detail: "metering attestation did NOT recover to the payTo destination",
        },
        holdState: "released",
      };
    }
    let consumedMicro: bigint;
    try {
      consumedMicro = parseUsdToMicro(report.consumed);
    } catch {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: { code: "policy_ambiguous", detail: `unparseable consumed amount: "${report.consumed}"` },
        holdState: "released",
      };
    }
    if (consumedMicro > ceiling) {
      this.#holds.release(streamId);
      return {
        ok: false,
        error: {
          code: "policy_failure",
          detail: `metered ${formatMicroUsd(consumedMicro)} exceeds the ${formatMicroUsd(ceiling)} ceiling`,
        },
        holdState: "released",
      };
    }
    try {
      this.#holds.settle(streamId, consumedMicro);
    } catch (err) {
      // settle() releases the hold itself on zero/over-ceiling consumed —
      // nothing owed, nothing signed (YOPO zero-render ⇒ unpaid).
      return {
        ok: false,
        error: { code: "policy_failure", detail: `hold settlement refused: ${String(err)}` },
        holdState: "released",
      };
    }

    // ---- 6. sign EXACT consumption + POST the completion call ----
    const signed = await this.signer.recordAndSign(challenge.payTo, consumedMicro, gate.memo);
    if (!signed.ok) {
      // Ledger refused (replay/limit) — hold consumed but unpaid: fail closed.
      return {
        ok: false,
        error: { code: "policy_failure", detail: `settlement refused: ${signed.error.detail}` },
        holdState: "settled",
      };
    }
    const completion: RequestAttempt = {
      url: attempt.url,
      method: attempt.method ?? "POST",
      prompt,
      body: JSON.stringify({ streamId }),
      headers: { [X_PAYTHOS_STREAM_HEADER]: streamId },
    };
    const retry = await this.rawFetchBuilder(completion, signed.voucher, signed.signature);
    if (retry.status === 402) {
      return {
        ok: false,
        error: { code: "invalid_voucher", detail: "completion payment rejected" },
        status: 402,
        holdState: "settled",
      };
    }
    if (retry.ok) {
      return {
        ok: true,
        streamId,
        consumedUsd: formatMicroUsd(consumedMicro),
        consumedMicro,
        voucher: signed.voucher,
        data: fullText,
      };
    }
    return {
      ok: false,
      error: { code: "network_error", detail: `upstream ${retry.status} on completion` },
      status: retry.status,
      holdState: "settled",
    };
  }

  /**
   * Policy gate. GOFER evaluation is sync and cheap; tier-2 signalling
   * is returned to the CALLER so the async human review (chat/webhook) can run.
   */
  gate(
    challenge: PaymentChallenge,
    prompt: string,
  ): GateDecision {
    const amountMicro = parseMaxMicro(challenge);
    const memo = GoferPolicyEngine.intentMemo(prompt, Math.floor(Date.now() / 1000));

    if (!this.#bucket.tryConsume().allowed) {
      return { ok: false, error: { code: "rate_limited", detail: "local token-bucket throttled this loop" } };
    }
    const report = this.#gofer.preFlight(this.contextFor(challenge));
    if (!report.willSucceed) return { ok: false, error: { code: "policy_failure", detail: report.reason } };
    if (report.requiresHumanApproval) {
      return { ok: true, needsHuman: true, reason: report.reason, memo, amountMicro };
    }
    return { ok: true, memo, amountMicro };
  }

  protected contextFor(challenge: PaymentChallenge) {
    return {
      amountMicro: parseMaxMicro(challenge),
      // ACTIVE `upto` holds run against the same rolling budget until they
      // settle or release (YOPO ceiling = reserved headroom, not spend).
      remainingAllowanceMicro: this.#allowanceMicro > this.#holds.activeHoldMicro()
        ? this.#allowanceMicro - this.#holds.activeHoldMicro()
        : 0n,
      merchant: challenge.payTo,
      allowlist: this.options.allowlist,
      counterpartyApproved: this.transactabilityApprove(challenge.payTo),
    };
  }

  protected transactabilityApprove(merchant: string): boolean {
    const oracle = this.options.transactability ?? AlwaysApprove;
    return oracle.approve(merchant);
  }

  /** Tier-2 path: awaited cryptographic review (human chat/webhook/dashboard). */
  async confirmTier2(summary: Omit<HumanApprovalSummary, "kind">): Promise<boolean> {
    const gate = this.options.approveWithHuman;
    if (!gate) return false; // fail closed
    return gate({ ...summary, kind: "tier2_review" });
  }

  protected async rawFetchBuilder(attempt: RequestAttempt, voucher?: Voucher, signature?: string): Promise<Response> {
    const headers = new Headers(attempt.headers);
    if (voucher && signature) {
      headers.set(PAYMENT_SIGNATURE_HEADER, JSON.stringify({
        voucher: serializeVoucher(voucher),
        signature,
      }));
    }
    const request: RequestInit = { method: attempt.method ?? "GET", headers };
    if (attempt.body !== undefined) request.body = attempt.body;
    try {
      return await (this.options.fetch ?? globalThis.fetch)(attempt.url, request);
    } catch (err) {
      throw new PaythosError("network_error", `fetch failed: ${String(err)}`);
    }
  }
}

/** The x402 `PAYMENT-SIGNATURE` envelope is JSON `{ voucher, signature }` (PROTOCOL.md §3). */
export function serializeVoucher(v: Voucher): Record<string, string | number> {
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

/**
 * Default §4.2 metering extraction: the LAST non-empty line of the body is
 * the metering JSON (plain or wrapped `{ "metering": {...} }`).
 */
export function defaultExtractMetering(_response: Response, fullText: string): MeteringReport | undefined {
  const lines = fullText.split("\n").filter((l) => l.trim().length > 0);
  for (let i = lines.length - 1; i >= 0; i--) {
    const report = parseMeteringReport(lines[i]!);
    if (report !== undefined) return report;
  }
  return undefined;
}

export function humanApprovalFailure(reason: string): PolicyEvaluatedFailure {
  return { code: "human_approval_required", detail: reason };
}

function networkFail(status: number): ExecutedResult {
  return { ok: false, error: { code: "network_error", detail: `HTTP ${status}` }, status };
}

/** `max`/`amount` fields accepted ("0.01" decimal or "10000" atomic micro). */
export function parseMaxMicro(challenge: PaymentChallenge): bigint {
  const raw = (challenge as { max?: string; amount?: string }).max ?? (challenge as { amount?: string }).amount;
  if (typeof raw !== "string") {
    throw new PaythosError("invalid_challenge", "challenge carries no max/amount field");
  }
  try {
    // Decimal point implies USD decimal format; raw digits imply atomic micro.
    return raw.includes(".") ? microFromDecimal(raw) : BigInt(raw);
  } catch {
    throw new PaythosError("invalid_challenge", `unparseable challenge amount: ${raw}`);
  }
}

function microFromDecimal(usd: string): bigint {
  if (!/^\d+(\.\d{1,6})?$/.test(usd)) {
    throw new PaythosError("invalid_challenge", `invalid USDC amount: ${usd}`);
  }
  const [w, f = ""] = usd.split(".");
  const f6 = (f + "0".repeat(6)).slice(0, 6);
  return BigInt(w + f6);
}

/** Decode + validate a base64 x402 PAYMENT-REQUIRED header (docs/PROTOCOL.md §3.1). */
export function decodeChallenge(res: Response): PaymentChallenge {
  const header = res.headers.get("payment-required");
  if (!header) throw new PaythosError("invalid_challenge", "402 without PAYMENT-REQUIRED header");
  let decoded: PaymentChallenge;
  try {
    decoded = JSON.parse(
      Buffer.from(header, "base64").toString("utf8"),
    ) as PaymentChallenge;
  } catch {
    throw new PaythosError("invalid_challenge", "PAYMENT-REQUIRED is not valid base64 JSON");
  }
  if (decoded.x402Version !== 2) {
    throw new PaythosError("invalid_challenge", `unsupported x402Version ${decoded.x402Version}`);
  }
  if (!decoded.payTo || !decoded.network) {
    throw new PaythosError("invalid_challenge", "challenge missing payTo/network");
  }
  return decoded;
}

export { formatMicroUsd };
