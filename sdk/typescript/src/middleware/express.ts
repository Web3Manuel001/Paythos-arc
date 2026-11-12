/**
 * Express adapter for the Paythos merchant membrane (Gate 2, Module 3).
 * Thin: translate req/res into the framework-agnostic VoucherAccumulator.
 * Peer-optional: only works when `express` is installed (package.json peers).
 *
 * Gating contract (fail closed): a request WITHOUT payment headers gets a
 * 402 + x402 PAYMENT-REQUIRED challenge when `challengeFor` is configured.
 * Without the factory the mount cannot price the resource, so it still
 * rejects with 402 `payment_required` — there is NO pass-through mode.
 */
import type { Request, Response, NextFunction } from "express";
import {
  MerchantChallengeContext,
  MerchantVerifierConfig,
  VoucherAccumulator,
  VerifyOutcome,
} from "./merchant.js";
import { PAYMENT_REQUIRED_HEADER, PaymentChallenge, X_PAYTHOS_VOUCHER_HEADER, X_PAYTHOS_SIGNATURE_HEADER } from "../types.js";

/** Pinned request fields once a voucher verifies (downstream handler visibility). */
declare module "express-serve-static-core" {
  interface Request {
    paythos?: { agentKey: string; unsettledMicro: string };
  }
}

export interface PaythosMerchantMount extends MerchantVerifierConfig {
  /** Exposed for tests/ops: the accumulator behind this mount. */
  readonly accumulator?: VoucherAccumulator;
}

export function paythosMerchant(config: MerchantVerifierConfig) {
  const accumulator = new VoucherAccumulator(config);
  const challengeFor = config.challengeFor;

  return (req: Request, res: Response, next: NextFunction): void => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === "string") headers.set(k, v);
    }

    if (!hasPaymentHeaders(headers)) {
      if (!challengeFor) {
        // Fail closed: without a challenge factory there is no way to price
        // the route, so an unpaid request must never reach the handler
        // (reviewer 2026-11: legacy mounts passed everything through free).
        res.status(402);
        res.setHeader("accept-payment", "PAYTHOS/x402v2");
        res.json({
          error: "payment_required",
          detail: "challengeFor not configured — priced routes require payment (fail closed)",
        });
        return;
      }
      // GATED route: no proof of payment ⇒ x402 challenge (fail closed).
      const ctx: MerchantChallengeContext = { method: req.method ?? "GET", url: req.originalUrl ?? req.url };
      const challenge = challengeFor(ctx);
      try {
        accumulator.assertPayee(challenge);
      } catch (err) {
        // Misconfiguration must never advertise a destination this mount will
        // not redeem for; fail closed instead of drifting (reviewer 2026-11).
        res.status(500);
        res.json({ error: "merchant_payee_mismatch", detail: String(err) });
        return;
      }
      res.status(402);
      res.setHeader(PAYMENT_REQUIRED_HEADER, encodeChallenge(challenge));
      res.setHeader("accept-payment", "PAYTHOS/x402v2");
      res.json({ error: "payment_required", ...challenge });
      return;
    }

    const outcome: VerifyOutcome = accumulator.verifyPayment(headers, req.ip);
    if (!outcome.ok) {
      res.status(outcome.status);
      res.setHeader("accept-payment", "PAYTHOS/x402v2");
      if (outcome.status === 429) {
        // INV-M6: throttle the loop — no re-challenge, just backoff.
        res.setHeader("Retry-After", String(Math.max(1, Math.ceil(outcome.retryAfterSeconds ?? 1))));
        res.json({ error: outcome.reason ?? "rate limited" });
        return;
      }
      if (challengeFor) {
        // Re-challenge on rejection so the agent can retry with a fresh voucher.
        const ctx: MerchantChallengeContext = { method: req.method ?? "GET", url: req.originalUrl ?? req.url };
        res.setHeader(PAYMENT_REQUIRED_HEADER, encodeChallenge(challengeFor(ctx)));
      }
      res.json({ error: outcome.reason ?? "payment rejected" });
      return;
    }
    req.paythos = { agentKey: outcome.agentKey ?? "", unsettledMicro: outcome.unsettledMicro.toString() };
    next();
  };
}

function hasPaymentHeaders(h: Headers): boolean {
  return (
    h.has(X_PAYTHOS_VOUCHER_HEADER) ||
    h.has(X_PAYTHOS_SIGNATURE_HEADER) ||
    h.has("payment-signature")
  );
}

function encodeChallenge(challenge: PaymentChallenge): string {
  return Buffer.from(JSON.stringify(challenge), "utf8").toString("base64");
}
