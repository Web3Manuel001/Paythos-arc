/**
 * Express adapter for the Paythos merchant membrane (Gate 2, Module 3).
 * Thin: translate req/res into the framework-agnostic VoucherAccumulator.
 * Peer-optional: only works when `express` is installed (package.json peers).
 */
import type { Request, Response, NextFunction } from "express";
import {
  MerchantVerifierConfig,
  VoucherAccumulator,
  VerifyOutcome,
} from "./merchant.js";
import { PAYMENT_REQUIRED_HEADER } from "../types.js";

/** Pinned request fields once a voucher verifies (downstream handler visibility). */
declare module "express-serve-static-core" {
  interface Request {
    paythos?: { agentKey: string; unsettledMicro: string };
  }
}

export function paythosMerchant(config: MerchantVerifierConfig) {
  const accumulator = new VoucherAccumulator(config);

  return (req: Request, res: Response, next: NextFunction): void => {
    // No x-paythos headers → this request is free / unpriced; pass through.
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === "string") headers.set(k, v);
    }
    if (!headers.has(PAYMENT_REQUIRED_HEADER) && !hasPaymentHeaders(headers)) {
      next();
      return;
    }

    const outcome: VerifyOutcome = accumulator.verifyPayment(headers);
    if (!outcome.ok) {
      res.status(outcome.status).json({ error: outcome.reason ?? "payment rejected" });
      res.setHeader("accept-payment", "PAYTHOS/x402v2");
      return;
    }
    req.paythos = { agentKey: outcome.agentKey ?? "", unsettledMicro: outcome.unsettledMicro.toString() };
    next();
  };
}

function hasPaymentHeaders(h: Headers): boolean {
  return h.has("x-paythos-voucher") || h.has("x-paythos-signature");
}
