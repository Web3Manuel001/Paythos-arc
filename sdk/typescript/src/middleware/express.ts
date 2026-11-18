/**
 * Express adapter for the Paythos merchant membrane.
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

/**
 * True for RFC1918 / loopback / link-local / unspecified / IPv6 ULA addresses.
 * Behind a proxy, `req.ip` stays the proxy unless Express `trust proxy` is set;
 * that would make every agent share one per-IP bucket.
 */
export function isPrivateOrLoopbackIp(ip: string | undefined): boolean {
  if (typeof ip !== "string" || ip.length === 0) return false;
  const normalized = ip.trim().toLowerCase().replace(/^\[|\]$/g, "");
  const v4 = normalized.replace(/^::ffff:/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v4)) {
    const [a, b] = v4.split(".").map(Number) as [number, number, number, number];
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    /^fe[89ab]/.test(normalized)
  );
}

const PROXY_FORWARDING_HEADERS = [
  "forwarded",
  "x-forwarded-for",
  "x-real-ip",
  "cf-connecting-ip",
  "true-client-ip",
] as const;

/** True when a proxy/edge has supplied a client-identity header. */
export function hasProxyForwardingHeaders(headers: Headers): boolean {
  return PROXY_FORWARDING_HEADERS.some((name) => {
    const value = headers.get(name);
    return typeof value === "string" && value.trim().length > 0;
  });
}

/**
 * Explain a per-IP limiter misconfiguration without failing the spend path.
 *
 * Two blind spots are covered:
 *  - a public edge IP (e.g. Cloudflare) is NOT private, yet it is still the
 *    proxy address unless `trust proxy` is set;
 *  - forwarded headers (`cf-connecting-ip`, `x-forwarded-for`, …) prove a
 *    proxy even when `req.ip` looks public.
 */
export function proxyTrustWarning(
  ip: string | undefined,
  headers: Headers,
  trustProxy: unknown,
): string | undefined {
  if (trustProxy) return undefined;
  if (hasProxyForwardingHeaders(headers)) {
    return "[paythos] proxy-forwarded client headers present but Express 'trust proxy' is unset; set app.set('trust proxy', <hops or subnet>) so per-IP limits key on the real client";
  }
  if (isPrivateOrLoopbackIp(ip)) {
    return "[paythos] req.ip is private/loopback; behind a proxy set app.set('trust proxy', <hops or subnet>) so per-IP limits key on the real client";
  }
  return undefined;
}

export function paythosMerchant(config: MerchantVerifierConfig) {
  const accumulator = new VoucherAccumulator(config);
  const challengeFor = config.challengeFor;
  let warnedProxyTrust = false;

  return (req: Request, res: Response, next: NextFunction): void => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === "string") headers.set(k, v);
    }

    // Proxy misconfiguration warning (once). Check BEFORE the payment branch so
    // an unpaid request from behind Cloudflare still surfaces the misconfig.
    if (!warnedProxyTrust && process.env.NODE_ENV !== "test") {
      const warning = proxyTrustWarning(req.ip, headers, req.app.get("trust proxy"));
      if (warning !== undefined) {
        warnedProxyTrust = true;
        console.warn(warning);
      }
    }

    if (!hasPaymentHeaders(headers)) {
      if (!challengeFor) {
        // Fail closed: without a challenge factory there is no way to price
        // the route, so an unpaid request must never reach the handler
        // (an earlier version let unpaid requests through).
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
        // not redeem for; fail closed instead of drifting.
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
