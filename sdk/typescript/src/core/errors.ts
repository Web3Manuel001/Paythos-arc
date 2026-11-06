/**
 * Typed error routing (AGENTS.md: route errors as typed results, never strings).
 */
export type PaythosErrorCode =
  | "chain_unverified"
  | "invalid_challenge"
  | "invalid_voucher"
  | "policy_failure"
  | "rate_limited"
  | "network_error"
  | "config_missing";

export class PaythosError extends Error {
  readonly code: PaythosErrorCode;
  readonly detail?: unknown;

  constructor(code: PaythosErrorCode, message: string, detail?: unknown) {
    super(message);
    this.name = "PaythosError";
    this.code = code;
    this.detail = detail;
  }
}
