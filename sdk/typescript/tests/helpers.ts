import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

const TESTNET = "eip155:5042002" as const;
export const TEST_VAULT = "0xa9d5525BE440831c64695d30c915DF303E0151EF";
export const AR_NATIVE_USDC = "0x3600000000000000000000000000000000000000";
export const TEST_MERCHANT = "0x1234567890123456789012345678901234567890";

export function ephemeralPrivateKey(): string {
  return "0x" + randomBytes(32).toString("hex");
}

export { TESTNET };
