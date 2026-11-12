/**
 * Metering-report attestation (docs/PROTOCOL.md §4.2).
 * The server's terminal stream frame is `MeteringReport` JSON carrying a
 * signature over the canonical report bytes. The client verifies the signer
 * recovers to the challenge `payTo` destination — a MITM or lying midpoint
 * cannot inflate the bill without the merchant's key.
 */
import { keccak256, toUtf8Bytes, verifyMessage } from "ethers";
import { PaythosError } from "../core/errors.js";

export interface MeteringReport {
  scheme: "upto";
  units: "USD";
  /**
   * Client-chosen stream nonce, sent on the stream open (X-PAYTHOS-STREAM).
   * The merchant MUST echo it exactly; a report bound to any other id is a
   * replay and is rejected (reviewer N2).
   */
  streamId: string;
  /** Decimal USDC actually consumed, e.g. "0.0034". */
  consumed: string;
  /** Merchant attestation over the canonical report bytes (recovery = payTo). */
  signature: string;
}

/** `scheme|streamId|consumed|units` — the ONLY bytes ever attested. */
export function meteringCanonical(
  report: Pick<MeteringReport, "scheme" | "streamId" | "consumed" | "units">,
): string {
  return `${report.scheme}|${report.streamId}|${report.consumed}|${report.units}`;
}

/** Keccak digest of the canonical form (used as the personal-message payload). */
export function meteringDigest(report: MeteringReport): string {
  return keccak256(toUtf8Bytes(meteringCanonical(report)));
}

/** Merchant-side helper: attest a finished stream (client repair/refund base). */
export async function signMeteringReport(
  wallet: { signMessage(message: string): Promise<string> },
  report: Omit<MeteringReport, "signature">,
): Promise<MeteringReport> {
  return { ...report, signature: await wallet.signMessage(meteringCanonical(report)) };
}

/**
 * Recover the attestation signer. Throws typed errors on malformed reports;
 * the CALLER compares against `challenge.payTo`.
 */
export function recoverMeteringSigner(report: MeteringReport): string {
  if (report.scheme !== "upto" || report.units !== "USD") {
    throw new PaythosError("invalid_challenge", `metering report must be {scheme:"upto", units:"USD"}`);
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(report.signature)) {
    throw new PaythosError("invalid_challenge", "metering signature is not a 65-byte hex ECDSA sig");
  }
  for (const field of ["streamId", "consumed"] as const) {
    if (typeof report[field] !== "string" || report[field].length === 0) {
      throw new PaythosError("invalid_challenge", `metering report missing ${field}`);
    }
  }
  return verifyMessage(meteringCanonical(report), report.signature).toLowerCase();
}

/**
 * Parse a terminal stream chunk into a MeteringReport. Accepts either the raw
 * JSON object or one wrapped in `{ metering: {...} }`. Undefined when the
 * chunk is not metering JSON (ordinary payload chunks return undefined).
 */
export function parseMeteringReport(raw: string): MeteringReport | undefined {
  const candidate = raw.trim();
  if (!candidate.startsWith("{")) return undefined;
  try {
    const json = JSON.parse(candidate) as Record<string, unknown>;
    const inner = (json["metering"] as Record<string, unknown> | undefined) ?? json;
    if (typeof inner !== "object" || inner === null) return undefined;
    if (inner["scheme"] !== "upto" || inner["units"] !== "USD" || typeof inner["signature"] !== "string") {
      return undefined;
    }
    return {
      scheme: "upto",
      units: "USD",
      streamId: String(inner["streamId"]),
      consumed: String(inner["consumed"]),
      signature: inner["signature"],
    };
  } catch {
    return undefined;
  }
}
