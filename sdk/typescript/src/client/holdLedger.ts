/**
 * Hold ledger for `upto` streaming (docs/PROTOCOL.md §4.2).
 * A hold is an INTERNAL budget authorization — never a voucher. The ceiling
 * is locked when the stream opens and released on failure/break (YOPO,
 * INV-M5); settlement converts exactly the attested consumption into the
 * signed cumulative voucher by the client.
 */
import { keccak256, toUtf8Bytes } from "ethers";

export type HoldState = "active" | "settled" | "released";

export interface HoldEntry {
  /** Stream id (client-generated keccak256(url|prompt|ts)). */
  streamId: string;
  merchant: string;
  /** Locked ceiling in micro-USDC (NOT a claimable amount). */
  ceilingMicro: bigint;
  /** Settled consumption in micro-USDC (0 while active/released). */
  settledMicro: bigint;
  state: HoldState;
  createdAt: number;
  settledAt?: number;
  releasedAt?: number;
}

export class HoldLedger {
  readonly #holds = new Map<string, HoldEntry>();

  /** Deterministic client-side stream id. */
  static streamIdFor(url: string, prompt: string, timestampMs: number): string {
    return keccak256(toUtf8Bytes(`${url}|${prompt}|${timestampMs}`));
  }

  /**
   * Lock a ceiling against the session budget (fail closed: LockError on a
   * duplicate streamId — replays of settlement after settlement).
   */
  lock(streamId: string, merchant: string, ceilingMicro: bigint): HoldEntry {
    if (ceilingMicro <= 0n) throw new Error("hold ceiling must be positive");
    const existing = this.#holds.get(streamId);
    if (existing !== undefined) {
      throw new Error(`hold ${streamId.slice(0, 10)}… already ${existing.state}`);
    }
    const entry: HoldEntry = {
      streamId,
      merchant: merchant.toLowerCase(),
      ceilingMicro,
      settledMicro: 0n,
      state: "active",
      createdAt: Date.now(),
    };
    this.#holds.set(streamId, entry);
    return entry;
  }

  /** YOPO release: stream broke/failed/unattested — nothing owed. */
  release(streamId: string): void {
    const entry = this.#require(streamId);
    if (entry.state !== "active") return; // idempotent
    entry.state = "released";
    entry.releasedAt = Date.now();
  }

  /** Convert the hold into attested consumption; ceiling must not be exceeded. */
  settle(streamId: string, consumedMicro: bigint): void {
    const entry = this.#require(streamId);
    if (entry.state !== "active") throw new Error(`hold ${streamId.slice(0, 10)}… already ${entry.state}`);
    if (consumedMicro <= 0n) {
      this.release(streamId);
      throw new Error("consumed must be positive — zero-rendered streams release unpaid (YOPO)");
    }
    if (consumedMicro > entry.ceilingMicro) {
      this.release(streamId);
      throw new Error(`consumed ${consumedMicro} exceeds locked ceiling ${entry.ceilingMicro}`);
    }
    entry.state = "settled";
    entry.settledMicro = consumedMicro;
    entry.settledAt = Date.now();
  }

  /** Query — returns undefined when unknown. */
  get(streamId: string): HoldEntry | undefined {
    return this.#holds.get(streamId);
  }

  /** Total ACTIVE ceiling per merchant — the exposure held against budget. */
  activeHoldMicro(merchant?: string): bigint {
    let total = 0n;
    for (const h of this.#holds.values()) {
      if (h.state !== "active") continue;
      if (merchant !== undefined && h.merchant !== merchant.toLowerCase()) continue;
      total += h.ceilingMicro;
    }
    return total;
  }

  /** Snapshot for telemetry/tests. */
  snapshot(): HoldEntry[] {
    return [...this.#holds.values()];
  }

  #require(streamId: string): HoldEntry {
    const entry = this.#holds.get(streamId);
    if (entry === undefined) throw new Error(`unknown hold ${streamId.slice(0, 10)}…`);
    return entry;
  }
}
