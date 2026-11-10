/**
 * Transactability Index (docs/ARCHITECTURE.md Module 4.2, SECURITY.md §3).
 * Counterparty health scored from MEASURED service quality: uptime, response
 * validity, latency, 5xx rate. Vendors of pay-then-fail endpoints are
 * downgraded and eventually blocked (INV-M5's companion defense).
 *
 * The registry is pluggable: the MVP ships an in-memory store; signed p2p
 * attestations and a decentralized registry land post-MVP (SECURITY.md §3).
 * Unknown merchants are ALLOWED by default — absence of evidence is not
 * evidence; the Destination Allowlist is the fail-closed boundary.
 */
import type { TransactabilityOracle } from "./paythosClient.js";

export interface MerchantObservation {
  /** Epoch ms (defaults to now). */
  at?: number;
  /** The interaction completed (HTTP-wise). */
  ok: boolean;
  latencyMs: number;
  /** Observed HTTP status, when one applied. */
  status?: number;
  /**
   * Response VALIDITY: attested metering / well-formed payment proof.
   * `undefined` when the interaction carries no validity signal.
   */
  valid?: boolean | undefined;
}

export type TransactabilityVerdict = "allow" | "downgrade" | "block";

export interface TransactabilityScore {
  merchant: string;
  /** Composite 0..100 (uptime 35% · validity 35% · latency 20% · 5xx 10%). */
  score: number;
  verdict: TransactabilityVerdict;
  uptime: number;
  validity: number;
  latencyMs: number;
  errorRate5xx: number;
  samples: number;
  source: "local" | "registry" | "empty";
  updatedAt: number;
}

/** Registry wire shape (verdict/source are derived locally on lookup). */
export type TransactabilityAttestation = Omit<TransactabilityScore, "verdict" | "source">;

export interface TransactabilityRegistry {
  lookup(merchant: string): TransactabilityAttestation | undefined;
  publish(attestation: TransactabilityAttestation): void;
}

export class InMemoryTransactabilityRegistry implements TransactabilityRegistry {
  readonly #attestations = new Map<string, TransactabilityAttestation>();

  lookup(merchant: string): TransactabilityAttestation | undefined {
    return this.#attestations.get(merchant.toLowerCase());
  }

  publish(attestation: TransactabilityAttestation): void {
    this.#attestations.set(attestation.merchant.toLowerCase(), attestation);
  }

  snapshot(): TransactabilityAttestation[] {
    return [...this.#attestations.values()];
  }
}

export interface TransactabilityConfig {
  /** Rolling sample window per merchant. */
  windowSize: number;
  /** Latency at/above this budget scores 0 on the latency component. */
  latencyBudgetMs: number;
  downgradeBelow: number;
  blockBelow: number;
  /** Validity floor: below it (with enough samples) the merchant is blocked. */
  validityFloor: number;
  /** Minimum samples before the validity floor can block. */
  minSamples: number;
  /**
   * Verdict for merchants with NO local history and NO registry attestation.
   * The allowlist remains the fail-closed boundary; default allows.
   */
  unknownVerdict: "allow" | "block";
}

export const DEFAULT_TRANSACTABILITY_CONFIG: TransactabilityConfig = {
  windowSize: 64,
  latencyBudgetMs: 2_000,
  downgradeBelow: 75,
  blockBelow: 50,
  validityFloor: 0.5,
  minSamples: 4,
  unknownVerdict: "allow",
};

export class TransactabilityIndex implements TransactabilityOracle {
  readonly #config: TransactabilityConfig;
  readonly #registry: TransactabilityRegistry | undefined;
  readonly #observations = new Map<string, MerchantObservation[]>();

  constructor(opts: { config?: Partial<TransactabilityConfig>; registry?: TransactabilityRegistry } = {}) {
    this.#config = { ...DEFAULT_TRANSACTABILITY_CONFIG, ...opts.config };
    this.#registry = opts.registry;
  }

  /** Oracle surface: block only on measured/published evidence. */
  approve(merchant: string): boolean {
    return this.score(merchant).verdict !== "block";
  }

  /** Record a single interaction observation; returns the fresh score. */
  record(merchant: string, observation: Omit<MerchantObservation, "at"> & { at?: number }): TransactabilityScore {
    const key = merchant.toLowerCase();
    const window = this.#observations.get(key) ?? [];
    window.push({ ...observation, at: observation.at ?? Date.now() });
    if (window.length > this.#config.windowSize) window.splice(0, window.length - this.#config.windowSize);
    this.#observations.set(key, window);
    const score = this.#compute(key, window);
    this.#registry?.publish({
      merchant: score.merchant,
      score: score.score,
      uptime: score.uptime,
      validity: score.validity,
      latencyMs: score.latencyMs,
      errorRate5xx: score.errorRate5xx,
      samples: score.samples,
      updatedAt: score.updatedAt,
    });
    return score;
  }

  /** Current score (local window first, then registry, then empty). */
  score(merchant: string): TransactabilityScore {
    const key = merchant.toLowerCase();
    const window = this.#observations.get(key);
    if (window !== undefined && window.length > 0) return this.#compute(key, window);
    const published = this.#registry?.lookup(key);
    if (published !== undefined) {
      return { ...published, merchant: key, verdict: this.#verdict(published.score, published.validity, published.samples), source: "registry" };
    }
    return {
      merchant: key,
      score: 100,
      verdict: this.#config.unknownVerdict,
      uptime: 1,
      validity: 1,
      latencyMs: 0,
      errorRate5xx: 0,
      samples: 0,
      source: "empty",
      updatedAt: Date.now(),
    };
  }

  snapshot(): TransactabilityScore[] {
    return [...this.#observations.keys()].map((merchant) => this.score(merchant));
  }

  #compute(merchant: string, window: MerchantObservation[]): TransactabilityScore {
    const total = window.length;
    const okCount = window.filter((o) => o.ok).length;
    const validCount = window.filter((o) => o.valid !== false).length;
    const fiveXxCount = window.filter((o) => o.status !== undefined && o.status >= 500 && o.status < 600).length;
    const latencyAvg = window.reduce((sum, o) => sum + Math.max(0, o.latencyMs), 0) / total;

    const uptime = okCount / total;
    const validity = validCount / total;
    const errorRate5xx = fiveXxCount / total;
    const latencyScore = clamp01(1 - latencyAvg / this.#config.latencyBudgetMs);
    const score = Math.round(100 * (0.35 * uptime + 0.35 * validity + 0.2 * latencyScore + 0.1 * (1 - errorRate5xx)));

    return {
      merchant,
      score,
      verdict: this.#verdict(score, validity, total),
      uptime,
      validity,
      latencyMs: Math.round(latencyAvg),
      errorRate5xx,
      samples: total,
      source: "local",
      updatedAt: window[total - 1]!.at ?? Date.now(),
    };
  }

  #verdict(score: number, validity: number, samples: number): TransactabilityVerdict {
    if (score < this.#config.blockBelow) return "block";
    if (samples >= this.#config.minSamples && validity < this.#config.validityFloor) return "block";
    if (score < this.#config.downgradeBelow) return "downgrade";
    return "allow";
  }
}

function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}

/** Structural check: does this oracle accept observations? */
export function isTransactabilityIndex(
  oracle: TransactabilityOracle | undefined,
): oracle is TransactabilityIndex {
  return oracle !== undefined && typeof (oracle as { record?: unknown }).record === "function";
}
