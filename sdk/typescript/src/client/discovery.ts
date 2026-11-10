/**
 * Circle Discovery API ingestion + Transactability union firewall
 * (docs/CIRCLE-INTEGRATION.md §2.1–2.2).
 *
 * Circle curates and sanctions-screens the catalog; Paythos re-gates it
 * through the Transactability Index. A listing is offered to an agent only
 * when at least one of its `accepts` entries pays a merchant that passes the
 * Paythos counterparty check. Paythos never re-lists — it re-gates.
 *
 * Endpoint: GET https://api.circle.com/v2/x402/discovery/resources (keyless).
 */
import { PaythosError } from "../core/errors.js";
import type { PolicyEvaluatedFailure } from "../types.js";
import type { TransactabilityOracle } from "./paythosClient.js";

export const CIRCLE_DISCOVERY_URL = "https://api.circle.com/v2/x402/discovery/resources";

export type CircleDiscoveryCategory =
  | "SOCIAL_INTELLIGENCE"
  | "FINANCIAL_ANALYSIS"
  | "WEB_SEARCH_RESEARCH"
  | "PREDICTION_MARKETS"
  | "CREATIVE"
  | "INFRASTRUCTURE";

export interface CircleDiscoveryQuery {
  /** Fuzzy search. */
  query?: string;
  type?: "http" | "mcp";
  category?: CircleDiscoveryCategory;
  /** CAIP-2, e.g. `eip155:5042002` (Arc Testnet). */
  network?: string;
  asset?: string;
  scheme?: string;
  payTo?: string;
  /** Listing price ceiling in USD. */
  maxUsdPrice?: number;
  supportsVanillax402?: boolean;
  supportsCircleGateway?: boolean;
  siwx?: boolean;
  fields?: string;
  limit?: number;
  offset?: number;
}

export interface CircleAcceptEntry {
  scheme: string;
  network: string;
  asset: string;
  /** Atomic micro-USDC string. */
  amount: string;
  payTo: string;
  [extra: string]: unknown;
}

export interface ServiceListing {
  accepts: CircleAcceptEntry[];
  metadata?: {
    provider?: {
      name?: string;
      description?: string;
      category?: string;
      tags?: string[];
      docsUrl?: string;
      openApiUrl?: string;
      [extra: string]: unknown;
    };
    [extra: string]: unknown;
  };
  [extra: string]: unknown;
}

export interface CirclePagination {
  total?: number;
  limit?: number;
  offset?: number;
  [extra: string]: unknown;
}

export type DiscoveryResult =
  | {
      ok: true;
      listings: ServiceListing[];
      pagination?: CirclePagination;
      /** Listings dropped by the Transactability union firewall. */
      filtered: number;
    }
  | { ok: false; error: PolicyEvaluatedFailure };

export interface DiscoveryOptions {
  /** Injected fetch (tests / custom transport). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Override for CI mocks; defaults to the live Circle endpoint. */
  url?: string;
  /** Union firewall: a listing survives only if an accept passes `approve`. */
  transactability?: TransactabilityOracle;
}

/** Build the query string without emitting empty/undefined parameters. */
export function discoveryQueryString(query: CircleDiscoveryQuery): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    params.set(key, String(value));
  }
  const encoded = params.toString();
  return encoded.length > 0 ? `?${encoded}` : "";
}

/**
 * Query the Circle Discovery catalog and apply the Paythos union firewall.
 * Typed result — never throws for transport/format problems (AGENTS.md).
 */
export async function queryCircleMarketplace(
  query: CircleDiscoveryQuery = {},
  options: DiscoveryOptions = {},
): Promise<DiscoveryResult> {
  const url = `${options.url ?? CIRCLE_DISCOVERY_URL}${discoveryQueryString(query)}`;
  let response: Response;
  try {
    response = await (options.fetch ?? globalThis.fetch)(url, {
      method: "GET",
      headers: { accept: "application/json" },
    });
  } catch (err) {
    return {
      ok: false,
      error: { code: "network_error", detail: `Circle Discovery fetch failed: ${String(err)}` },
    };
  }
  if (!response.ok) {
    return {
      ok: false,
      error: { code: "network_error", detail: `Circle Discovery HTTP ${response.status}` },
    };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return {
      ok: false,
      error: { code: "policy_ambiguous", detail: "Circle Discovery returned non-JSON" },
    };
  }

  let parsed: { x402Version?: unknown; items?: unknown; pagination?: unknown };
  try {
    parsed = assertDiscoveryEnvelope(body);
  } catch (err) {
    const detail = err instanceof PaythosError ? err.message : String(err);
    return { ok: false, error: { code: "policy_ambiguous", detail: `malformed Discovery catalog: ${detail}` } };
  }

  const all = parsed.items as ServiceListing[];
  const gate = options.transactability;
  const listings = gate === undefined ? all : all.filter((listing) => hasApprovedAccept(listing, gate));
  return {
    ok: true,
    listings,
    filtered: all.length - listings.length,
    ...(parsed.pagination !== undefined ? { pagination: parsed.pagination as CirclePagination } : {}),
  };
}

function assertDiscoveryEnvelope(body: unknown): { x402Version?: unknown; items?: unknown; pagination?: unknown } {
  if (typeof body !== "object" || body === null) throw new PaythosError("invalid_challenge", "response is not an object");
  const envelope = body as Record<string, unknown>;
  if (envelope["x402Version"] !== 2) {
    throw new PaythosError("invalid_challenge", `unsupported x402Version ${String(envelope["x402Version"])}`);
  }
  if (!Array.isArray(envelope["items"])) throw new PaythosError("invalid_challenge", "response.items is not an array");
  for (const item of envelope["items"] as unknown[]) {
    if (typeof item !== "object" || item === null || !Array.isArray((item as Record<string, unknown>)["accepts"])) {
      throw new PaythosError("invalid_challenge", "listing lacks an accepts[] array");
    }
  }
  return envelope as { x402Version?: unknown; items?: unknown; pagination?: unknown };
}

function hasApprovedAccept(listing: ServiceListing, gate: TransactabilityOracle): boolean {
  return listing.accepts.some(
    (accept) => typeof accept.payTo === "string" && accept.payTo.length > 0 && gate.approve(accept.payTo),
  );
}
