/**
 * Circle Discovery ingestion + Transactability union firewall
 * (docs/CIRCLE-INTEGRATION.md §2.1–2.2).
 */
import { describe, expect, it, vi } from "vitest";
import {
  CIRCLE_DISCOVERY_URL,
  discoveryQueryString,
  queryCircleMarketplace,
} from "../src/client/discovery.js";
import { TransactabilityIndex } from "../src/client/transactability.js";
import { TEST_MERCHANT } from "./helpers.js";

const MERCHANT_A = TEST_MERCHANT.toLowerCase();
const MERCHANT_B = "0x00000000000000000000000000000000000000bb";
const MERCHANT_C = "0x00000000000000000000000000000000000000cc";

function listing(payTos: string[], name = "svc"): unknown {
  return {
    accepts: payTos.map((payTo) => ({
      scheme: "exact",
      network: "eip155:5042002",
      asset: "0x3600000000000000000000000000000000000000",
      amount: "10000",
      payTo,
    })),
    metadata: { provider: { name, category: "FINANCIAL_ANALYSIS" } },
  };
}

function catalog(items: unknown[], pagination?: unknown): Response {
  return new Response(JSON.stringify({ x402Version: 2, items, ...(pagination ? { pagination } : {}) }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const allowExcept = (blocked: string[]) => ({ approve: (m: string) => !blocked.includes(m.toLowerCase()) });

describe("queryCircleMarketplace — query building", () => {
  it("serializes only defined parameters", () => {
    expect(discoveryQueryString({})).toBe("");
    const qs = discoveryQueryString({ network: "eip155:5042002", maxUsdPrice: 0.01, limit: 10 });
    expect(qs).toBe("?network=eip155%3A5042002&maxUsdPrice=0.01&limit=10");
  });
});

describe("queryCircleMarketplace — ingestion", () => {
  it("returns the catalog untouched when no oracle is supplied", async () => {
    const fetchFn = vi.fn(async () => catalog([listing([MERCHANT_A]), listing([MERCHANT_B]), listing([MERCHANT_C])]));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.listings).toHaveLength(3);
    expect(result.filtered).toBe(0);
  });

  it("passes the caller's query through to the Circle endpoint", async () => {
    const fetchFn = vi.fn(async (_url: string | URL | Request) => catalog([]));
    await queryCircleMarketplace(
      { network: "eip155:5042002", category: "FINANCIAL_ANALYSIS", limit: 5 },
      { fetch: fetchFn as unknown as typeof fetch },
    );
    const calledUrl = String(fetchFn.mock.calls[0]![0]);
    expect(calledUrl.startsWith(CIRCLE_DISCOVERY_URL)).toBe(true);
    expect(calledUrl).toContain("network=eip155%3A5042002");
    expect(calledUrl).toContain("category=FINANCIAL_ANALYSIS");
    expect(calledUrl).toContain("limit=5");
    expect(calledUrl).not.toContain("query=");
  });

  it("supports a CI mock URL", async () => {
    const fetchFn = vi.fn(async () => catalog([]));
    await queryCircleMarketplace({ query: "weather" }, { fetch: fetchFn as unknown as typeof fetch, url: "https://mock.test/catalog" });
    expect(String(fetchFn.mock.calls[0]![0])).toBe("https://mock.test/catalog?query=weather");
  });

  it("passes pagination through", async () => {
    const fetchFn = vi.fn(async () => catalog([], { total: 636, limit: 1, offset: 0 }));
    const result = await queryCircleMarketplace({ limit: 1 }, { fetch: fetchFn as unknown as typeof fetch });
    if (!result.ok) throw new Error("expected success");
    expect(result.pagination).toEqual({ total: 636, limit: 1, offset: 0 });
  });
});

describe("queryCircleMarketplace — Transactability union firewall", () => {
  it("drops listings whose every accept fails the Paythos check", async () => {
    const items = [listing([MERCHANT_A], "keep"), listing([MERCHANT_B], "drop"), listing([MERCHANT_B, MERCHANT_C], "rescue")];
    const fetchFn = vi.fn(async () => catalog(items));
    const oracle = allowExcept([MERCHANT_B]);
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch, transactability: oracle });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.listings).toHaveLength(2);
    expect(result.filtered).toBe(1);
    const names = result.listings.map((l) => l.metadata?.provider?.name);
    expect(names).toEqual(["keep", "rescue"]);
  });

  it("a pay-then-fail merchant disappears from the catalog", async () => {
    const index = new TransactabilityIndex();
    for (let i = 0; i < 4; i++) index.record(MERCHANT_B, { ok: true, latencyMs: 0, status: 200, valid: false });
    const fetchFn = vi.fn(async () => catalog([listing([MERCHANT_B]), listing([MERCHANT_A])]));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch, transactability: index });
    if (!result.ok) throw new Error("expected success");
    expect(result.filtered).toBe(1);
    expect(result.listings[0]!.accepts[0]!.payTo).toBe(MERCHANT_A);
  });

  it("accepts with an empty payTo never pass the firewall", async () => {
    const approve = vi.fn(() => true);
    const fetchFn = vi.fn(async () => catalog([listing([""])]));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch, transactability: { approve } });
    if (!result.ok) throw new Error("expected success");
    expect(result.listings).toHaveLength(0);
    expect(approve).not.toHaveBeenCalled();
  });
});

describe("queryCircleMarketplace — fail closed", () => {
  it("non-200 is a typed network error", async () => {
    const fetchFn = vi.fn(async () => new Response("nope", { status: 502 }));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("network_error");
    expect(result.error.detail).toContain("502");
  });

  it("transport throw is a typed network error", async () => {
    const fetchFn = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.detail).toContain("ECONNREFUSED");
  });

  it("non-JSON bodies are refused", async () => {
    const fetchFn = vi.fn(async () => new Response("<html>", { status: 200 }));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("policy_ambiguous");
  });

  it("wrong x402Version is refused", async () => {
    const fetchFn = vi.fn(async () => new Response(JSON.stringify({ x402Version: 1, items: [] }), { status: 200 }));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.detail).toContain("x402Version");
  });

  it("listings without accepts[] are refused", async () => {
    const fetchFn = vi.fn(async () => new Response(JSON.stringify({ x402Version: 2, items: [{ metadata: {} }] }), { status: 200 }));
    const result = await queryCircleMarketplace({}, { fetch: fetchFn as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.detail).toContain("accepts");
  });
});
