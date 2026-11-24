/**
 * Arc RPC transport guards (see src/core/arcRpc.ts).
 * Offline: no request is issued, the network is pinned at construction.
 */
import { describe, expect, it } from "vitest";
import { arcRpcProvider, installArcRpcTransport } from "../src/core/arcRpc.js";

const RPC = "https://rpc.testnet.arc.io";

describe("arcRpcProvider", () => {
  it("pins the Arc Testnet chain without a startup probe", async () => {
    const provider = arcRpcProvider(RPC);
    // staticNetwork + explicit chain: resolved from memory, no RPC round trip.
    const network = await provider.getNetwork();
    expect(network.chainId).toBe(5042002n);
    await provider.destroy();
  });

  it("fails closed on an unverified network (PROTOCOL-OPEN-Q1)", () => {
    expect(() => arcRpcProvider("https://rpc.mainnet.arc.io", { network: "arc:mainnet" })).toThrow(
      /FAIL CLOSED/,
    );
  });

  it("installs the fetch transport idempotently", () => {
    expect(() => {
      installArcRpcTransport({ attempts: 2 });
      installArcRpcTransport({ attempts: 9 });
    }).not.toThrow();
  });
});
