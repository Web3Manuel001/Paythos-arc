import { describe, expect, it } from "vitest";
import { Interface } from "ethers";
import paythosVaultAbi from "../src/abi/paythosVault.json";
import { VaultReader, type RawCaller } from "../src/core/vaultReader.js";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { PaythosClient } from "../src/client/paythosClient.js";
import { AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";

const IFACE = new Interface(paythosVaultAbi as unknown as []);

/** Offline RawCaller: encodes canned vault responses against the real ABI. */
class FakeVault implements RawCaller {
  readonly #responses: Record<string, unknown>;
  readonly #bySelector = new Map<string, string>();

  constructor(responses: Record<string, unknown>) {
    this.#responses = responses;
    for (const fn of Object.keys(responses)) {
      this.#bySelector.set(IFACE.getFunction(fn).selector, fn);
    }
  }

  async call(_to: string, data: string): Promise<string> {
    void _to;
    const fn = this.#bySelector.get(data.slice(0, 10));
    if (fn === undefined) throw new Error(`FakeVault: unexpected selector ${data.slice(0, 10)}`);
    return IFACE.encodeFunctionResult(fn, [this.#responses[fn] as never]);
  }
}

describe("VaultReader — offline with canned responses", () => {
  it("reads config, agent policy, allowance and settled state", async () => {
    const fake = new FakeVault({
      SETTLEMENT_TOKEN: AR_NATIVE_USDC,
      TREASURY: TEST_MERCHANT,
      feeBps: 150n,
      isAgentActive: true,
      remainingAllowance: 19_900_000n,
      getPolicy: { dailyLimit: 25_000_000n, maxPerTx: 10_000_000n, expiresAt: 1_800_000_000n },
      claimed: 100_000n,
    });
    const reader = new VaultReader(fake, TEST_VAULT);

    const telemetry = await reader.telemetry();
    expect(telemetry).toEqual({ settlementToken: AR_NATIVE_USDC.toLowerCase(), treasury: TEST_MERCHANT, feeBps: 150n });
    expect(await reader.isAgentActive("0x" + "11".repeat(20))).toBe(true);
    expect(await reader.remainingAllowance("0x" + "11".repeat(20))).toBe(19_900_000n);
    const policy = await reader.policyOf("0x" + "11".repeat(20));
    expect(policy.maxPerTx).toBe(10_000_000n);
    expect(policy.dailyLimit).toBe(25_000_000n);
    expect(await reader.claimedFor("0x" + "11".repeat(20), TEST_MERCHANT)).toBe(100_000n);
  });
});

/** contextFor is protected; probe allowance through a typed accessor. */
interface Gatable {
  contextFor(challenge: unknown): { remainingAllowanceMicro: bigint };
}
function gatedAllowance(client: PaythosClient): bigint {
  const probe = client as unknown as Gatable;
  return probe.contextFor({
    x402Version: 2,
    scheme: "exact",
    network: TESTNET,
    asset: AR_NATIVE_USDC,
    payTo: TEST_MERCHANT,
    max: "0.01",
    resource: "/test",
  }).remainingAllowanceMicro;
}

describe("PaythosClient allowanceProvider — live telemetry feed", () => {
  function makeSigner(): AgentVoucherSigner {
    return new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    });
  }

  it("refreshes allowance from the provider before gating", async () => {
    let remote = 15_000_000n;
    const client = new PaythosClient(makeSigner(), {
      network: TESTNET,
      allowlist: new Set([TEST_MERCHANT]),
      allowanceProvider: () => Promise.resolve(remote),
    });
    await client.refreshAllowance();
    expect(gatedAllowance(client)).toBe(15_000_000n);
    remote = 7_000_000n;
    await client.refreshAllowance();
    expect(gatedAllowance(client)).toBe(7_000_000n);
  });

  it("keeps the last-known allowance when telemetry fails", async () => {
    const client = new PaythosClient(makeSigner(), {
      network: TESTNET,
      allowlist: new Set([TEST_MERCHANT]),
      allowanceProvider: () => Promise.reject(new Error("rpc down")),
      allowanceMicro: 12_000_000n,
    });
    await client.refreshAllowance();
    expect(gatedAllowance(client)).toBe(12_000_000n);
  });

  it("defaults to DEFAULT_ALLOWANCE_MICRO without any provider", () => {
    const client = new PaythosClient(makeSigner(), {
      network: TESTNET,
      allowlist: new Set([TEST_MERCHANT]),
    });
    expect(gatedAllowance(client)).toBe(20_000_000n);
  });
});
