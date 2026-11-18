import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { once } from "node:events";
import { Wallet } from "ethers";
import {
  ARC_TESTNET_USDC,
  challengeFromRequirement,
  createCircleMarketplaceX402,
} from "../src/client/circleMarketplace.js";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { PaythosClient } from "../src/client/paythosClient.js";
import type { PaymentRequired, PaymentRequirements } from "@x402/core/types";
import { ephemeralPrivateKey, TEST_MERCHANT, TEST_VAULT, TESTNET } from "./helpers.js";

const GATEWAY_WALLET = "0x0077777d7eba4688bdef3e311b846f25870a19b9";
const closed: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(closed.splice(0).map((close) => close()));
});

function requirement(extra: Record<string, unknown>, amount = "10000"): PaymentRequirements {
  return {
    scheme: "exact",
    network: TESTNET,
    asset: ARC_TESTNET_USDC,
    amount,
    payTo: TEST_MERCHANT,
    maxTimeoutSeconds: 60,
    extra,
  };
}

function paymentRequired(accepts: PaymentRequirements[]): PaymentRequired {
  return {
    x402Version: 2,
    resource: { url: "https://agents.circle.com/services/example", mimeType: "application/json" },
    accepts,
  };
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64");
}

async function marketServer(options: {
  accepts: PaymentRequirements[];
  onPaid?: (req: IncomingMessage) => Promise<boolean> | boolean;
  settlement?: Record<string, unknown>;
}): Promise<{ url: string; requests: () => number }> {
  let count = 0;
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    count += 1;
    const paid = req.headers["payment-signature"] !== undefined;
    if (!paid) {
      const challenge = paymentRequired(options.accepts);
      res.writeHead(402, {
        "content-type": "application/json",
        "PAYMENT-REQUIRED": encode(challenge),
      });
      res.end(JSON.stringify(challenge));
      return;
    }
    if (options.onPaid && !(await options.onPaid(req))) {
      res.writeHead(402, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid signature" }));
      return;
    }
    res.writeHead(200, {
      "content-type": "application/json",
      "PAYMENT-RESPONSE": encode(
        options.settlement ?? {
          success: true,
          transaction: "0x" + "ab".repeat(32),
          network: TESTNET,
        },
      ),
    });
    res.end(JSON.stringify({ ok: true }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no server address");
  closed.push(
    () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  );
  return { url: `http://127.0.0.1:${address.port}/paid`, requests: () => count };
}

function client(allowlist: ReadonlySet<string> = new Set([TEST_MERCHANT.toLowerCase()])): PaythosClient {
  const wallet = new Wallet(ephemeralPrivateKey());
  const signer = new AgentVoucherSigner({
    privateKey: wallet.privateKey,
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    epoch: 1,
  });
  return new PaythosClient(signer, {
    signer,
    network: TESTNET,
    allowlist,
    allowanceMicro: 20_000_000n,
  });
}

describe("Circle marketplace x402 v2 adapter", () => {
  it("bridges the standard envelope into the Paythos challenge shape", () => {
    const req = requirement({ name: "USDC", version: "2" }, "25000");
    const challenge = challengeFromRequirement(paymentRequired([req]), req, "https://fallback");
    expect(challenge).toMatchObject({
      x402Version: 2,
      scheme: "exact",
      network: TESTNET,
      asset: ARC_TESTNET_USDC,
      payTo: TEST_MERCHANT,
      max: "0.025",
      amount: "25000",
      resource: "https://agents.circle.com/services/example",
    });
  });

  it("rejects non-Arc networks and non-USDC assets (fail closed)", async () => {
    const wallet = new Wallet(ephemeralPrivateKey());
    const signer = new AgentVoucherSigner({
      privateKey: wallet.privateKey,
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const { client: x402 } = createCircleMarketplaceX402(signer);
    const foreign = { ...requirement({ name: "USDC", version: "2" }), network: "eip155:8453" };
    await expect(
      x402.createPaymentPayload(paymentRequired([foreign])),
    ).rejects.toThrow(/No network\/scheme registered|No matching payment requirements|filtered out by policies/);

    const wrongAsset = {
      ...requirement({ name: "USDC", version: "2" }),
      asset: "0x0000000000000000000000000000000000000001",
    };
    await expect(
      x402.createPaymentPayload(paymentRequired([wrongAsset])),
    ).rejects.toThrow(/No network\/scheme registered|No matching payment requirements|filtered out by policies/);
  });

  it("pays a standard exact EIP-3009 marketplace service", async () => {
    const server = await marketServer({
      accepts: [requirement({ name: "USDC", version: "2" }, "10000")],
    });
    const paythos = client();
    const result = await paythos.fetchWithCircleMarketplace({ url: server.url, prompt: "buy" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.amountMicro).toBe(10_000n);
    expect(result.payment).toMatchObject({
      network: TESTNET,
      asset: ARC_TESTNET_USDC,
      gatewayBatched: false,
    });
    expect(result.settlement?.success).toBe(true);
    expect(await result.data.json()).toEqual({ ok: true });
    expect(paythos.directSpentMicro).toBe(10_000n);
    expect(paythos.holds.activeHoldMicro()).toBe(0n);
    expect(server.requests()).toBe(2);
  });

  it("fails closed when the rail reports a failed settlement", async () => {
    const server = await marketServer({
      accepts: [requirement({ name: "USDC", version: "2" }, "10000")],
      settlement: {
        success: false,
        errorReason: "insufficient_funds",
        transaction: "0x" + "00".repeat(32),
        network: TESTNET,
      },
    });
    const paythos = client();
    const result = await paythos.fetchWithCircleMarketplace({ url: server.url, prompt: "buy" });
    expect(result).toMatchObject({
      ok: false,
      error: { code: "payment_settlement_failed", detail: "insufficient_funds" },
    });
    expect(paythos.directSpentMicro).toBe(0n);
    expect(paythos.holds.activeHoldMicro()).toBe(0n);
  });

  it("prefers Circle Gateway batched settlement when offered", async () => {
    const server = await marketServer({
      accepts: [
        requirement(
          { name: "GatewayWalletBatched", version: "2", verifyingContract: GATEWAY_WALLET },
          "20000",
        ),
      ],
    });
    const paythos = client();
    const result = await paythos.fetchWithCircleMarketplace({ url: server.url, prompt: "buy" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.amountMicro).toBe(20_000n);
    expect(result.payment?.gatewayBatched).toBe(true);
    expect(result.settlement?.success).toBe(true);
  });

  it("denies an unallowlisted marketplace payee before signing", async () => {
    const server = await marketServer({
      accepts: [requirement({ name: "USDC", version: "2" })],
    });
    const paythos = client(new Set());
    const result = await paythos.fetchWithCircleMarketplace({ url: server.url, prompt: "buy" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("policy_failure");
    expect(result.error.detail).toMatch(/allowlist/);
    // Only the initial 402 probe ran; no signed retry left the process.
    expect(server.requests()).toBe(1);
  });

  it("requires human approval for Tier-2 marketplace spend (fail closed)", async () => {
    const server = await marketServer({
      accepts: [requirement({ name: "USDC", version: "2" }, "2000000")],
    });
    const paythos = client();
    const result = await paythos.fetchWithCircleMarketplace({ url: server.url, prompt: "buy" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("human_approval_required");
    expect(server.requests()).toBe(1);
  });
});
