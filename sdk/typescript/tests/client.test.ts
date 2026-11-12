import { describe, expect, it } from "vitest";
import { AddressInfo } from "node:net";
import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { PaythosClient } from "../src/client/paythosClient.js";
import { decodeChallenge, parseMaxMicro } from "../src/client/paythosClient.js";
import { parseUsdToMicro } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";

const ALLOWLIST = new Set([TEST_MERCHANT.toLowerCase()]);

function challengeJson(max: string): Record<string, unknown> {
  return {
    x402Version: 2,
    scheme: "exact",
    network: TESTNET,
    asset: "0x3600000000000000000000000000000000000000",
    payTo: TEST_MERCHANT,
    max,
    resource: "https://api.example.com/premium",
  };
}

interface TestBackend {
  server: import("node:http").Server;
  url: string;
  requests: { headers: Record<string, string> }[];
}

/** Minimal x402 backend: first call 402s, paid retry returns 200 price + body. */
function paidBackend(price: string): Promise<TestBackend> {
  return new Promise((resolve) => {
    const requests: { headers: Record<string, string> }[] = [];
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string") headers[k.toLowerCase()] = v;
      }
      requests.push({ headers });
      const signatureHeader = headers["payment-signature"];
      if (!signatureHeader) {
        if (req.url === "/echo-challenge") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(challengeJson(price)));
          return;
        }
        res.writeHead(402, {
          "payment-required": Buffer.from(JSON.stringify(challengeJson(price)), "utf8").toString("base64"),
        });
        res.end("payment required");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, paid: price }));
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({
        server,
        url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/premium`,
        requests,
      });
    });
  });
}

describe("PaythosClient.fetchWithX402", () => {
  it("completes the 402 → gate → sign → retry lifecycle end-to-end", async () => {
    const backend = await paidBackend("0.25");
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const client = new PaythosClient(signer, { signer, network: TESTNET, allowlist: ALLOWLIST });

    const result = await client.fetchWithX402({ url: backend.url, prompt: "fetch premium article" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const body = (await result.data.json()) as { paid: string };
    expect(body.paid).toBe("0.25");

    // The retry carried a decodable cumulative voucher + signature.
    expect(backend.requests).toHaveLength(2);
    const payment = JSON.parse(backend.requests[1]!.headers["payment-signature"]!) as {
      voucher: { cumulativeAmount: string };
      signature: string;
    };
    expect(payment.voucher.cumulativeAmount).toBe(parseUsdToMicro("0.25").toString());
    expect(payment.signature.startsWith("0x")).toBe(true);

    backend.server.close();
  });

  it("second purchase to the same merchant is cumulative", async () => {
    const backend = await paidBackend("0.10");
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const client = new PaythosClient(signer, { signer, network: TESTNET, allowlist: ALLOWLIST });

    const first = await client.fetchWithX402({ url: backend.url, prompt: "a" });
    const second = await client.fetchWithX402({ url: backend.url, prompt: "b" });
    expect(first.ok && second.ok).toBe(true);

    const payments = backend.requests
      .map((r) => r.headers["payment-signature"])
      .filter(Boolean)
      .map((raw) => JSON.parse(raw!) as { voucher: { cumulativeAmount: string } });
    expect(payments[0]!.voucher.cumulativeAmount).toBe("100000");
    expect(payments[1]!.voucher.cumulativeAmount).toBe("200000"); // 0.20 total
    backend.server.close();
  });

  it("denies merchants OUTSIDE the destination allowlist", async () => {
    const backend = await paidBackend("0.01");
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const blockedBackend = await paidBackend("0.01");
    const client = new PaythosClient(signer, {
      signer,
      network: TESTNET,
      allowlist: new Set(["0x8888888888888888888888888888888888888888"]),
    });
    const result = await client.fetchWithX402({ url: blockedBackend.url, prompt: "x" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("policy_failure");
    }
    backend.server.close();
  });

  it("Tier-2 spends fail closed without a human-gate provider", async () => {
    const backend = await paidBackend("5.00"); // > $1, ≤ $10
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const client = new PaythosClient(signer, { signer, network: TESTNET, allowlist: ALLOWLIST });
    const result = await client.fetchWithX402({ url: backend.url, prompt: "expensive" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("human_approval_required");
    }
    expect(backend.requests).toHaveLength(1); // no signed retry happened
    backend.server.close();
  });

  it("Tier-2 approves when the human gate confirms", async () => {
    const backend = await paidBackend("5.00");
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const client = new PaythosClient(signer, {
      signer,
      network: TESTNET,
      allowlist: ALLOWLIST,
      approveWithHuman: async (summary) => {
        expect(summary.amountUsd).toBe("5");
        expect(summary.kind).toBe("tier2_review");
        return true;
      },
    });
    const result = await client.fetchWithX402({ url: backend.url, prompt: "approved purchase" });
    expect(result.ok).toBe(true);
    backend.server.close();
  });

  it("dryRun() leaves capital untouched (no ledger registration)", () => {
    const signer = new AgentVoucherSigner({
      privateKey: ephemeralPrivateKey(),
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });
    const client = new PaythosClient(signer, { signer, network: TESTNET, allowlist: ALLOWLIST });
    const report = client.dryRun(challengeJson("0.50") as never);
    expect(report.willSucceed).toBe(true);
    expect(signer.ledgerSnapshot()).toHaveLength(0);
  });
});

describe("challenge decoding", () => {
  it("parseMaxMicro: max is decimal USD, amount is atomic micro (no guessing)", () => {
    expect(parseMaxMicro({ ...challengeJson("0.01"), scheme: "exact" } as never)).toBe(10_000n);
    // Bare integer max is USD, NOT atomic micro (reviewer 2026-11 ambiguity).
    expect(parseMaxMicro({ ...challengeJson("10"), scheme: "exact" } as never)).toBe(10_000_000n);
    expect(parseMaxMicro({ ...challengeJson("100000"), scheme: "exact" } as never)).toBe(100_000_000_000n);
    // Atomic form is the explicit x402 `amount` field.
    expect(
      parseMaxMicro({ ...challengeJson(""), amount: "100000", scheme: "exact" } as never),
    ).toBe(100_000n);
  });
});
