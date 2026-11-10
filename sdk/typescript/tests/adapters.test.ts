/**
 * Gate-4 adapter conformance (docs/ARCHITECTURE.md Module 5).
 * The adapters are duck-typed against their host frameworks (no hard deps);
 * these tests validate the exact shapes LangChain / ElizaOS / AutoGen consume.
 */
import { describe, expect, it } from "vitest";
import { AddressInfo } from "node:net";
import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { PaythosClient } from "../src/client/paythosClient.js";
import { makeLangChainTools } from "../src/adapters/langchain.js";
import { makeElizaPlugin } from "../src/adapters/elizaos.js";
import { makeAutoGenSpecs, makeAutoGenHandlers } from "../src/adapters/autogen.js";
import { PaymentChallenge } from "../src/types.js";
import { AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";

const MERCHANT = TEST_MERCHANT;

function challenge(payTo: string, max: string): PaymentChallenge {
  return {
    x402Version: 2,
    scheme: "exact",
    network: TESTNET,
    asset: AR_NATIVE_USDC,
    payTo,
    max,
    resource: "https://api.example.com/premium",
  };
}

/** Minimal x402 backend: 402 challenge first, 200 on the signed retry. */
async function paidBackend(price: string): Promise<{ url: string; close: () => void }> {
  const server = await new Promise<import("node:http").Server>((resolve) => {
    const s = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (!req.headers["payment-signature"]) {
        res.writeHead(402, {
          "payment-required": Buffer.from(JSON.stringify(challenge(MERCHANT, price)), "utf8").toString("base64"),
        });
        res.end("payment required");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, paid: price }));
    });
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/premium`,
    close: () => server.close(),
  };
}

function fixtures(fetchOverride?: typeof fetch): { client: PaythosClient; signer: AgentVoucherSigner } {
  const signer = new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    epoch: 1,
  });
  const client = new PaythosClient(signer, {
    signer,
    network: TESTNET,
    allowlist: new Set([MERCHANT.toLowerCase()]),
    ...(fetchOverride ? { fetch: fetchOverride } : {}),
  });
  return { client, signer };
}

describe("LangChain adapter", () => {
  it("exposes DynamicStructuredTool-shaped tools and executes every action", async () => {
    const { client, signer } = fixtures();
    const tools = makeLangChainTools(client, signer);
    expect(tools.map((t) => t.name)).toEqual(["paythos_dry_run", "paythos_purchase", "paythos_budget"]);
    for (const tool of tools) {
      expect(typeof tool.description).toBe("string");
      expect(tool.schema).toBeDefined();
      expect(typeof tool.func).toBe("function");
    }

    const [dryRun, purchase, budget] = tools;
    const report = JSON.parse(await dryRun!.func({ ...challenge(MERCHANT, "0.25") })) as {
      willSucceed: boolean;
      tier: number;
    };
    expect(report.willSucceed).toBe(true);
    expect(report.tier).toBe(1);

    const backend = await paidBackend("0.25");
    try {
      const bought = JSON.parse(
        await purchase!.func({ url: backend.url, challenge: challenge(MERCHANT, "0.25"), prompt: "article" }),
      ) as { status: number; voucher: { cumulativeAmount: string } };
      expect(bought.status).toBe(200);
      expect(bought.voucher.cumulativeAmount).toBe("250000");
    } finally {
      backend.close();
    }

    const snapshot = JSON.parse(await budget!.func({})) as {
      agentKey: string;
      ledger: { sessionTotalUsd: string }[];
      remainingAllowanceUsd: string;
    };
    expect(snapshot.agentKey).toBe(signer.agentKey);
    expect(snapshot.ledger).toHaveLength(1);
    expect(snapshot.ledger[0]!.sessionTotalUsd).toBe("0.25");
  });
});

describe("ElizaOS adapter", () => {
  it("emits plugin actions with validate/handler semantics and budget-safe fallthrough", async () => {
    let backendUrl = "";
    const rerouted = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return fetch(url === "https://api.example.com/premium" ? backendUrl : url, init);
    }) as typeof fetch;
    const { client, signer } = fixtures(rerouted);
    const plugin = makeElizaPlugin(client, signer);
    expect(plugin.name).toBe("paythos");
    expect(plugin.actions.map((a) => a.name)).toEqual(["PAYTHOS_DRY_RUN", "PAYTHOS_PURCHASE"]);

    const runtime = { agentId: "agent-1" };
    const dry = plugin.actions[0]!;
    const message = {
      content: { text: `Simulate this spend: ${JSON.stringify(challenge(MERCHANT, "0.75"))}` },
    };
    expect(await dry.validate(runtime, message)).toBe(true);
    const dryResult = await dry.handler(runtime, message);
    expect(dryResult.success).toBe(true);
    expect(dryResult.text).toContain("tier 1");

    expect(await dry.validate(runtime, { content: { text: "no challenge here" } })).toBe(false);

    const buy = plugin.actions[1]!;
    const backend = await paidBackend("0.25");
    backendUrl = backend.url;
    try {
      const buyText = `paythos:buy ${JSON.stringify(challenge(MERCHANT, "0.25"))}`;
      expect(await buy.validate(runtime, { content: { text: buyText } })).toBe(true);
      expect(await buy.validate(runtime, { content: { text: `no buy verb ${JSON.stringify(challenge(MERCHANT, "0.25"))}` } })).toBe(false);
      const bought = await buy.handler(runtime, { content: { text: buyText } });
      expect(bought.success, bought.text).toBe(true);
      expect(bought.text).toContain("Purchased");
    } finally {
      backend.close();
    }
  });
});

describe("AutoGen adapter", () => {
  it("emits OpenAI function specs plus a dispatch table wired to the SDK", async () => {
    const { client, signer } = fixtures();
    const specs = makeAutoGenSpecs();
    expect(specs.map((s) => s.function.name)).toEqual(["paythos_dry_run", "paythos_purchase", "paythos_budget"]);
    for (const spec of specs) {
      expect(spec.type).toBe("function");
      expect(spec.function.parameters.type).toBe("object");
    }
    expect(() => JSON.stringify(specs)).not.toThrow();

    const handlers = makeAutoGenHandlers(client, signer);
    expect(Object.keys(handlers).sort()).toEqual(["paythos_budget", "paythos_dry_run", "paythos_purchase"]);

    const report = (await handlers["paythos_dry_run"]!({ challenge: challenge(MERCHANT, "0.25") })) as {
      willSucceed: boolean;
    };
    expect(report.willSucceed).toBe(true);

    const backend = await paidBackend("0.25");
    try {
      const bought = (await handlers["paythos_purchase"]!({
        url: backend.url,
        challenge: challenge(MERCHANT, "0.25"),
        prompt: "article",
      })) as { status: number; voucher: { cumulativeAmount: string } };
      expect(bought.status).toBe(200);
      expect(bought.voucher.cumulativeAmount).toBe("250000");
    } finally {
      backend.close();
    }

    const snapshot = (await handlers["paythos_budget"]!({})) as { agentKey: string; ledger: unknown[] };
    expect(snapshot.agentKey).toBe(signer.agentKey);
    expect(snapshot.ledger).toHaveLength(1);
  });
});
