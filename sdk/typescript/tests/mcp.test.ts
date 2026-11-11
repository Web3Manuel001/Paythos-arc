/**
 * Gate-4 MCP server conformance (docs/ARCHITECTURE.md Module 4.3).
 * Boots the stdio JSON-RPC daemon with ONLY env vars (no config code) and
 * exercises the MCP handshake + all four tools offline.
 */
import { describe, expect, it } from "vitest";
import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PaymentChallenge } from "../src/types.js";
import { AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";

interface RpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: {
    content?: { type: string; text: string }[];
  };
  error?: { code: number; message: string };
}

const TOOL_NAMES = ["get_agent_budget", "dry_run_errand", "settle_invoice", "query_x402_resource"];

function challenge(): PaymentChallenge {
  return {
    x402Version: 2,
    scheme: "exact",
    network: TESTNET,
    asset: AR_NATIVE_USDC,
    payTo: TEST_MERCHANT,
    max: "0.25",
    resource: "https://api.example.com/premium",
  };
}

/** Line-delimited JSON-RPC client over the child's stdio. */
class McpClient {
  readonly child: ChildProcessWithoutNullStreams;
  #buffer = "";
  #waiters = new Map<number, (res: RpcResponse) => void>();
  #lines: RpcResponse[] = [];

  constructor(env: Record<string, string>, stateFile: string) {
    this.child = spawn(process.execPath, ["--import", "tsx", "src/mcp/server.ts"], {
      cwd: new URL("..", import.meta.url).pathname,
      env: { ...process.env, ...env, PAYTHOS_MCP_LEDGER: stateFile },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      for (;;) {
        const newline = this.#buffer.indexOf("\n");
        if (newline === -1) break;
        const line = this.#buffer.slice(0, newline).trim();
        this.#buffer = this.#buffer.slice(newline + 1);
        if (!line) continue;
        const parsed = JSON.parse(line) as RpcResponse;
        const id = typeof parsed.id === "number" ? parsed.id : null;
        const waiter = id === null ? undefined : this.#waiters.get(id);
        if (waiter) {
          this.#waiters.delete(id);
          waiter(parsed);
        } else {
          this.#lines.push(parsed);
        }
      }
    });
  }

  request(id: number, method: string, params?: Record<string, unknown>): Promise<RpcResponse> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout waiting for ${method}`)), 10_000);
      this.#waiters.set(id, (res) => {
        clearTimeout(timer);
        resolve(res);
      });
      this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, 2_000);
      this.child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      this.child.kill();
    });
  }
}

function toolPayload(res: RpcResponse): Record<string, unknown> {
  expect(res.error).toBeUndefined();
  const text = res.result?.content?.[0]?.text;
  if (typeof text !== "string") throw new Error("missing MCP text content");
  return JSON.parse(text) as Record<string, unknown>;
}

describe("Paythos MCP server (stdio)", () => {
  it("boots with env vars only and serves the handshake + four tools", async () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), "paythos-mcp-")), "ledger.json");
    const rpc = new McpClient(
      {
        PAYTHOS_EPHEMERAL_KEY: ephemeralPrivateKey(),
        PAYTHOS_VAULT_ADDRESS: TEST_VAULT,
        PAYTHOS_AGENT_EPOCH: "1",
        PAYTHOS_MERCHANTS: TEST_MERCHANT,
      },
      stateFile,
    );

    try {
      const init = toolPayload(await rpc.request(1, "initialize", { protocolVersion: "2024-11-05" }));
      expect((init["serverInfo"] as { name: string }).name).toBe("paythos-mcp");
      expect(init["protocolVersion"]).toBe("2024-11-05");

      const list = toolPayload(await rpc.request(2, "tools/list"));
      const tools = list["tools"] as { name: string; description: string; inputSchema: unknown }[];
      expect(tools.map((t) => t.name)).toEqual(TOOL_NAMES);
      for (const tool of tools) {
        expect(typeof tool.description).toBe("string");
        expect(tool.inputSchema).toBeTruthy();
      }

      const budget = toolPayload(await rpc.request(3, "tools/call", { name: "get_agent_budget", arguments: {} }));
      expect(budget["epoch"]).toBe(1);
      expect(budget["network"]).toBe(TESTNET);
      expect(budget["vaultAddress"]).toBe(TEST_VAULT);
      expect(budget["allowanceSource"]).toBe("spec_default");
      expect(budget["remainingAllowanceMicro"]).toBe("20");
      expect(budget["spendLedgerCount"]).toBe(0);

      const report = toolPayload(
        await rpc.request(4, "tools/call", { name: "dry_run_errand", arguments: { challenge: challenge() } }),
      );
      expect(report["willSucceed"]).toBe(true);
      expect(report["tier"]).toBe(1);

      const settled = toolPayload(
        await rpc.request(5, "tools/call", {
          name: "settle_invoice",
          arguments: { challenge: challenge(), prompt: "buy premium article" },
        }),
      );
      const voucher = settled["voucher"] as { cumulativeAmount: string; epoch: number };
      expect(voucher.cumulativeAmount).toBe("250000");
      expect(voucher.epoch).toBe(1);
      expect(String(settled["signature"])).toMatch(/^0x[0-9a-f]{130}$/);
      expect(settled["headers"]).toBeTruthy();

      const after = toolPayload(await rpc.request(6, "tools/call", { name: "get_agent_budget", arguments: {} }));
      expect(after["spendLedgerCount"]).toBe(1);

      const unknown = await rpc.request(7, "tools/call", { name: "no_such_tool", arguments: {} });
      expect(unknown.error?.message).toMatch(/unknown tool/);

      const ping = toolPayload(await rpc.request(8, "ping"));
      expect(ping).toEqual({});

      // The ledger snapshot persisted through the stdio session.
      expect(JSON.parse(readFileSync(stateFile, "utf8"))).toHaveLength(1);
    } finally {
      await rpc.stop();
    }
  }, 120_000);

  it("fails closed at startup on an unknown PAYTHOS_NETWORK", async () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), "paythos-mcp-")), "ledger.json");
    const child = spawn(process.execPath, ["--import", "tsx", "src/mcp/server.ts"], {
      cwd: new URL("..", import.meta.url).pathname,
      env: {
        ...process.env,
        PAYTHOS_EPHEMERAL_KEY: ephemeralPrivateKey(),
        PAYTHOS_VAULT_ADDRESS: TEST_VAULT,
        PAYTHOS_AGENT_EPOCH: "1",
        PAYTHOS_NETWORK: "eip155:1",
        PAYTHOS_MCP_LEDGER: stateFile,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    const code = await new Promise<number | null>((resolve) => child.once("exit", (c) => resolve(c)));
    expect(code).toBe(2);
    expect(stderr).toMatch(/unknown PAYTHOS_NETWORK/);
  }, 30_000);
});
