#!/usr/bin/env node
/**
 * Paythos MCP server (docs/ARCHITECTURE.md Module 4.3) — stdio JSON-RPC 2.0.
 * Any MCP-capable agent host (Claude Desktop, Cursor, …) mounts budgeted
 * errands through these four tools. Zero network egress beyond the tools.
 *
 * Run: npx tsx src/mcp/server.ts   (or compiled dist/mcp/server.js)
 * Env: PAYTHOS_EPHEMERAL_KEY, PAYTHOS_VAULT_ADDRESS (AGENTS.md secrets rule 5).
 */
import { createInterface } from "node:readline";
import { writeFileSync } from "node:fs";
import {
  CHAIN_REGISTRY,
  PaymentChallenge,
  formatMicroUsd,
} from "../types.js";
import { AgentVoucherSigner } from "../signer/voucherSigner.js";
import { PaythosClient, DEFAULT_ALLOWANCE_MICRO } from "../client/paythosClient.js";
import { TransactabilityIndex } from "../client/transactability.js";
import { PaythosError } from "../core/errors.js";
import { VaultReader, vaultReaderFor } from "../core/vaultReader.js";
import { JsonRpcProvider, Wallet } from "ethers";
import { loadDotEnv } from "../config/env.js";

loadDotEnv(); // sdk/typescript/.env when present; exported env vars still win

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const TOOLS: McpTool[] = [
  {
    name: "get_agent_budget",
    description:
      "Report the ephemeral agent's remaining rolling allowance, signer ledger state, and GOFER tier thresholds. No side effects.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "dry_run_errand",
    description:
      "Pre-execution financial simulation (Module 4.1): evaluate a x402 challenge through GOFER without moving capital. Always run this before settle_invoice.",
    inputSchema: {
      type: "object",
      required: ["challenge"],
      properties: {
        challenge: {
          type: "object",
          description: "Decoded x402 v2 PAYMENT-REQUIRED challenge (x402Version=2, payTo, max, scheme).",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "settle_invoice",
    description:
      "Sign and record a cumulative EIP-712 voucher for a challenged resource. Runs the full GOFER gate first; Tier-2 spends deny without a human gate provider.",
    inputSchema: {
      type: "object",
      required: ["challenge"],
      properties: {
        challenge: { type: "object", description: "x402 v2 PAYMENT-REQUIRED challenge." },
        prompt: { type: "string", description: "Verifiable-intent prompt text; only its keccak hash leaves the boundary." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "query_x402_resource",
    description:
      "Fetch a x402-gated URL end-to-end: GET → 402 → GOFER gate → voucher → retry. Returns the response text plus the signed voucher for audit.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string", description: "https:// resource URL" },
        prompt: { type: "string", description: "Verifiable-intent prompt text" },
      },
      additionalProperties: false,
    },
  },
];

/* ---------------- server construction (fail-closed env) ---------------- */

function envOrDie(name: string): string {
  const value = process.env[name];
  if (!value) {
    // No stdout pollution — the MCP channel IS stdout. Fail to stderr and exit.
    process.stderr.write(`paythos-mcp: ${name} is not set (secrets come from env, AGENTS.md rule 5)\n`);
    process.exit(2);
  }
  return value;
}

const EPHEMERAL_KEY = envOrDie("PAYTHOS_EPHEMERAL_KEY");
const VAULT_ADDRESS = envOrDie("PAYTHOS_VAULT_ADDRESS");
const NETWORK = (process.env.PAYTHOS_NETWORK ?? "eip155:5042002") as keyof typeof CHAIN_REGISTRY;
const ALLOWLIST = new Set<string>(
  (process.env.PAYTHOS_MERCHANTS ? process.env.PAYTHOS_MERCHANTS.split(",") : [])
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
);

/**
 * Optional on-chain telemetry (Gate 2.5): set PAYTHOS_RPC_URL + the vault
 * default and `get_agent_budget` reports REAL vault state; absent env keeps
 * the offline spec-default (never blocks tool startup).
 */
const RPC_URL = process.env.PAYTHOS_RPC_URL?.trim() || undefined;
let vaultReader: VaultReader | undefined;
function reader(): VaultReader {
  if (!RPC_URL) throw new PaythosError("config_missing", "PAYTHOS_RPC_URL is not set");
  return (vaultReader ??= vaultReaderFor(new JsonRpcProvider(RPC_URL, undefined, { staticNetwork: true }), VAULT_ADDRESS));
}

/**
 * INV-6 epoch resolution (PROTOCOL v3): the live vault epoch is authoritative
 * when RPC is configured; offline mode requires PAYTHOS_AGENT_EPOCH.
 * Epoch 0 (never authorized) fails closed — nothing to sign against.
 */
async function resolveEpoch(agentAddress: string): Promise<number> {
  if (RPC_URL) {
    const live = await reader().epochOf(agentAddress);
    if (live < 1) {
      console.error("FAIL CLOSED: agent has no live delegation epoch on-chain (authorize it first)");
      process.exit(2);
    }
    return live;
  }
  const envEpoch = Number(process.env.PAYTHOS_AGENT_EPOCH ?? NaN);
  if (!Number.isInteger(envEpoch) || envEpoch < 1) {
    console.error("FAIL CLOSED: set PAYTHOS_AGENT_EPOCH (>= 1) or PAYTHOS_RPC_URL (reads epochOf live, INV-6)");
    process.exit(2);
  }
  return envEpoch;
}

/** Pre-sign epoch sync: rotate only when the chain's epoch actually moved. */
async function syncEpoch(): Promise<void> {
  if (!RPC_URL) return;
  const live = await reader().epochOf(signer.agentKey);
  if (live !== signer.epoch) signer.setEpoch(live);
}

const agentAddress = new Wallet(EPHEMERAL_KEY).address;
const liveEpoch = await resolveEpoch(agentAddress);

const signer = new AgentVoucherSigner({
  privateKey: EPHEMERAL_KEY,
  domain: { network: NETWORK, vaultAddress: VAULT_ADDRESS },
  epoch: liveEpoch,
});

async function onChainAllowanceMicro(): Promise<bigint> {
  if (!RPC_URL) return DEFAULT_ALLOWANCE_MICRO;
  return reader().remainingAllowance(signer.agentKey);
}

const client = new PaythosClient(signer, {
  signer,
  network: NETWORK,
  allowlist: ALLOWLIST,
  transactability: new TransactabilityIndex(), // measured in-session health
  allowanceMicro: DEFAULT_ALLOWANCE_MICRO,
  ...(RPC_URL ? { allowanceProvider: onChainAllowanceMicro } : {}),
});

/* ---------------- tool dispatch ---------------- */

function toolResult(id: JsonRpcRequest["id"], payload: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] } }) + "\n";
}

function toolError(id: JsonRpcRequest["id"], code: number, message: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n";
}

function dispatch(req: JsonRpcRequest): string {
  const id = req.id ?? null;
  const params = req.params ?? {};

  switch (req.method) {
    case "initialize":
      return toolResult(id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "paythos-mcp", version: "0.1.0" },
      });

    case "tools/list":
      return toolResult(id, { tools: TOOLS });

    case "tools/call": {
      const name = params["name"] as string | undefined;
      const args = (params["arguments"] as Record<string, unknown> | undefined) ?? {};
      let result: unknown;
      try {
        result = callTool(name, args);
      } catch (err) {
        if (err instanceof PaythosError) {
          return toolResult(id, { error: { code: err.code, message: err.message } });
        }
        return toolError(id, -32603, `internal error: ${String(err)}`);
      }
      if (result instanceof Promise) {
        result.then(
          (payload) => {
            process.stdout.write(toolResult(id, payload));
            persistLedger();
          },
          (err) => {
            const message = err instanceof PaythosError ? `${err.code}: ${err.message}` : String(err);
            process.stdout.write(toolError(id, -32603, message));
          },
        );
        return ""; // async tools answer on the resolved branch
      }
      return toolResult(id, result);
    }

    case "ping":
      return toolResult(id, {});

    default:
      return toolError(id, -32601, `method not found: ${req.method}`);
  }
}

async function callTool(name: string | undefined, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case "get_agent_budget": {
      let real: Awaited<ReturnType<typeof onChainAllowanceMicro>> | undefined;
      if (RPC_URL) {
        try {
          real = await onChainAllowanceMicro();
        } catch {
          real = undefined; // telemetry outage → spec default, tool still answers
        }
      }
      const ledger = signer.ledgerSnapshot().map((e) => [e.merchant, formatMicroUsd(e.cumulativeAmount)]);
      return {
        agentKey: signer.agentKey,
        network: NETWORK,
        vaultAddress: VAULT_ADDRESS,
        chainedVerified: CHAIN_REGISTRY[NETWORK].verified,
        remainingAllowanceMicro: formatMicroUsd(real ?? DEFAULT_ALLOWANCE_MICRO),
        allowanceSource: real !== undefined ? "on_chain" : "spec_default",
        epoch: signer.epoch,
        ledger,
        tiers: {
          microAutoExecUsd: "$1.00",
          humanApprovalUpperUsd: "$10.00",
          hardCeilingUsd: "$25.00",
        },
        spendLedgerCount: ledger.length,
      };
    }

    case "dry_run_errand": {
      const challenge = args["challenge"] as PaymentChallenge;
      const report = client.dryRun(challenge);
      // MCP frames are text/JSON: bigint fields (micro-USDC) must cross as strings.
      return JSON.parse(
        JSON.stringify({ ...report, reason: report.reason, tier: report.tier }, (_, value) =>
          typeof value === "bigint" ? value.toString() : value,
        ),
      ) as Record<string, unknown>;
    }

    case "settle_invoice": {
      const challenge = args["challenge"] as PaymentChallenge;
      const prompt = (args["prompt"] as string | undefined) ?? "mcp settle_invoice";
      const gate = client.gate(challenge, prompt);
      if (!gate.ok) return { error: gate.error };
      if ("needsHuman" in gate && gate.needsHuman) {
        return { error: { code: "human_approval_required", detail: gate.reason } };
      }
      await syncEpoch(); // INV-6: rotate if the agent was re-authorized since startup
      const signed = await signer.recordAndSign(challenge.payTo, gate.amountMicro, gate.memo);
      if (!signed.ok) return { error: signed.error };
      return {
        voucher: {
          ...signed.voucher,
          cumulativeAmount: signed.voucher.cumulativeAmount.toString(),
          validUntil: signed.voucher.validUntil.toString(),
        },
        signature: signed.signature,
        headers: signed.headers,
      };
    }

    case "query_x402_resource": {
      const url = args["url"] as string;
      if (typeof url !== "string" || !/^https:\/\//.test(url)) {
        throw new PaythosError("invalid_challenge", "url must be an https URL");
      }
      return client.fetchWithX402({ url, prompt: (args["prompt"] as string)?.slice(0, 512) ?? url }).then(async (res) => {
        if (!res.ok) return { error: res.error };
        return {
          status: res.data.status,
          body: (await res.data.text()).slice(0, 4096),
          voucher: res.voucher
            ? { ...res.voucher, cumulativeAmount: res.voucher.cumulativeAmount.toString(), validUntil: res.voucher.validUntil.toString() }
            : null,
        };
      });
    }

    default:
      throw new PaythosError("invalid_challenge", `unknown tool: ${name}`);
  }
}

/* ---------------- stdio JSON-RPC loop ---------------- */

const stateFile = process.env.PAYTHOS_MCP_LEDGER;
function persistLedger(): void {
  if (!stateFile) return;
  const snapshot = signer.ledgerSnapshot().map((entry) => ({
    merchant: entry.merchant,
    cumulativeAmount: entry.cumulativeAmount.toString(),
    lastSignedAt: entry.lastSignedAt,
  }));
  writeFileSync(stateFile, JSON.stringify(snapshot), "utf8");
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let req: JsonRpcRequest;
  try {
    req = JSON.parse(trimmed) as JsonRpcRequest;
  } catch {
    process.stdout.write(toolError(null, -32700, "parse error") );
    return;
  }
  const response = dispatch(req);
  process.stdout.write(response);
  persistLedger();
});

// Keep the async tool promises unhandled-safe: MCP stdio is synchronous per line;
// query_x402_resource resolves via promise chaining inside dispatch (fire-and-forget would break ordering),
// so force async tools to be handled:
rl.on("close", () => persistLedger());
process.on("SIGINT", () => { persistLedger(); process.exit(0); });
