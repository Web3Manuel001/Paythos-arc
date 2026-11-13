/**
 * Arc Testnet live smoke: SDK + MCP server + on-chain settlement.
 *
 * Proves a real funded run without any mocks:
 *   1. authorizes a fresh ephemeral agent on an existing v3 vault,
 *   2. boots the MCP stdio server with env only,
 *   3. calls get_agent_budget / dry_run_errand / settle_invoice twice,
 *   4. settles the cumulative voucher on-chain via claimVoucher(),
 *   5. asserts claimed(), epoch() and the fee split.
 *
 * Usage (from sdk/typescript, secrets from .env or the environment):
 *   PAYTHOS_DEPLOYER_KEY=0x…        # vault owner, funded with USDC
 *   PAYTHOS_VAULT_ADDRESS=0x…       # existing v3 vault
 *   PAYTHOS_EPHEMERAL_KEY=0x…       # optional; generated per run when absent
 *   PAYTHOS_MERCHANT_ADDRESS=0x…    # required: the merchant payee being purchased from
 *   npm run e2e:mcp-live
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, getAddress, parseUnits, verifyTypedData } from "ethers";
import { loadDotEnv } from "../src/config/env.js";
import { AgentVoucherSigner, VOUCHER_TYPES } from "../src/signer/voucherSigner.js";
import { claimVoucherArgs } from "../src/middleware/flushDaemon.js";
import { formatMicroUsd } from "../src/types.js";
import type { Voucher } from "../src/types.js";

loadDotEnv();

const ARC_CHAIN_ID = 5042002;
const ARC_USDC = "0x3600000000000000000000000000000000000000";
const NETWORK = "eip155:5042002" as const;
const EXPLORER = "https://explorer.testnet.arc.io";
const here = dirname(fileURLToPath(import.meta.url));
const paythosVaultAbi = JSON.parse(
  readFileSync(resolve(here, "../src/abi/paythosVault.json"), "utf8"),
) as unknown[];

function envOrExit(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    console.error(`FAIL CLOSED: ${name} is not set (secrets come from env only).`);
    process.exit(2);
  }
  return value;
}

const usd = (value: string): bigint => parseUnits(value, 6);

interface RpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: { content?: { type: string; text: string }[] };
  error?: { code: number; message: string };
}

class McpClient {
  readonly child: ChildProcessWithoutNullStreams;
  #buffer = "";
  #waiters = new Map<number, (res: RpcResponse) => void>();
  #stderr = "";

  constructor(env: NodeJS.ProcessEnv) {
    this.child = spawn(process.execPath, ["--import", "tsx", "src/mcp/server.ts"], {
      cwd: resolve(here, ".."),
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.#stderr += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      for (;;) {
        const newline = this.#buffer.indexOf("\n");
        if (newline === -1) break;
        const line = this.#buffer.slice(0, newline).trim();
        this.#buffer = this.#buffer.slice(newline + 1);
        if (!line) continue;
        const parsed = JSON.parse(line) as RpcResponse;
        this.#waiters.get(parsed.id)?.(parsed);
        this.#waiters.delete(parsed.id);
      }
    });
  }

  request(id: number, method: string, params?: Record<string, unknown>): Promise<RpcResponse> {
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`MCP ${method} timed out; stderr: ${this.#stderr.trim()}`));
      }, 30_000);
      this.#waiters.set(id, (res) => {
        clearTimeout(timer);
        resolvePromise(res);
      });
      this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  async stop(): Promise<void> {
    if (this.child.exitCode !== null) return;
    await new Promise<void>((resolvePromise) => {
      const timer = setTimeout(() => {
        this.child.kill("SIGKILL");
        resolvePromise();
      }, 2_000);
      this.child.once("exit", () => {
        clearTimeout(timer);
        resolvePromise();
      });
      this.child.kill();
    });
  }
}

function payload(res: RpcResponse): Record<string, unknown> {
  if (res.error) throw new Error(`MCP error ${res.error.code}: ${res.error.message}`);
  const text = res.result?.content?.[0]?.text;
  if (typeof text !== "string") throw new Error("MCP response has no text payload");
  return JSON.parse(text) as Record<string, unknown>;
}

async function main(): Promise<void> {
  const rpcUrl = process.env.ARC_RPC_URL?.trim() || "https://rpc.testnet.arc.io";
  const deployerKey = envOrExit("PAYTHOS_DEPLOYER_KEY");
  const vaultAddress = getAddress(envOrExit("PAYTHOS_VAULT_ADDRESS"));
  const ephemeralKey = process.env.PAYTHOS_EPHEMERAL_KEY?.trim() || Wallet.createRandom().privateKey;
  const merchant = getAddress(envOrExit("PAYTHOS_MERCHANT_ADDRESS"));

  const provider = new JsonRpcProvider(rpcUrl, undefined, { staticNetwork: true, batchMaxCount: 1 });
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ARC_CHAIN_ID) {
    throw new Error(`RPC chainId ${network.chainId} is not Arc Testnet ${ARC_CHAIN_ID}`);
  }
  const owner = new Wallet(deployerKey, provider);
  const vault = new Contract(vaultAddress, paythosVaultAbi, owner);
  const usdc = new Contract(
    ARC_USDC,
    ["function balanceOf(address) view returns (uint256)", "function approve(address,uint256) returns (bool)"],
    owner,
  );

  const [vaultOwner, token, feeBps, vaultBalance] = await Promise.all([
    vault.owner() as Promise<string>,
    vault.SETTLEMENT_TOKEN() as Promise<string>,
    vault.feeBps() as Promise<bigint>,
    usdc.balanceOf(vaultAddress) as Promise<bigint>,
  ]);
  if (getAddress(vaultOwner) !== owner.address) {
    throw new Error(`deployer ${owner.address} is not vault owner ${vaultOwner}`);
  }
  if (getAddress(token) !== ARC_USDC) throw new Error("vault settlement token is not Arc USDC");
  if (merchant === owner.address) {
    throw new Error("PAYTHOS_MERCHANT_ADDRESS must be the merchant payee, not the vault owner");
  }

  const agent = new AgentVoucherSigner({
    privateKey: ephemeralKey,
    domain: { network: NETWORK, vaultAddress },
    epoch: 1,
  });
  const now = Math.floor(Date.now() / 1000);
  const policy = { dailyLimit: usd("5"), maxPerTx: usd("1"), expiresAt: BigInt(now + 7 * 86_400) };

  console.log("Arc Testnet live MCP + SDK smoke");
  console.log("  rpc             :", rpcUrl);
  console.log("  vault           :", vaultAddress, `(${EXPLORER}/address/${vaultAddress})`);
  console.log("  owner/deployer  :", owner.address);
  console.log("  merchant        :", merchant);
  console.log("  agent (derived) :", agent.agentKey);
  console.log("  feeBps          :", feeBps.toString());

  const authorize = await vault.authorizeAgent(agent.agentKey, policy);
  await authorize.wait();
  const epoch = Number((await vault.epochOf(agent.agentKey)) as bigint);
  agent.setEpoch(epoch);
  const allow = await vault.allowMerchant(agent.agentKey, merchant);
  await allow.wait();
  console.log("  authorizeAgent  :", authorize.hash, "epoch", epoch);
  console.log("  allowMerchant   :", allow.hash);

  const merchantBalanceBefore = (await usdc.balanceOf(merchant)) as bigint;
  const claimUsd = usd("0.10");
  if ((vaultBalance as bigint) < claimUsd) {
    const deposit = usd("0.50");
    const approve = await usdc.approve(vaultAddress, deposit);
    await approve.wait();
    const funded = await vault.deposit(deposit);
    await funded.wait();
    console.log("  deposit         :", funded.hash, "0.50 USDC");
  } else {
    console.log("  vault balance   :", (vaultBalance as bigint).toString(), "(atomic, sufficient)");
  }

  const stateFile = join(mkdtempSync(join(tmpdir(), "paythos-mcp-live-")), "ledger.json");
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    PAYTHOS_EPHEMERAL_KEY: ephemeralKey,
    PAYTHOS_VAULT_ADDRESS: vaultAddress,
    PAYTHOS_RPC_URL: rpcUrl,
    PAYTHOS_MERCHANTS: merchant,
    PAYTHOS_MCP_LEDGER: stateFile,
  };
  delete childEnv.PAYTHOS_DEPLOYER_KEY;
  const mcp = new McpClient(childEnv);

  try {
    const init = payload(await mcp.request(1, "initialize", { protocolVersion: "2024-11-05" }));
    if ((init["serverInfo"] as { name?: string }).name !== "paythos-mcp") {
      throw new Error("MCP handshake did not identify paythos-mcp");
    }
    const tools = payload(await mcp.request(2, "tools/list"))["tools"] as { name: string }[];
    const names = tools.map((tool) => tool.name);
    for (const expected of ["get_agent_budget", "dry_run_errand", "settle_invoice", "query_x402_resource"]) {
      if (!names.includes(expected)) throw new Error(`MCP tool missing: ${expected}`);
    }

    const budget = payload(await mcp.request(3, "tools/call", { name: "get_agent_budget", arguments: {} }));
    if (budget["allowanceSource"] !== "on_chain") {
      throw new Error(`expected on-chain allowance, got ${String(budget["allowanceSource"])}`);
    }
    if (budget["epoch"] !== epoch) throw new Error("MCP epoch does not match the live vault epoch");
    console.log("  MCP budget      :", budget["remainingAllowanceMicro"], "USDC, epoch", budget["epoch"]);

    const challenge = (max: string) => ({
      x402Version: 2 as const,
      scheme: "exact" as const,
      network: NETWORK,
      asset: ARC_USDC,
      payTo: merchant,
      max,
      resource: "https://api.paythos.local/arc-mcp-live",
    });

    const dry = payload(
      await mcp.request(4, "tools/call", { name: "dry_run_errand", arguments: { challenge: challenge("0.04") } }),
    );
    if (dry["willSucceed"] !== true || dry["tier"] !== 1) {
      throw new Error(`dry run did not approve tier 1: ${JSON.stringify(dry)}`);
    }
    console.log("  MCP dryRun      :", "tier", dry["tier"], "| willSucceed", dry["willSucceed"]);

    const first = payload(
      await mcp.request(5, "tools/call", {
        name: "settle_invoice",
        arguments: { challenge: challenge("0.04"), prompt: "arc live invoice one" },
      }),
    );
    const second = payload(
      await mcp.request(6, "tools/call", {
        name: "settle_invoice",
        arguments: { challenge: challenge("0.06"), prompt: "arc live invoice two" },
      }),
    );
    const rawVoucher = second["voucher"] as Voucher & { cumulativeAmount: string; validUntil: string; epoch: number };
    const signature = second["signature"] as string;
    const voucher: Voucher = {
      ...rawVoucher,
      cumulativeAmount: BigInt(rawVoucher.cumulativeAmount),
      validUntil: BigInt(rawVoucher.validUntil),
    };
    void first;
    if (voucher.cumulativeAmount !== claimUsd) {
      throw new Error(`MCP cumulative ${voucher.cumulativeAmount} != ${claimUsd}`);
    }
    if (voucher.epoch !== epoch) throw new Error("voucher epoch does not match the live epoch");

    const recovered = verifyTypedData(
      { name: "Paythos Protocol", version: "3", chainId: ARC_CHAIN_ID, verifyingContract: vaultAddress },
      VOUCHER_TYPES,
      voucher,
      signature,
    );
    if (getAddress(recovered) !== agent.agentKey) throw new Error("voucher signature does not recover to the agent");
    console.log(
      "  MCP vouchers    :",
      `0.04 + 0.06 = ${formatMicroUsd(voucher.cumulativeAmount)} USDC | signature verified`,
    );

    const claim = await vault.claimVoucher(claimVoucherArgs(voucher), signature);
    const receipt = await claim.wait();
    const claimed = (await vault.claimed(agent.agentKey, merchant)) as bigint;
    if (claimed !== claimUsd) throw new Error(`on-chain claimed ${claimed} != ${claimUsd}`);
    const fee = (claimUsd * (feeBps as bigint)) / 10_000n;
    const net = claimUsd - fee;
    const merchantBalanceAfter = (await usdc.balanceOf(merchant)) as bigint;
    if (merchantBalanceAfter - merchantBalanceBefore !== net) {
      throw new Error(
        `merchant payout mismatch: received ${merchantBalanceAfter - merchantBalanceBefore}, expected ${net}`,
      );
    }
    console.log("  claimVoucher    :", claim.hash, "block", receipt?.blockNumber);
    console.log(
      "  claimed()       :",
      `${formatMicroUsd(claimed)} USDC | fee ${formatMicroUsd(fee)} net ${formatMicroUsd(net)}`,
    );
    console.log("  merchant payout :", `${formatMicroUsd(net)} USDC received (balance delta verified)`);
    console.log("\nRESULT: PASS — funded Arc Testnet MCP + SDK + on-chain settlement");
  } finally {
    await mcp.stop();
  }
}

main().catch((err) => {
  console.error("LIVE MCP E2E ERROR:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
