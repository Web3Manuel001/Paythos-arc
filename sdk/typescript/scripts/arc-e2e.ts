/**
 * Arc Testnet end-to-end proof (docs/ROADMAP.md Gate 2 acceptance).
 *
 * Deploys PaythosVault to Arc Testnet, authorizes an ephemeral agent, funds the
 * vault, signs a cumulative EIP-712 voucher OFFLINE with the SDK signer, settles
 * it on-chain via claimVoucher(), and verifies the on-chain invariants + fee split.
 *
 * Fail-closed: exits(2) when required secrets/Funding are absent (AGENTS.md rule 5).
 * Secrets are read from the environment only and never logged.
 *
 * Usage:
 *   export PAYTHOS_DEPLOYER_KEY=0x...      # funded owner/hot-key (gas in USDC)
 *   export PAYTHOS_TREASURY_ADDRESS=0x...  # non-zero treasury wallet
 *   export PAYTHOS_EPHEMERAL_KEY=0x...     # agent signing key (can be fresh)
 *   # optional:
 *   export PAYTHOS_MERCHANT_ADDRESS=0x...  # default: deployer address
 *   export PAYTHOS_DEPOSIT_USD=0.50
 *   export PAYTHOS_CLAIM_USD=0.10
 *   npx tsx scripts/arc-e2e.ts
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  Contract,
  ContractFactory,
  JsonRpcProvider,
  Wallet,
  getAddress,
  parseUnits,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import type { ContractTransactionResponse, InterfaceAbi } from "ethers";
import { AgentVoucherSigner, GoferPolicyEngine } from "../src/index.js";
import type { PaythosNetwork } from "../src/types.js";

interface VaultLike {
  deploymentTransaction(): ContractTransactionResponse | null;
  waitForDeployment(): Promise<unknown>;
  getAddress(): Promise<string>;
  SETTLEMENT_TOKEN(): Promise<string>;
  TREASURY(): Promise<string>;
  authorizeAgent(
    agentKey: string,
    policy: { dailyLimit: bigint; maxPerTx: bigint; expiresAt: bigint },
  ): Promise<ContractTransactionResponse>;
  allowMerchant(agentKey: string, merchant: string): Promise<ContractTransactionResponse>;
  deposit(amount: bigint): Promise<ContractTransactionResponse>;
  claimVoucher(
    voucher: {
      agentKey: string;
      merchant: string;
      token: string;
      cumulativeAmount: bigint;
      validUntil: bigint;
      memo: string;
    },
    signature: string,
  ): Promise<ContractTransactionResponse>;
  claimed(agentKey: string, merchant: string): Promise<bigint>;
  spentToday(agentKey: string): Promise<bigint>;
  feeBps(): Promise<bigint>;
}

interface UsdcLike {
  balanceOf(owner: string): Promise<bigint>;
  approve(spender: string, amount: bigint): Promise<ContractTransactionResponse>;
}

const ARC_TESTNET_CHAIN_ID = 5042002;
const ARC_TESTNET_USDC = "0x3600000000000000000000000000000000000000";
const NETWORK: PaythosNetwork = "eip155:5042002";
const EXPLORER = "https://explorer.testnet.arc.io";

function envOrExit(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    console.error(`FAIL CLOSED: ${name} is not set. Secrets come from the environment only.`);
    process.exit(2);
  }
  return value;
}

function usd(str: string): bigint {
  return parseUnits(str, 6);
}

async function main(): Promise<void> {
  const rpcUrl = process.env.ARC_RPC_URL ?? "https://rpc.testnet.arc.io";
  const deployerKey = envOrExit("PAYTHOS_DEPLOYER_KEY");
  const treasury = getAddress(envOrExit("PAYTHOS_TREASURY_ADDRESS"));
  const ephemeralKey = envOrExit("PAYTHOS_EPHEMERAL_KEY");
  const depositUsd = usd(process.env.PAYTHOS_DEPOSIT_USD ?? "0.50");
  const claimUsd = usd(process.env.PAYTHOS_CLAIM_USD ?? "0.10");

  if (treasury === "0x0000000000000000000000000000000000000000") {
    console.error("FAIL CLOSED: PAYTHOS_TREASURY_ADDRESS is the zero address.");
    process.exit(2);
  }

  const provider = new JsonRpcProvider(rpcUrl);
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ARC_TESTNET_CHAIN_ID) {
    console.error(`FAIL CLOSED: RPC chainId ${network.chainId} ≠ Arc Testnet ${ARC_TESTNET_CHAIN_ID}`);
    process.exit(2);
  }

  const deployer = new Wallet(deployerKey, provider);
  const merchant = process.env.PAYTHOS_MERCHANT_ADDRESS
    ? getAddress(process.env.PAYTHOS_MERCHANT_ADDRESS)
    : deployer.address;

  console.log("Arc Testnet E2E — Paythos Protocol");
  console.log("  deployer (owner):", deployer.address);
  console.log("  treasury        :", treasury);
  console.log("  merchant        :", merchant);

  // ---- 1. Deploy the vault (ABI from the SDK package, bytecode from forge out/) ----
  const here = dirname(fileURLToPath(import.meta.url));
  const artifactPath = resolve(here, "../../../contracts/out/PaythosVault.sol/PaythosVault.json");
  let artifact: { abi: unknown[]; bytecode: { object: string } };
  try {
    artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as typeof artifact;
  } catch {
    console.error(`FAIL CLOSED: forge artifact missing at ${artifactPath} — run 'forge build' in contracts/ first.`);
    process.exit(2);
  }

  const factory = new ContractFactory(artifact.abi as InterfaceAbi, artifact.bytecode.object, deployer);
  const deployed = await factory.deploy(ARC_TESTNET_USDC, treasury);
  const vault = deployed as unknown as VaultLike;
  console.log("  deploy tx       :", deployed.deploymentTransaction()?.hash ?? "(unknown)");
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log("  vault           :", vaultAddress);
  console.log(`  ${EXPLORER}/address/${vaultAddress}`);

  // ---- 2. Read back immutable wiring ----
  const settlement = getAddress((await vault.SETTLEMENT_TOKEN()) as string);
  const vaultTreasury = getAddress((await vault.TREASURY()) as string);
  if (settlement !== ARC_TESTNET_USDC) throw new Error("settlement token mismatch");
  if (vaultTreasury !== treasury) throw new Error("treasury mismatch");
  console.log("  settlement token:", settlement, "(Arc native USDC precompile)");

  // ---- 3. Ephemeral agent delegation ----
  const agentSigner = new AgentVoucherSigner({
    privateKey: ephemeralKey,
    domain: { network: NETWORK, vaultAddress },
  });
  const agentKey = agentSigner.agentKey;
  const now = Math.floor(Date.now() / 1000);
  const policy = {
    dailyLimit: usd("5"),
    maxPerTx: usd("1"),
    expiresAt: BigInt(now + 3600),
  };
  const authorizeTx = await vault.authorizeAgent(agentKey, policy);
  await authorizeTx.wait();
  console.log("  authorizeAgent  :", authorizeTx.hash);

  const allowTx = await vault.allowMerchant(agentKey, merchant);
  await allowTx.wait();
  console.log("  allowMerchant   :", allowTx.hash, "→", merchant);

  // ---- 4. Fund the vault (owner deposit) ----
  const usdc = new Contract(
    ARC_TESTNET_USDC,
    [
      "function balanceOf(address) view returns (uint256)",
      "function allowance(address,address) view returns (uint256)",
      "function approve(address,uint256) returns (bool)",
    ],
    deployer,
  ) as unknown as UsdcLike;
  const balance = await usdc.balanceOf(deployer.address);
  console.log("  USDC balance    :", balance.toString(), "(atomic)");
  if (balance < depositUsd) {
    console.error(
      `FAIL CLOSED: deployer holds ${balance} atomic USDC < requested deposit ${depositUsd}. ` +
        "Fund via https://faucet.circle.com then re-run.",
    );
    process.exit(2);
  }
  const approveTx = await usdc.approve(vaultAddress, depositUsd);
  await approveTx.wait();
  const depositTx = await vault.deposit(depositUsd);
  await depositTx.wait();
  console.log("  deposit         :", depositTx.hash, `${depositUsd} atomic`);

  // ---- 5. Offline voucher signing via the SDK (dryRun first, no capital moved) ----
  const challenge = {
    x402Version: 2 as const,
    scheme: "exact" as const,
    network: NETWORK,
    asset: ARC_TESTNET_USDC,
    payTo: merchant,
    max: process.env.PAYTHOS_CLAIM_USD ?? "0.10",
    resource: "https://arc-e2e.paythos.local/invoice",
  };
  const memo = GoferPolicyEngine.intentMemo("arc testnet e2e invoice", now);
  const policyReport = new GoferPolicyEngine().preFlight({
    amountMicro: claimUsd,
    remainingAllowanceMicro: policy.dailyLimit,
    merchant,
    allowlist: new Set([merchant.toLowerCase()]),
    counterpartyApproved: true,
  });
  console.log("  dryRun tier     :", policyReport.tier, "| willSucceed:", policyReport.willSucceed);
  if (!policyReport.willSucceed) throw new Error(`policy denied: ${policyReport.reason}`);

  const signed = await agentSigner.recordAndSign(merchant, claimUsd, memo);
  if (!signed.ok) throw new Error(`voucher signing failed: ${signed.error.detail}`);
  console.log("  voucher memo    :", memo);
  console.log("  cumulative      :", signed.voucher.cumulativeAmount.toString());

  // ---- 6. Settle on-chain ----
  const claimTx = await vault.claimVoucher(
    {
      agentKey: signed.voucher.agentKey,
      merchant: signed.voucher.merchant,
      token: signed.voucher.token,
      cumulativeAmount: signed.voucher.cumulativeAmount,
      validUntil: signed.voucher.validUntil,
      memo: signed.voucher.memo,
    },
    signed.signature,
  );
  const receipt = await claimTx.wait();
  console.log("  claimVoucher    :", claimTx.hash, "block", receipt?.blockNumber);

  // ---- 7. Assert on-chain invariants ----
  const claimed = (await vault.claimed(agentKey, merchant)) as bigint;
  const spentToday = (await vault.spentToday(agentKey)) as bigint;
  const feeBps = (await vault.feeBps()) as bigint;
  const claimedOk = claimed === claimUsd;
  const spentOk = spentToday === claimUsd;
  const feeOk = feeBps === 150n;
  console.log("  claimed()       :", claimed.toString(), claimedOk ? "OK" : "MISMATCH");
  console.log("  spentToday()    :", spentToday.toString(), spentOk ? "OK" : "MISMATCH");
  console.log("  feeBps()        :", feeBps.toString(), feeOk ? "OK (150 bps)" : "MISMATCH");

  const fee = (claimUsd * feeBps) / 10_000n;
  console.log("  fee split       :", `fee=${fee} net=${claimUsd - fee} (atomic USDC)`);

  // ---- 8. Monotonicity guard: replaying the same voucher MUST revert ----
  let replayReverted = false;
  try {
    const replay = await vault.claimVoucher(
      {
        agentKey: signed.voucher.agentKey,
        merchant: signed.voucher.merchant,
        token: signed.voucher.token,
        cumulativeAmount: signed.voucher.cumulativeAmount,
        validUntil: signed.voucher.validUntil,
        memo: signed.voucher.memo,
      },
      signed.signature,
    );
    await replay.wait();
  } catch {
    replayReverted = true;
  }
  console.log("  replay rejected :", replayReverted ? "OK (InvalidVoucherAmount)" : "FAIL — replay landed!");

  const ok = claimedOk && spentOk && feeOk && replayReverted;
  console.log("\nRESULT:", ok ? "PASS — Gate 2 Arc Testnet E2E complete" : "FAIL — see mismatches above");
  console.log("Explorer vault:", `${EXPLORER}/address/${vaultAddress}`);
  console.log("Structured memo:", keccak256(toUtf8Bytes(`${vaultAddress}:${claimTx.hash}`)));
  process.exit(ok ? 0 : 1);
}

main().catch((err) => {
  console.error("E2E ERROR:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
