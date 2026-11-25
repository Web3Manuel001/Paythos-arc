/**
 * Top up the settlement-token reserve of an existing PaythosVault.
 * Owner-only by construction: `deposit()` is `onlyOwner` in bytecode.
 *
 * Usage (from sdk/typescript, secrets from .env or the environment):
 *   npm run vault:fund                # deposit 1.00 USDC
 *   npm run vault:fund -- 2.50        # deposit 2.50 USDC
 *
 * Env:
 *   PAYTHOS_DEPLOYER_KEY=0x...        # vault owner; also pays Arc gas in USDC
 *   PAYTHOS_VAULT_ADDRESS=0x...       # existing vault
 *   ARC_RPC_URL=...                   # optional, defaults to Arc Testnet RPC
 *
 * Never prints a key. PaythosVault.deposit() is the only capital-in path;
 * the vault has no receive()/fallback(), so a plain transfer would be lost.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, Wallet, getAddress, parseUnits } from "ethers";
import { loadDotEnv } from "../src/config/env.js";
import { arcRpcProvider } from "../src/core/arcRpc.js";
import { formatMicroUsd } from "../src/types.js";

loadDotEnv();

const ARC_CHAIN_ID = 5042002n;
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

async function main(): Promise<void> {
  const amountArg = process.argv[2]?.trim() || "1";
  const amount = parseUnits(amountArg, 6);
  if (amount <= 0n) throw new Error(`amount must be > 0, got ${amountArg}`);

  const rpcUrl = process.env.ARC_RPC_URL?.trim() || "https://rpc.testnet.arc.io";
  const vaultAddress = getAddress(envOrExit("PAYTHOS_VAULT_ADDRESS"));
  const owner = new Wallet(envOrExit("PAYTHOS_DEPLOYER_KEY"), arcRpcProvider(rpcUrl, { network: NETWORK }));

  const reportedChainId = BigInt(await owner.provider.send("eth_chainId", []));
  if (reportedChainId !== ARC_CHAIN_ID) {
    throw new Error(`RPC chainId ${reportedChainId} is not Arc Testnet ${ARC_CHAIN_ID}`);
  }

  const vault = new Contract(vaultAddress, paythosVaultAbi, owner);
  const usdc = new Contract(
    ARC_USDC,
    ["function balanceOf(address) view returns (uint256)", "function allowance(address,address) view returns (uint256)", "function approve(address,uint256) returns (bool)"],
    owner,
  );

  const [vaultOwner, token] = await Promise.all([vault.owner() as Promise<string>, vault.SETTLEMENT_TOKEN() as Promise<string>]);
  if (getAddress(vaultOwner) !== owner.address) {
    throw new Error(`signer ${owner.address} is not vault owner ${vaultOwner}`);
  }
  if (getAddress(token) !== ARC_USDC) throw new Error("vault settlement token is not Arc USDC");

  const [ownerBalance, allowance, vaultBefore] = await Promise.all([
    usdc.balanceOf(owner.address) as Promise<bigint>,
    usdc.allowance(owner.address, vaultAddress) as Promise<bigint>,
    usdc.balanceOf(vaultAddress) as Promise<bigint>,
  ]);
  if (ownerBalance < amount) {
    throw new Error(
      `owner holds ${formatMicroUsd(ownerBalance)} USDC, requested deposit is ${formatMicroUsd(amount)} USDC (Arc gas is also paid in USDC)`,
    );
  }

  console.log("Arc Testnet vault top-up");
  console.log("  vault           :", vaultAddress, `(${EXPLORER}/address/${vaultAddress})`);
  console.log("  owner           :", owner.address);
  console.log("  amount          :", formatMicroUsd(amount), "USDC");
  console.log("  vault before    :", formatMicroUsd(vaultBefore), "USDC");
  console.log("  owner balance   :", formatMicroUsd(ownerBalance), "USDC");

  if (allowance < amount) {
    const approve = await usdc.approve(vaultAddress, amount);
    await approve.wait();
    console.log("  approve         :", approve.hash);
  }

  const funded = await vault.deposit(amount);
  const receipt = await funded.wait();
  const vaultAfter = (await usdc.balanceOf(vaultAddress)) as bigint;
  if (vaultAfter - vaultBefore !== amount) {
    throw new Error(`vault delta ${vaultAfter - vaultBefore} != deposit ${amount}`);
  }

  console.log("  deposit         :", funded.hash, "block", receipt?.blockNumber);
  console.log("  vault after     :", formatMicroUsd(vaultAfter), "USDC");
  console.log("\nRESULT: PASS (vault reserve topped up)");
}

main().catch((err) => {
  console.error("VAULT FUND ERROR:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
