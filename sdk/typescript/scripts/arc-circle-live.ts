/**
 * Arc Testnet live smoke: Circle developer-controlled wallet signs, vault settles.
 *
 * Proves a real funded run without any agent private key in this process:
 *   1. resolves (or creates) an ARC-TESTNET EOA in Circle's developer wallets,
 *   2. authorizes that Circle wallet as an agent on the existing v3 vault,
 *   3. asks Circle `signTypedData` to sign cumulative vouchers,
 *   4. verifies the EIP-712 signature recovers to the Circle wallet,
 *   5. settles via claimVoucher() and asserts claimed() + merchant payout.
 *
 * The Circle wallet holds no USDC: it only signs. Funding stays in the vault.
 *
 * Usage (from sdk/typescript, secrets from .env or the environment):
 *   CIRCLE_API_KEY=…                 # Circle console API key
 *   CIRCLE_ENTITY_SECRET=…           # Circle entity secret (never commit)
 *   CIRCLE_WALLET_ID=…               # optional; creates an EOA wallet when absent
 *   PAYTHOS_DEPLOYER_KEY=0x…         # vault owner, funded with USDC
 *   PAYTHOS_VAULT_ADDRESS=0x…        # existing v3 vault
 *   PAYTHOS_MERCHANT_ADDRESS=0x…     # merchant payee (not the vault owner)
 *   npm run e2e:circle-live
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, getAddress, parseUnits, verifyTypedData } from "ethers";
import { initiateDeveloperControlledWalletsClient } from "@circle-fin/developer-controlled-wallets";
import { loadDotEnv } from "../src/config/env.js";
import {
  createCircleWalletVoucherSigner,
  type CircleWalletClientLike,
} from "../src/signer/circleWalletSigner.js";
import { VOUCHER_TYPES } from "../src/signer/voucherSigner.js";
import { claimVoucherArgs } from "../src/middleware/flushDaemon.js";
import { formatMicroUsd } from "../src/types.js";

loadDotEnv();

const ARC_CHAIN_ID = 5042002;
const ARC_USDC = "0x3600000000000000000000000000000000000000";
const NETWORK = "eip155:5042002" as const;
const CIRCLE_BLOCKCHAIN = "ARC-TESTNET";
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

interface ResolvedCircleWallet {
  id: string;
  address: string;
  blockchain: string;
  accountType: string;
}

async function resolveWallet(
  client: ReturnType<typeof initiateDeveloperControlledWalletsClient>,
): Promise<ResolvedCircleWallet> {
  const existingId = process.env.CIRCLE_WALLET_ID?.trim();
  if (existingId) {
    const response = await client.getWallet({ id: existingId });
    const wallet = response.data?.wallet;
    if (!wallet) throw new Error(`Circle wallet ${existingId} not found`);
    return {
      id: wallet.id,
      address: getAddress(wallet.address),
      blockchain: wallet.blockchain,
      accountType: wallet.accountType ?? "EOA",
    };
  }

  const walletSet = await client.createWalletSet({ name: `Paythos Arc agent ${new Date().toISOString()}` });
  const walletSetId = walletSet.data?.walletSet?.id;
  if (!walletSetId) throw new Error("Circle createWalletSet returned no wallet set id");
  const created = await client.createWallets({
    walletSetId,
    blockchains: [CIRCLE_BLOCKCHAIN],
    count: 1,
    accountType: "EOA",
  });
  const wallet = created.data?.wallets?.[0];
  if (!wallet) throw new Error("Circle createWallets returned no wallet");
  return {
    id: wallet.id,
    address: getAddress(wallet.address),
    blockchain: wallet.blockchain,
    accountType: wallet.accountType ?? "EOA",
  };
}

async function main(): Promise<void> {
  const rpcUrl = process.env.ARC_RPC_URL?.trim() || "https://rpc.testnet.arc.io";
  const deployerKey = envOrExit("PAYTHOS_DEPLOYER_KEY");
  const vaultAddress = getAddress(envOrExit("PAYTHOS_VAULT_ADDRESS"));
  const merchant = getAddress(envOrExit("PAYTHOS_MERCHANT_ADDRESS"));
  const circleApiKey = envOrExit("CIRCLE_API_KEY");
  const circleEntitySecret = envOrExit("CIRCLE_ENTITY_SECRET");

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

  const client = initiateDeveloperControlledWalletsClient({
    apiKey: circleApiKey,
    entitySecret: circleEntitySecret,
  });
  const wallet = await resolveWallet(client);
  if (wallet.blockchain !== CIRCLE_BLOCKCHAIN) {
    throw new Error(`Circle wallet is on ${wallet.blockchain}, expected ${CIRCLE_BLOCKCHAIN}`);
  }
  if (wallet.accountType !== "EOA") {
    // ERC-1271 would need the SCA deployed before claimVoucher; keep this smoke EOA-only.
    throw new Error(`Circle wallet ${wallet.id} is ${wallet.accountType}; this smoke requires an EOA`);
  }
  if (wallet.address === owner.address) {
    throw new Error("Circle agent wallet must differ from the vault owner/deployer");
  }
  if (merchant === owner.address) {
    throw new Error("PAYTHOS_MERCHANT_ADDRESS must be the merchant payee, not the vault owner");
  }

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

  console.log("Arc Testnet live Circle Wallet + SDK smoke");
  console.log("  rpc             :", rpcUrl);
  console.log("  vault           :", vaultAddress, `(${EXPLORER}/address/${vaultAddress})`);
  console.log("  owner/deployer  :", owner.address);
  console.log("  merchant        :", merchant);
  console.log("  circle wallet   :", wallet.address, `(id ${wallet.id})`);
  console.log("  feeBps          :", feeBps.toString());

  const now = Math.floor(Date.now() / 1000);
  const policy = { dailyLimit: usd("5"), maxPerTx: usd("1"), expiresAt: BigInt(now + 7 * 86_400) };
  const authorize = await vault.authorizeAgent(wallet.address, policy);
  await authorize.wait();
  const epoch = Number((await vault.epochOf(wallet.address)) as bigint);
  const allow = await vault.allowMerchant(wallet.address, merchant);
  await allow.wait();
  console.log("  authorizeAgent  :", authorize.hash, "epoch", epoch);
  console.log("  allowMerchant   :", allow.hash);

  const signer = createCircleWalletVoucherSigner({
    client: client as CircleWalletClientLike,
    walletId: wallet.id,
    walletAddress: wallet.address,
    domain: { network: NETWORK, vaultAddress },
    epoch,
  });
  const first = await signer.recordAndSign(merchant, usd("0.04"), "0x" + "a1".repeat(32));
  const second = await signer.recordAndSign(merchant, usd("0.06"), "0x" + "a2".repeat(32));
  if (!first.ok) throw new Error(`Circle voucher 1 failed: ${first.error.detail}`);
  if (!second.ok) throw new Error(`Circle voucher 2 failed: ${second.error.detail}`);
  const voucher = second.voucher;
  const signature = second.signature;
  if (voucher.cumulativeAmount !== usd("0.10")) {
    throw new Error(`cumulative ${voucher.cumulativeAmount} != 0.10 USDC`);
  }
  if (voucher.epoch !== epoch) throw new Error("voucher epoch does not match the live epoch");

  const recovered = verifyTypedData(
    { name: "Paythos Protocol", version: "3", chainId: ARC_CHAIN_ID, verifyingContract: vaultAddress },
    VOUCHER_TYPES,
    voucher,
    signature,
  );
  if (getAddress(recovered) !== wallet.address) {
    throw new Error(`Circle signature recovered ${recovered}, expected ${wallet.address}`);
  }
  console.log(
    "  Circle vouchers :",
    `0.04 + 0.06 = ${formatMicroUsd(voucher.cumulativeAmount)} USDC | signature verified`,
  );

  const merchantBalanceBefore = (await usdc.balanceOf(merchant)) as bigint;
  if ((vaultBalance as bigint) < voucher.cumulativeAmount) {
    const deposit = usd("0.50");
    const approve = await usdc.approve(vaultAddress, deposit);
    await approve.wait();
    const funded = await vault.deposit(deposit);
    await funded.wait();
    console.log("  deposit         :", funded.hash, "0.50 USDC");
  } else {
    console.log("  vault balance   :", (vaultBalance as bigint).toString(), "(atomic, sufficient)");
  }

  const claim = await vault.claimVoucher(claimVoucherArgs(voucher), signature);
  const receipt = await claim.wait();
  const claimed = (await vault.claimed(wallet.address, merchant)) as bigint;
  if (claimed !== voucher.cumulativeAmount) {
    throw new Error(`on-chain claimed ${claimed} != ${voucher.cumulativeAmount}`);
  }
  const fee = (voucher.cumulativeAmount * (feeBps as bigint)) / 10_000n;
  const net = voucher.cumulativeAmount - fee;
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
  console.log("  agent balance   : 0 USDC on Circle wallet (signing only; vault enforces limits)");
  console.log("\nRESULT: PASS — Circle Wallet EIP-712 signature settled on Arc Testnet");
  console.log(`Reuse with CIRCLE_WALLET_ID=${wallet.id}`);
}

main().catch((err) => {
  console.error("LIVE CIRCLE E2E ERROR:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
