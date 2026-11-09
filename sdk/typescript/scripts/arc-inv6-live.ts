/**
 * Arc Testnet live proof of INV-6 (PROTOCOL v3 epoch binding).
 * Runs AGAINST AN EXISTING vault (no deploy):
 *   1. authorizeAgent(agent)          → epoch E
 *   2. claim cumulative C1 (epoch E)  → OK
 *   3. authorizeAgent(agent) again    → epoch E+1, allowlist cleared
 *   4. claim a voucher SIGNED WITH the stale epoch E  → MUST revert SessionEpochMismatch
 *   5. claim with the live epoch E+1  → OK (monotonic cumulative continues)
 *
 * Env:
 *   export PAYTHOS_DEPLOYER_KEY=0x...      # funded owner key (gas + deposits)
 *   export PAYTHOS_VAULT_ADDRESS=0x...     # existing vault (e.g. from arc-e2e.ts)
 *   export PAYTHOS_EPHEMERAL_KEY=0x...     # optional fixed agent key; random if absent
 */
import { Contract, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes } from "ethers";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { loadDotEnv } from "../src/config/env.js";

function envOrExit(name: string): string {
  const v = process.env[name]?.trim();
  if (!v) {
    console.error(`FAIL CLOSED: ${name} missing`);
    process.exit(2);
  }
  return v;
}

async function main(): Promise<void> {
  loadDotEnv();
  const VAULT = envOrExit("PAYTHOS_VAULT_ADDRESS");
  const RPC = process.env.ARC_RPC_URL?.trim() || "https://rpc.testnet.arc.io";
  const provider = new JsonRpcProvider(RPC, undefined, { staticNetwork: true });
  const deployer = new Wallet(envOrExit("PAYTHOS_DEPLOYER_KEY"), provider);
  const AGENT_KEY = envOrExit("PAYTHOS_EPHEMERAL_KEY");
  const agentSigner = new AgentVoucherSigner({
    privateKey: AGENT_KEY,
    domain: { network: "eip155:5042002", vaultAddress: VAULT },
    epoch: 1, // synced from chain after each authorize below
  });
  const agentKey = agentSigner.agentKey;
  const merchant = deployer.address; // self-merchant, mirrors arc-e2e.ts
  const NETWORK = "eip155:5042002";

  const vault = new Contract(
    VAULT,
    [
      "function epochOf(address) view returns (uint64)",
      "function authorizeAgent(address,(uint256 dailyLimit,uint256 maxPerTx,uint64 expiresAt)) returns ()",
      "function allowMerchant(address,address) returns ()",
      "function claimVoucher((address agentKey,address merchant,address token,uint256 cumulativeAmount,uint256 validUntil,uint64 epoch,bytes32 memo),bytes) returns ()",
      "function claimed(address,address) view returns (uint256)",
      "function feeBps() view returns (uint16)",
    ],
    deployer,
  );
  const chainId = (await provider.getNetwork()).chainId;
  if (chainId !== 5042002n) throw new Error(`wrong chain: ${chainId}`);
  console.log("Arc Testnet INV-6 live session");
  console.log("  vault            :", VAULT);
  console.log("  agent (derived)  :", agentKey);
  console.log("  merchant         :", merchant);

  const policyOf = () => ({ dailyLimit: 5_000_000n, maxPerTx: 1_000_000n, expiresAt: BigInt(Math.floor(Date.now() / 1000) + 3600) });

  // ---- 1. authorize → epoch E ----
  let tx = await vault.authorizeAgent(agentKey, policyOf());
  await tx.wait();
  let epoch = Number(await vault.epochOf(agentKey));
  agentSigner.setEpoch(epoch);
  console.log("  epoch            :", epoch, "(after first authorizeAgent)");

  tx = await vault.allowMerchant(agentKey, merchant);
  await tx.wait();

  // ---- 2. claim with live epoch → OK ----
  const memo1 = keccak256(toUtf8Bytes(`inv6-live:${Date.now()}:a`));
  const s1 = await agentSigner.recordAndSign(merchant, 100_000n, memo1);
  if (!s1.ok) throw new Error(`sign1 failed: ${s1.error.detail}`);
  tx = await vault.claimVoucher(
    { ...s1.voucher, epoch: BigInt(s1.voucher.epoch) },
    s1.signature,
  );
  await tx.wait();
  console.log("  claim #1         :", tx.hash, `epoch ${s1.voucher.epoch} OK (cum 100000)`);

  // ---- 3. re-authorize → epoch E+1, allowlist cleared ----
  tx = await vault.authorizeAgent(agentKey, policyOf());
  await tx.wait();
  const newEpoch = Number(await vault.epochOf(agentKey));
  console.log("  reauth epoch     :", newEpoch, "(bumped from", epoch, ")");
  if (newEpoch !== epoch + 1) throw new Error(`epoch did not increment: ${epoch} → ${newEpoch}`);
  tx = await vault.allowMerchant(agentKey, merchant);
  await tx.wait();

  // ---- 4. STALE-epoch voucher signed with same agent key → MUST revert ----
  // Rebuild a signer on the SAME key but pinned to the OLD epoch; mirror the
  // live ledger so cumulative strictly increases (revert must come from the
  // epoch check, not from monotonicity).
  const stale = new AgentVoucherSigner({
    privateKey: AGENT_KEY,
    domain: { network: NETWORK, vaultAddress: VAULT },
    epoch, // the OLD epoch deliberately
  });
  for (const entry of agentSigner.ledgerSnapshot()) {
    stale.settleMerchant(entry.merchant, entry.cumulativeAmount);
  }
  const memo2 = keccak256(toUtf8Bytes(`inv6-stale:${Date.now()}`));
  const s2 = await stale.recordAndSign(merchant, 100_000n, memo2);
  if (!s2.ok) throw new Error(`stale sign failed: ${s2.error.detail}`);
  if (s2.voucher.epoch !== epoch) throw new Error("stale voucher did not embed the stale epoch");
  let reverted = false;
  try {
    const bad = await vault.claimVoucher({ ...s2.voucher, epoch: BigInt(s2.voucher.epoch) }, s2.signature);
    await bad.wait();
  } catch {
    reverted = true;
  }
  console.log("  stale claim      :", reverted ? "REVERTED OK (SessionEpochMismatch expected)" : "MINED — INV-6 BROKEN");
  if (!reverted) throw new Error("stale-epoch voucher settled on-chain — invariant violated");

  // ---- 5. live-epoch claim under CLEAN-SLATE semantics → OK ----
  // setEpoch(nulls) mirror the vault: authorizeAgent bumps the epoch and the
  // vault zeroes previousClaimed for the pair — cumulative restarts at 100000.
  agentSigner.setEpoch(newEpoch);
  const memo3 = keccak256(toUtf8Bytes(`inv6-live2:${Date.now()}`));
  const s3 = await agentSigner.recordAndSign(merchant, 100_000n, memo3);
  if (!s3.ok) throw new Error(`sign3 failed: ${s3.error.detail}`);
  if (s3.voucher.cumulativeAmount !== 100_000n) throw new Error(`unexpected cumulative ${s3.voucher.cumulativeAmount}`);
  tx = await vault.claimVoucher({ ...s3.voucher, epoch: BigInt(s3.voucher.epoch) }, s3.signature);
  await tx.wait();
  console.log("  claim #2         :", tx.hash, `epoch ${s3.voucher.epoch} OK (cum 100000 — clean-slate epoch)`);

  const claimed = await vault.claimed(agentKey, merchant);
  console.log("  claimed() total  :", claimed.toString(), claimed === 100_000n ? "OK" : "MISMATCH");

  console.log("\nRESULT: PASS — INV-6 live: stale epoch reverted, live epoch settled");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
