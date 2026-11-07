/**
 * flushd — flush-daemon reconcile tool (Gate 3, INV-M3 ops).
 *
 * Reconciliation runs against the receipts the daemon persisted after every
 * confirmed settlement and the vault's own `claimed()` state; drift spots a
 * receipt written without the settlement landing (operator must investigate).
 *
 * In-process wiring for a merchant service (production embed):
 *   const daemon = new FlushDaemon({
 *     submitter: new EthersVaultSubmitter(wallet, vaultAddress, provider),
 *     receipts: new JsonReceiptStore(path),
 *   });
 *   daemon.attach(accumulator); // middleware flush trigger → on-chain settle
 *
 * Env: PAYTHOS_VAULT_ADDRESS, PAYTHOS_RPC_URL (optional; auth-free read-only
 * calls only, no keys ever needed here — the tool never submits transactions).
 */
import { readFileSync } from "node:fs";
import { loadDotEnv } from "../src/config/env.js";

loadDotEnv();

const VAULT = process.env.PAYTHOS_VAULT_ADDRESS;
if (!VAULT || !/^0x[0-9a-fA-F]{40}$/.test(VAULT)) {
  console.error("FAIL CLOSED: PAYTHOS_VAULT_ADDRESS missing or malformed");
  process.exit(2);
}
const RPC = process.env.PAYTHOS_RPC_URL?.trim() || "https://rpc.testnet.arc.io";
const RECEIPTS_PATH = process.env.PAYTHOS_FLUSH_RECEIPTS ?? "flush-receipts.json";

interface ReceiptLine {
  agentKey: string;
  merchant: string;
  cumulativeAmount: string;
  txHash: string | null;
  settledAt: number;
  alreadySettled?: boolean;
}

async function main(): Promise<void> {
  const { JsonRpcProvider } = await import("ethers");
  const { VaultReader, vaultReaderFor } = await import("../src/core/vaultReader.js");

  let receipts: Array<[string, ReceiptLine]>;
  try {
    const doc = JSON.parse(readFileSync(RECEIPTS_PATH, "utf8")) as Record<string, ReceiptLine>;
    receipts = Object.entries(doc);
  } catch {
    console.log(`no receipts at ${RECEIPTS_PATH} — daemon has not settled anything yet`);
    return;
  }
  if (receipts.length === 0) {
    console.log("receipts file is empty — daemon has not settled anything yet");
    return;
  }

  const provider = new JsonRpcProvider(RPC, undefined, { staticNetwork: true });
  const reader: VaultReader = vaultReaderFor(provider, VAULT);

  let drift = 0;
  for (const [key, r] of receipts) {
    let claimedOnChain: bigint;
    try {
      claimedOnChain = await reader.claimedFor(r.agentKey, r.merchant);
    } catch (err) {
      console.error(`${key}: RPC READ FAILED (${String(err)}) — rerun later`);
      drift += 1;
      continue;
    }
    const receiptTotal = BigInt(r.cumulativeAmount);
    const state = claimedOnChain === receiptTotal ? "OK" : claimedOnChain > receiptTotal ? "OK (ahead)" : "DRIFT (on-chain behind)";
    if (claimedOnChain < receiptTotal) drift += 1;
    const tx = r.txHash ?? (r.alreadySettled ? "already-settled(no tx)" : "MISSING TX");
    console.log(`${key}: receipt ${receiptTotal} | on-chain ${claimedOnChain} | ${state} | tx ${tx} | at ${new Date(r.settledAt * 1000).toISOString()}`);
  }

  if (drift > 0) {
    console.error(`RESULT: ${drift} drifted receipt(s) — investigate before trusting the receipt store`);
    process.exit(1);
  }
  console.log(`RESULT: ${receipts.length} receipt(s) reconcile exactly with vault claimed() state`);
}

main().catch((err) => {
  console.error("FAIL CLOSED:", err);
  process.exit(2);
});
