#!/usr/bin/env node
/**
 * Read-only Circle marketplace compatibility probe.
 *
 * Fetches a real x402 v2 service, decodes the standard PAYMENT-REQUIRED
 * envelope, selects the Arc Testnet USDC accept, and SIGNS a Gateway/exact
 * authorization locally. It never retries or settles, so no USDC moves.
 *
 * Run: npm run probe:marketplace [-- <url>]
 */
import { Wallet } from "ethers";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import {
  createCircleMarketplaceX402,
  ensureWebCrypto,
} from "../src/client/circleMarketplace.js";
import { loadDotEnv } from "../src/config/env.js";

loadDotEnv();

async function main(): Promise<void> {
  await ensureWebCrypto();
  const url = process.argv[2] ?? process.env.PAYTHOS_MARKETPLACE_URL ?? "https://api.botpay.network/go";
  if (!/^https:\/\//.test(url)) throw new Error("marketplace URL must be https");

  const response = await fetch(url, { headers: { accept: "application/json" } });
  const body = await response.json().catch(() => undefined);
  if (response.status !== 402) throw new Error(`expected 402, got ${response.status}`);

  const privateKey = process.env.PAYTHOS_EPHEMERAL_KEY ?? Wallet.createRandom().privateKey;
  const signer = new AgentVoucherSigner({
    privateKey,
    // Only the EIP-712 domain object is built; no voucher is signed here.
    domain: { network: "eip155:5042002", vaultAddress: process.env.PAYTHOS_VAULT_ADDRESS ?? "0x0000000000000000000000000000000000000001" },
    epoch: 1,
  });
  const { http } = createCircleMarketplaceX402(signer);
  const required = http.getPaymentRequiredResponse((name) => response.headers.get(name), body);
  const payload = await http.createPaymentPayload(required);

  process.stdout.write(
    JSON.stringify(
      {
        url,
        selectedNetwork: payload.accepted.network,
        selectedAsset: payload.accepted.asset,
        rail: payload.accepted.extra?.name ?? "exact",
        amountAtomic: payload.accepted.amount,
        payTo: payload.accepted.payTo,
        signed: typeof payload.payload.signature === "string" && payload.payload.signature.length > 100,
        settled: false,
      },
      null,
      2,
    ) + "\n",
  );
}

main().catch((err) => {
  process.stderr.write(`marketplace probe failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
