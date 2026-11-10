/**
 * Gate-2 acceptance harness: in-memory voucher verification p99 < 5ms
 * (SECURITY.md INV-M1 — no RPC on the hot path).
 *
 * Usage: npx tsx scripts/bench-verify.ts [samples] [--enforce]
 *
 * The dominant cost is secp256k1 public-key recovery (pure JS). On typical
 * CI hardware ecrecover lands ~1-3ms, keeping p99 within the 5ms budget;
 * slow dev VMs can exceed it. Default is advisory; `--enforce` turns the
 * budget breach into a non-zero exit (release gating).
 */
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { VoucherAccumulator } from "../src/middleware/merchant.js";
import { serializeVoucher } from "../src/client/paythosClient.js";
import { AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "../tests/helpers.js";
import { PAYMENT_SIGNATURE_HEADER } from "../src/types.js";

const args = process.argv.slice(2);
const ENFORCE = args.includes("--enforce");
const SAMPLES = Number(args.find((a) => /^\d+$/.test(a)) ?? 2_000);
const BUDGET_MS = 5;

if (!Number.isInteger(SAMPLES) || SAMPLES < 100) {
  console.error(`usage: npx tsx scripts/bench-verify.ts [samples>=100] (got ${process.argv[2]})`);
  process.exit(2);
}

const signer = new AgentVoucherSigner({
  privateKey: ephemeralPrivateKey(),
  domain: { network: TESTNET, vaultAddress: TEST_VAULT },
  epoch: 1,
});
const accumulator = new VoucherAccumulator({
  network: TESTNET,
  vaultAddress: TEST_VAULT,
  settlementToken: AR_NATIVE_USDC,
  authorizedAgents: new Map([[signer.agentKey.toLowerCase(), 1]]),
  // Benchmark the verifier itself: lift the INV-M4 wall / flush triggers.
  creditToleranceMicro: 1_000_000_000_000n,
  flushThresholdMicro: 1_000_000_000_000n,
  // INV-M6 bucket wide enough for the whole sample window.
  rateLimit: { capacity: SAMPLES + 100, refillPerSecond: 10 },
});

// Warm-up outside the measured region (JIT + module init).
await accumulator.verifyPayment(envelope(await signVoucher(1_000n)));

const latenciesMs: number[] = [];
let cumulative = 1_000n;
for (let i = 0; i < SAMPLES; i++) {
  cumulative += 1_000n;
  const headers = envelope(await signVoucher(cumulative));
  const started = performance.now();
  const outcome = accumulator.verifyPayment(headers);
  const elapsed = performance.now() - started;
  if (!outcome.ok) {
    console.error(`verification #${i} failed: ${outcome.reason}`);
    process.exit(1);
  }
  latenciesMs.push(elapsed);
}

latenciesMs.sort((a, b) => a - b);
const percentile = (p: number): number => latenciesMs[Math.min(latenciesMs.length - 1, Math.ceil((p / 100) * latenciesMs.length) - 1)]!;
const mean = latenciesMs.reduce((sum, v) => sum + v, 0) / latenciesMs.length;

console.log(`samples=${SAMPLES} mean=${mean.toFixed(3)}ms p50=${percentile(50).toFixed(3)}ms p95=${percentile(95).toFixed(3)}ms p99=${percentile(99).toFixed(3)}ms max=${latenciesMs[latenciesMs.length - 1]!.toFixed(3)}ms`);

const p99 = percentile(99);
if (p99 > BUDGET_MS) {
  const message = `p99 ${p99.toFixed(3)}ms exceeds the ${BUDGET_MS}ms INV-M1 budget (host-dependent: ecrecover dominates)`;
  if (ENFORCE) {
    console.error(`FAIL: ${message}`);
    process.exit(1);
  }
  console.warn(`ADVISORY: ${message} — rerun with --enforce on release hardware`);
} else {
  console.log(`PASS: p99 ${p99.toFixed(3)}ms within the ${BUDGET_MS}ms INV-M1 budget`);
}

async function signVoucher(amountMicro: bigint) {
  const signed = await signer.recordAndSign(TEST_MERCHANT, amountMicro, "0x" + "11".repeat(32));
  if (!signed.ok) throw new Error(`signing failed: ${signed.error.detail}`);
  return signed;
}

function envelope(signed: { voucher: unknown; signature: string }): Record<string, string> {
  return {
    [PAYMENT_SIGNATURE_HEADER]: JSON.stringify({
      voucher: serializeVoucher(signed.voucher as never),
      signature: signed.signature,
    }),
  };
}
