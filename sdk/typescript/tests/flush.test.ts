import { describe, expect, it } from "vitest";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { VoucherAccumulator, type FlushPlan } from "../src/middleware/merchant.js";
import {
  FlushDaemon,
  JsonReceiptStore,
  MemoryReceiptStore,
  type VaultSubmitter,
} from "../src/middleware/flushDaemon.js";
import { AR_NATIVE_USDC, TEST_MERCHANT, TEST_VAULT, TESTNET, ephemeralPrivateKey } from "./helpers.js";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const MEMO = `0x${"ab".repeat(32)}`;

class CapturingSubmitter implements VaultSubmitter {
  calls: Array<{ cumulative: string; signature: string }> = [];
  failWith: string | undefined;

  async claim(voucher: { cumulativeAmount: bigint }, signature: string) {
    if (this.failWith) throw new Error(this.failWith);
    this.calls.push({ cumulative: voucher.cumulativeAmount.toString(), signature });
    return { kind: "submitted" as const, txHash: `0xdead${this.calls.length}` };
  }
}

class RecordingHandler {
  plans: FlushPlan[] = [];
  readonly onFlushReady = (plan: FlushPlan): Promise<void> => {
    this.plans.push(plan);
    return Promise.resolve();
  };
}

function makeSigner(): AgentVoucherSigner {
  return new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
  });
}

function makeAccumulator(signer: AgentVoucherSigner, handler?: RecordingHandler): VoucherAccumulator {
  return new VoucherAccumulator({
    network: TESTNET,
    vaultAddress: TEST_VAULT,
    settlementToken: AR_NATIVE_USDC,
    authorizedAgents: new Set([signer.agentKey.toLowerCase()]),
    flushThresholdMicro: 400n,
    onFlushReady: handler?.onFlushReady,
  });
}

describe("VoucherAccumulator — settled-state bookkeeping", () => {
  it("verifies, accumulates, and retains the highest-voucher signature", async () => {
    const signer = makeSigner();
    const acc = makeAccumulator(signer);
    const a = await signer.recordAndSign(TEST_MERCHANT, 100n, MEMO);
    const b = await signer.recordAndSign(TEST_MERCHANT, 50n, MEMO);
    const ok1 = acc.verifyPayment(a.headers);
    expect(ok1.ok).toBe(true);
    expect(acc.highest(signer.agentKey)?.cumulativeAmount).toBe(100n);
    const ok2 = acc.verifyPayment(b.headers);
    expect(ok2.ok).toBe(true);
    expect(acc.highest(signer.agentKey)?.cumulativeAmount).toBe(150n);
    expect(acc.highestSignature(signer.agentKey)).toBe(b.signature);
    expect(acc.unsettledFor(signer.agentKey)).toBe(150n);
  });

  it("credit wall measures UNSETTLED exposure and resets after markSettled", async () => {
    const signer = makeSigner();
    const acc = new VoucherAccumulator({
      network: TESTNET,
      vaultAddress: TEST_VAULT,
      settlementToken: AR_NATIVE_USDC,
      authorizedAgents: new Set([signer.agentKey.toLowerCase()]),
      creditToleranceMicro: 1_000n,
    });
    const first = await signer.recordAndSign(TEST_MERCHANT, 100n, MEMO);
    acc.verifyPayment(first.headers);
    const wall = await signer.recordAndSign(TEST_MERCHANT, 2_000n, MEMO);
    const rejected = acc.verifyPayment(wall.headers);
    expect(rejected.ok).toBe(false);
    expect(rejected.reason).toMatch(/INV-M4/);
    acc.markSettled(signer.agentKey, 100n);
    // cumulative 2100 − settled 100 = 2000 unsettled ⇒ still halted
    const still = await signer.recordAndSign(TEST_MERCHANT, 1n, MEMO);
    expect(acc.verifyPayment(still.headers).ok).toBe(false);
    acc.markSettled(signer.agentKey, 2_100n);
    const resumed = await signer.recordAndSign(TEST_MERCHANT, 1n, MEMO);
    const outcome = acc.verifyPayment(resumed.headers);
    expect(outcome.ok).toBe(true);
    expect(outcome.unsettledMicro).toBe(2n);
  });

  it("flush trigger fires on unsettled ≥ threshold with signature attached", async () => {
    const signer = makeSigner();
    const handler = new RecordingHandler();
    const acc = makeAccumulator(signer, handler);
    await signer.recordAndSign(TEST_MERCHANT, 350n, MEMO);
    const small = await signer.recordAndSign(TEST_MERCHANT, 10n, MEMO);
    acc.verifyPayment(small.headers);
    expect(handler.plans.length).toBe(0); // unsettled 360 < 400
    acc.markSettled(signer.agentKey, 0n);
    const big = await signer.recordAndSign(TEST_MERCHANT, 100n, MEMO);
    acc.verifyPayment(big.headers); // unsettled 460 ≥ 400
    expect(handler.plans.length).toBe(1);
    expect(handler.plans[0].voucher.cumulativeAmount).toBe(460n);
    expect(handler.plans[0].signature).toBe(big.signature);
    expect(handler.plans[0].agentKey.toLowerCase()).toBe(signer.agentKey.toLowerCase());
  });
});

describe("FlushDaemon", () => {
  it("settles the highest voucher and persists receipt after confirmation", async () => {
    const signer = makeSigner();
    const submitter = new CapturingSubmitter();
    const store = new MemoryReceiptStore();
    const daemon = new FlushDaemon({ submitter, receipts: store });
    const acc = makeAccumulator(signer);

    const voucher = { agentKey: signer.agentKey, merchant: TEST_MERCHANT, token: AR_NATIVE_USDC, cumulativeAmount: 500n, validUntil: 9_000_000_000n, memo: `0x${"0".repeat(64)}` };
    await daemon.settle({ agentKey: signer.agentKey, merchant: TEST_MERCHANT, voucher, signature: "0xfeed" }, acc);

    expect(submitter.calls.length).toBe(1);
    expect(submitter.calls[0]).toEqual({ cumulative: "500", signature: "0xfeed" });
    const receipts = await store.load();
    const receipt = receipts.get(`${signer.agentKey.toLowerCase()}:${TEST_MERCHANT.toLowerCase()}`);
    expect(receipt?.txHash).toBe("0xdead1");
    expect(receipt?.cumulativeAmount).toBe("500");
    expect(receipt?.alreadySettled).toBe(false);
    expect(acc.unsettledFor(signer.agentKey)).toBe(0n); // markSettled applied
  });

  it("is idempotent: same cumulative never submitted twice (INV-M3)", async () => {
    const signer = makeSigner();
    const submitter = new CapturingSubmitter();
    const store = new MemoryReceiptStore();
    const daemon = new FlushDaemon({ submitter, receipts: store });
    const voucher = { agentKey: signer.agentKey, merchant: TEST_MERCHANT, token: AR_NATIVE_USDC, cumulativeAmount: 500n, validUntil: 9_000_000_000n, memo: `0x${"0".repeat(64)}` };
    const plan = { agentKey: signer.agentKey, merchant: TEST_MERCHANT, voucher, signature: "0xfeed" };
    await daemon.settle(plan);
    await daemon.settle(plan); // duplicate trigger
    expect(submitter.calls.length).toBe(1);
  });

  it("records already-settled receipts when the vault rejects as stale", async () => {
    const signer = makeSigner();
    const submitter = new CapturingSubmitter();
    submitter.failWith = "execution reverted: InvalidVoucherAmount";
    const store = new MemoryReceiptStore();
    const daemon = new FlushDaemon({ submitter, receipts: store });
    const voucher = { agentKey: signer.agentKey, merchant: TEST_MERCHANT, token: AR_NATIVE_USDC, cumulativeAmount: 500n, validUntil: 9_000_000_000n, memo: `0x${"0".repeat(64)}` };
    await daemon.settle({ agentKey: signer.agentKey, merchant: TEST_MERCHANT, voucher, signature: "0xfeed" });
    const receipt = (await store.load()).get(`${signer.agentKey.toLowerCase()}:${TEST_MERCHANT.toLowerCase()}`);
    expect(receipt?.alreadySettled).toBe(true);
    expect(receipt?.txHash).toBeNull();
    // and a resubmission attempt is now skipped
    submitter.failWith = undefined;
    const submitter2 = submitter;
    const daemon2 = new FlushDaemon({ submitter: submitter2, receipts: store });
    await daemon2.settle({ agentKey: signer.agentKey, merchant: TEST_MERCHANT, voucher, signature: "0xfeed" });
    expect(submitter2.calls.length).toBe(0);
  });

  it("JsonReceiptStore round-trips through disk atomically", async () => {
    const dir = await mkdtemp(join(tmpdir(), "paythos-flush-"));
    try {
      const path = join(dir, "receipts.json");
      const store = new JsonReceiptStore(path);
      await store.save({ agentKey: "0xaA", merchant: "0xbB", cumulativeAmount: "700", txHash: "0x1", settledAt: 1, alreadySettled: false });
      const reopened = new JsonReceiptStore(path);
      const loaded = await reopened.load();
      expect(loaded.get("0xaa:0xbb")?.cumulativeAmount).toBe("700");
      const doc = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
      expect(Object.keys(doc)).toEqual(["0xaa:0xbb"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
