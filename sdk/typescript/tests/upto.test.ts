/**
 * YOPO / `upto` streaming suite (docs/PROTOCOL.md §4.2, SECURITY.md INV-M5).
 * Core property: a voucher exists ONLY for attested, rendered consumption —
 * every failure path releases the hold and signs NOTHING.
 */
import { describe, expect, it, vi } from "vitest";
import { Wallet } from "ethers";
import { AgentVoucherSigner } from "../src/signer/voucherSigner.js";
import { PaythosClient, StreamHooks, StreamedResult } from "../src/client/paythosClient.js";
import { HoldLedger } from "../src/client/holdLedger.js";
import { MeteringReport, recoverMeteringSigner, signMeteringReport, meteringCanonical } from "../src/client/metering.js";
import { PaymentChallenge, formatMicroUsd } from "../src/types.js";
import { TEST_VAULT, TESTNET, AR_NATIVE_USDC, ephemeralPrivateKey } from "./helpers.js";

/** Server wallet whose key IS the challenge payTo destination. */
const merchantWallet = new Wallet(ephemeralPrivateKey());
const MERCHANT = merchantWallet.address.toLowerCase();

function uptoChallenge(max: string): PaymentChallenge {
  return {
    x402Version: 2,
    scheme: "upto",
    network: TESTNET,
    asset: AR_NATIVE_USDC,
    payTo: MERCHANT,
    max,
    resource: "https://m.example.com/stream",
  };
}

function challengeResponse(challenge: PaymentChallenge): Response {
  return new Response("payment required", {
    status: 402,
    headers: {
      "payment-required": Buffer.from(JSON.stringify(challenge), "utf8").toString("base64"),
    },
  });
}

function headerOf(init: RequestInit | undefined, name: string): string | null {
  const headers = init?.headers as Headers | Record<string, string> | undefined;
  if (headers instanceof Headers) return headers.get(name);
  return headers?.[name] ?? null;
}

function isCompletionCall(init?: RequestInit): boolean {
  return init?.method === "POST" && headerOf(init, "x-paythos-stream") !== null;
}

interface Fixtures {
  client: PaythosClient;
  signer: AgentVoucherSigner;
  /** Scripted responses consumed in order; falls back to failing the test. */
  queue: Array<() => Response | Promise<Response>>;
  completions: Array<{ headers: Record<string, string>; body: string }>;
}

function makeClient(opts: Partial<ConstructorParameters<typeof PaythosClient>[1]> = {}): Fixtures {
  const signer = new AgentVoucherSigner({
    privateKey: ephemeralPrivateKey(),
    domain: { network: TESTNET, vaultAddress: TEST_VAULT },
    epoch: 1,
  });
  const queue: Fixtures["queue"] = [];
  const completions: Fixtures["completions"] = [];
  const fetchFn = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    if (isCompletionCall(init)) {
      completions.push({
        headers: Object.fromEntries((init!.headers as Headers).entries()),
        body: String(init!.body ?? ""),
      });
      return new Response(JSON.stringify({ settled: true }), { status: 200 });
    }
    const next = queue.shift();
    if (!next) throw new Error(`unexpected fetch #${fetchFn.mock.calls.length} — queue empty`);
    return await next();
  }) as unknown as typeof fetch;
  const client = new PaythosClient(signer, {
    signer,
    network: TESTNET,
    allowlist: new Set([MERCHANT]),
    fetch: fetchFn,
    ...opts,
  });
  vi.mocked(fetchFn).mock.calls;
  return { client, signer, queue, completions };
}

function enqueueChallenge(fix: Fixtures, challenge: PaymentChallenge): void {
  fix.queue.push(() => challengeResponse(challenge));
}

function enqueueStream(fix: Fixtures, body: string | ReadableStream<Uint8Array>): void {
  fix.queue.push(() => new Response(body, { status: 200 }));
}

async function runStream(fix: Fixtures, attempt: { url?: string; prompt?: string } = {}, hooks: StreamHooks = {}): Promise<StreamedResult> {
  return fix.client.streamWithX402(
    { url: attempt.url ?? "https://m.example.com/stream", prompt: attempt.prompt ?? "yopo test" },
    hooks,
  );
}

function clientError(result: StreamedResult): { error: { code: string; detail: string }; holdState: string } {
  if (result.ok) throw new Error("expected failure, got success");
  return { error: result.error as unknown as { code: string; detail: string }, holdState: result.holdState };
}

/* ---------------- HoldLedger unit invariants ---------------- */

describe("HoldLedger — unit invariants", () => {
  it("lock/settle lifecycle: settled holds free the budget, exact accounting", () => {
    const ledger = new HoldLedger();
    const sid = HoldLedger.streamIdFor("https://x", "p", 1);
    ledger.lock(sid, MERCHANT, 10_000n);
    expect(ledger.activeHoldMicro(MERCHANT)).toBe(10_000n);
    expect(ledger.activeHoldMicro("0xother")).toBe(0n);
    ledger.settle(sid, 3_400n);
    const entry = ledger.get(sid)!;
    expect(entry.state).toBe("settled");
    expect(entry.settledMicro).toBe(3_400n);
    expect(ledger.activeHoldMicro(MERCHANT)).toBe(0n);
  });

  it("release is YOPO: released holds owe nothing and are idempotent", () => {
    const ledger = new HoldLedger();
    const sid = HoldLedger.streamIdFor("https://x", "p", 2);
    ledger.lock(sid, MERCHANT, 10_000n);
    ledger.release(sid);
    expect(ledger.get(sid)!.state).toBe("released");
    expect(ledger.activeHoldMicro()).toBe(0n);
    ledger.release(sid); // idempotent
    expect(ledger.get(sid)!.state).toBe("released");
  });

  it("refuses duplicate locks, double settles, unknown ids, non-positive ceilings", () => {
    const ledger = new HoldLedger();
    const sid = HoldLedger.streamIdFor("https://x", "p", 3);
    expect(() => ledger.lock(sid, MERCHANT, 0n)).toThrow(/positive/);
    ledger.lock(sid, MERCHANT, 5_000n);
    expect(() => ledger.lock(sid, MERCHANT, 5_000n)).toThrow(/already active/);
    expect(() => ledger.settle("0xunknown", 1n)).toThrow(/unknown hold/);
    ledger.settle(sid, 2_000n);
    expect(() => ledger.settle(sid, 2_000n)).toThrow(/already settled/);
  });

  it("streamIdFor is deterministic and distinct per input", () => {
    expect(HoldLedger.streamIdFor("a", "b", 1)).toBe(HoldLedger.streamIdFor("a", "b", 1));
    expect(HoldLedger.streamIdFor("a", "b", 1)).not.toBe(HoldLedger.streamIdFor("a", "b", 2));
  });
});

/* ---------------- Metering attestation ---------------- */

describe("Metering attestation", () => {
  it("sign → recover round-trips to the merchant address", async () => {
    const report = await signMeteringReport(merchantWallet, {
      scheme: "upto",
      units: "USD",
      streamId: "0xabc",
      consumed: "0.0034",
    });
    expect(recoverMeteringSigner(report)).toBe(MERCHANT);
  });

  it("canonical bytes are stable and tamper-evident", async () => {
    expect(meteringCanonical({ scheme: "upto", streamId: "s", consumed: "0.1", units: "USD" })).toBe("upto|s|0.1|USD");
    const report = await signMeteringReport(merchantWallet, {
      scheme: "upto",
      units: "USD",
      streamId: "s",
      consumed: "0.1",
    });
    expect(recoverMeteringSigner({ ...report, consumed: "9.9" })).not.toBe(MERCHANT);
  });

  it("rejects malformed reports with typed errors", async () => {
    expect(() =>
      recoverMeteringSigner({
        scheme: "exact" as never,
        units: "USD" as never,
        streamId: "s",
        consumed: "1",
        signature: "0x" + "11".repeat(65),
      }),
    ).toThrow(/must be/);
    expect(() =>
      recoverMeteringSigner({ scheme: "upto", units: "USD", streamId: "s", consumed: "1", signature: "not-a-sig" }),
    ).toThrow(/65-byte/);
  });
});

/* ---------------- streamWithX402 — YOPO lifecycle ---------------- */

describe("streamWithX402 — full YOPO lifecycle", () => {
  it("happy path: metered consumption settles the EXACT voucher at completion", async () => {
    const fix = makeClient();
    const attested = await signMeteringReport(merchantWallet, {
      scheme: "upto",
      units: "USD",
      streamId: "stream-1",
      consumed: "0.0034",
    });
    enqueueChallenge(fix, uptoChallenge("0.01"));
    const enc = new TextEncoder();
    const chunked = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(enc.encode("hello "));
        controller.enqueue(enc.encode("streamed "));
        controller.enqueue(enc.encode("world\n" + JSON.stringify(attested) + "\n"));
        controller.close();
      },
    });
    enqueueStream(fix, chunked);

    const observed: string[] = [];
    const result = await runStream(fix, {}, { onChunk: (_d, acc) => observed.push(acc) });

    if (!result.ok) throw new Error(`expected success: ${JSON.stringify(result.error)}`);
    expect(result.consumedMicro).toBe(3400n);
    expect(result.consumedUsd).toBe(formatMicroUsd(3400n));
    expect(result.voucher.cumulativeAmount).toBe(3400n); // EXACT consumption, not the $0.01 ceiling
    expect(fix.signer.ledgerSnapshot()[0]!.cumulativeAmount).toBe(3400n);
    expect((result.data as string).includes("world")).toBe(true);
    expect(observed.slice(0, 2)).toEqual(["hello ", "hello streamed "]);
    expect(observed[2]!.startsWith("hello streamed world\n")).toBe(true);
    expect(observed[2]).toContain('"consumed":"0.0034"');
    expect(fix.client.holds.get(result.streamId!)!.state).toBe("settled");
    // completion call carried the settlement envelope + stream marker
    expect(fix.completions).toHaveLength(1);
    const completion = fix.completions[0]!;
    const envelope = JSON.parse(completion.headers["payment-signature"]) as {
      voucher: { cumulativeAmount: string };
    };
    expect(envelope.voucher.cumulativeAmount).toBe("3400");
    expect(completion.headers["x-paythos-stream"]).toBe(result.streamId);
    expect(JSON.parse(completion.body)["streamId"]).toBe(result.streamId);
  });

  it("mid-stream break releases the hold and signs NOTHING (INV-M5)", async () => {
    const fix = makeClient();
    enqueueChallenge(fix, uptoChallenge("0.01"));
    const breaking = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("partial "));
        setTimeout(() => controller.error(new Error("socket reset")), 5);
      },
    });
    enqueueStream(fix, breaking);

    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.code).toBe("network_error");
    expect(failure.holdState).toBe("released");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0); // no voucher for unrendered tokens
    expect(fix.client.holds.activeHoldMicro()).toBe(0n);
    expect(fix.completions).toHaveLength(0); // completion call never fired
  });

  it("stream closing WITHOUT a metering frame is released unpaid", async () => {
    const fix = makeClient();
    enqueueChallenge(fix, uptoChallenge("0.01"));
    enqueueStream(fix, "payload with no metering trailer\n");
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.code).toBe("policy_ambiguous");
    expect(failure.holdState).toBe("released");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0);
  });

  it("attestation signed by anyone other than payTo is refused + hold released", async () => {
    const fix = makeClient();
    const intruder = new Wallet(ephemeralPrivateKey());
    const report = await signMeteringReport(intruder, {
      scheme: "upto",
      units: "USD",
      streamId: "s",
      consumed: "0.009",
    });
    enqueueChallenge(fix, uptoChallenge("0.01"));
    enqueueStream(fix, JSON.stringify(report) + "\n");
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.code).toBe("policy_ambiguous");
    expect(failure.error.detail).toMatch(/payTo/);
    expect(failure.holdState).toBe("released");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0);
  });

  it("metered consumption ABOVE the ceiling is refused + hold released (never overpays)", async () => {
    const fix = makeClient();
    const report = await signMeteringReport(merchantWallet, {
      scheme: "upto",
      units: "USD",
      streamId: "s",
      consumed: "0.02",
    });
    enqueueChallenge(fix, uptoChallenge("0.01"));
    enqueueStream(fix, JSON.stringify(report) + "\n");
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.code).toBe("policy_failure");
    expect(failure.error.detail).toMatch(/exceeds/);
    expect(failure.holdState).toBe("released");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0);
  });

  it("zero-consumed metering releases the hold unpaid (nothing owed)", async () => {
    const fix = makeClient();
    const report = await signMeteringReport(merchantWallet, {
      scheme: "upto",
      units: "USD",
      streamId: "s",
      consumed: "0",
    });
    enqueueChallenge(fix, uptoChallenge("0.01"));
    enqueueStream(fix, JSON.stringify(report) + "\n");
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.holdState).toBe("released");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0);
  });

  it("exact-scheme challenge streams route to fetchWithX402 (typed, pre-hold)", async () => {
    const fix = makeClient();
    enqueueChallenge(fix, { ...uptoChallenge("0.01"), scheme: "exact" });
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.detail).toMatch(/fetchWithX402/);
    expect(failure.holdState).toBe("unset");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0);
  });

  it("insufficient allowance for the hold is refused pre-lock (demand accounting)", async () => {
    const fix = makeClient({ allowanceMicro: 100_000n }); // $0.10
    enqueueChallenge(fix, uptoChallenge("0.40"));
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.detail).toMatch(/insufficient allowance/);
    expect(failure.holdState).toBe("unset");
  });

  it("ACTIVE holds consume the budget: a second stream past free balance is refused", async () => {
    const fix = makeClient({ allowanceMicro: 500_000n }); // $0.50
    // Stream A settles exactly $0.40.
    const reportA = await signMeteringReport(merchantWallet, {
      scheme: "upto",
      units: "USD",
      streamId: "sA",
      consumed: "0.40",
    });
    enqueueChallenge(fix, uptoChallenge("0.40"));
    enqueueStream(fix, JSON.stringify(reportA) + "\n");
    const a = await runStream(fix, { prompt: "session A" });
    expect(a.ok).toBe(true);
    expect(fix.client.holds.activeHoldMicro()).toBe(0n); // settled → budget freed

    // Active hold injected mid-session: budget shrinks to $0.10.
    const manual = HoldLedger.streamIdFor("manual", "m", 1);
    fix.client.holds.lock(manual, MERCHANT, 400_000n);
    enqueueChallenge(fix, uptoChallenge("0.20"));
    const c = await runStream(fix, { prompt: "session C" });
    const failure = clientError(c);
    expect(failure.error.detail).toMatch(/insufficient allowance/);
    expect(failure.holdState).toBe("unset"); // nothing was locked
  });

  it("tier-2 ceiling with no human approver fails closed BEFORE any stream or hold", async () => {
    const fix = makeClient(); // default $20 spec allowance covers the $5 ceiling
    enqueueChallenge(fix, uptoChallenge("5.00"));
    const result = await runStream(fix);
    const failure = clientError(result);
    expect(failure.error.code).toBe("human_approval_required");
    expect(failure.holdState).toBe("unset");
    expect(fix.signer.ledgerSnapshot()).toHaveLength(0);
    expect(fix.completions).toHaveLength(0);
  });
});
