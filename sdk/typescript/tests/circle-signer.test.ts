import { describe, expect, it } from "vitest";
import { Wallet, verifyTypedData, type TypedDataDomain } from "ethers";
import { createCircleWalletVoucherSigner, type CircleWalletClientLike } from "../src/signer/circleWalletSigner.js";
import { VOUCHER_TYPES, domainFor } from "../src/signer/voucherSigner.js";
import { parseUsdToMicro } from "../src/types.js";
import { TEST_MERCHANT, TEST_VAULT, TESTNET } from "./helpers.js";

interface CapturedPayload {
  types: Record<string, Array<{ name: string; type: string }>>;
  primaryType: string;
  domain: TypedDataDomain;
  message: Record<string, string>;
}

function circleClient(wallet: Wallet): { client: CircleWalletClientLike; calls: CapturedPayload[] } {
  const calls: CapturedPayload[] = [];
  const client: CircleWalletClientLike = {
    async signTypedData(input) {
      const payload = JSON.parse(input.data) as CapturedPayload;
      calls.push(payload);
      const types = { ...payload.types };
      delete types.EIP712Domain;
      const signature = await wallet.signTypedData(payload.domain, types, payload.message);
      return { data: { signature } };
    },
  };
  return { client, calls };
}

describe("Circle developer-controlled wallet signer", () => {
  it("produces an EIP-712 payload the vault accepts and recovers to the Circle wallet", async () => {
    const wallet = Wallet.createRandom();
    const { client, calls } = circleClient(wallet);
    const signer = createCircleWalletVoucherSigner({
      client,
      walletId: "wallet-id-1",
      walletAddress: wallet.address,
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 7,
    });

    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.04"), "0x" + "aa".repeat(32));
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;

    expect(signer.agentKey).toBe(wallet.address);
    expect(calls).toHaveLength(1);
    const payload = calls[0]!;
    expect(payload.primaryType).toBe("Voucher");
    expect(payload.types.EIP712Domain).toEqual([
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ]);
    expect(payload.domain).toEqual(domainFor({ network: TESTNET, vaultAddress: TEST_VAULT }));
    expect(payload.message).toMatchObject({
      agentKey: wallet.address,
      merchant: TEST_MERCHANT,
      cumulativeAmount: "40000",
      epoch: 7,
    });

    expect(
      verifyTypedData(
        payload.domain,
        VOUCHER_TYPES,
        {
          agentKey: signed.voucher.agentKey,
          merchant: signed.voucher.merchant,
          token: signed.voucher.token,
          cumulativeAmount: signed.voucher.cumulativeAmount,
          validUntil: signed.voucher.validUntil,
          epoch: signed.voucher.epoch,
          memo: signed.voucher.memo,
        },
        signed.signature,
      ),
    ).toBe(wallet.address);
  });

  it("keeps cumulative session totals monotonic across Circle signatures", async () => {
    const wallet = Wallet.createRandom();
    const { client, calls } = circleClient(wallet);
    const signer = createCircleWalletVoucherSigner({
      client,
      walletId: "wallet-id-2",
      walletAddress: wallet.address,
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });

    await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.04"), "0x" + "bb".repeat(32));
    await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.06"), "0x" + "cc".repeat(32));

    expect(calls.map((call) => call.message.cumulativeAmount)).toEqual(["40000", "100000"]);
    expect(signer.ledgerSnapshot()[0]?.cumulativeAmount).toBe(parseUsdToMicro("0.10"));
  });

  it("fails closed and leaves the ledger untouched when Circle returns no signature", async () => {
    const wallet = Wallet.createRandom();
    const client: CircleWalletClientLike = {
      async signTypedData() {
        return { data: {} };
      },
    };
    const signer = createCircleWalletVoucherSigner({
      client,
      walletId: "wallet-id-3",
      walletAddress: wallet.address,
      domain: { network: TESTNET, vaultAddress: TEST_VAULT },
      epoch: 1,
    });

    const signed = await signer.recordAndSign(TEST_MERCHANT, parseUsdToMicro("0.01"), "0x" + "dd".repeat(32));
    expect(signed.ok).toBe(false);
    if (signed.ok) return;
    expect(signed.error.code).toBe("policy_ambiguous");
    expect(signed.error.detail).toContain("Circle signTypedData returned no signature");
    expect(signer.ledgerSnapshot()).toHaveLength(0);
  });
});
