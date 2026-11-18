# Paythos Protocol

**Enterprise spend-control and governance layer for AI agents transacting in USDC on Arc L1.** Cross-chain stablecoin funding arrives via Circle CCTP (burn-and-mint through Circle's rails), so other chains' USDC can fund a Paythos vault without Paythos ever operating a bridge.

Paythos sits between an AI agent and its money. It converts raw agent wallets into policy-enforced **Paythos Vaults**: non-custodial capital with on-chain daily ceilings, per-transaction bounds, session expiry, three-tier human approval gates, and a signed record of the agent's intent for every payment. A dedicated Circle Agent Wallets approval/audit adapter is on the stage 5 integration list (the vault/SDK layer is wallet-agnostic today).

Where Circle's Agent Stack (agents.circle.com) provides the rails (the marketplace, the currency, the nanopayments), Paythos provides the buy-side defense layer: pre-spend simulation, counterparty scoring, monotonic state-channel settlement, and enterprise policy enforcement.

## Status

**Build stages 1 to 4 complete; stage 5 (deployment and release) is in progress (Arc Testnet live and source-verified; mainnet, CCTP funding, public release, and grant package pending).** The protocol spec suite lives in `docs/` and is internal. It is intentionally not distributed in this repo. Implementation follows the staged sequence in `docs/ROADMAP.md`.

| Stage | Scope | State |
| --- | --- | --- |
| 1 | `PaythosVault.sol` + invariant fuzz suite | complete: 38 Foundry tests green |
| 2 | Voucher channel, merchant middleware, throttling, verify benchmark | complete: TS 156 · Python 121 |
| 3 | GOFER policy engine (spend authorization), dryRun, 3-tier approval, verifiable intent, metered `upto` streaming (YOPO), Transactability Index, Circle Discovery firewall, Circle marketplace x402 v2 buyer | complete |
| 4 | LangChain / ElizaOS / AutoGen adapters, stdio MCP server, one-block install | complete |
| 5 | Arc deployment + Circle CCTP funding + SDK release + grant package | in progress: Arc Testnet vault deployed and source-verified; mainnet, CCTP, SDK release, grant pending |

Live evidence on Arc Testnet (PROTOCOL v3, epoch-bound vouchers): vault
`0xD69eA0ab9671549095D473E5176579ee879373Ce` (deploy tx `0x69e20da8…a7895`;
source verified on Blockscout: `https://explorer.testnet.arc.io/address/0xD69eA0ab9671549095D473E5176579ee879373Ce#code`);
epoch-synced `claimVoucher` tx `0xa874d4f291be7a1eb2210e9c7ebda4f765e2f3bab8998095af7d17e597876c69`
(block 71523116, 150 bps fee, replay rejected), plus the live INV-6 proof: re-authorization
bumped epoch 1→2, a stale-epoch voucher reverted `SessionEpochMismatch`, and the
live-epoch claim settled. Funded MCP+SDK smoke (`npm run e2e:mcp-live`) settled two
cumulative vouchers (0.04 + 0.06 USDC) through the MCP `settle_invoice` tool against
distinct merchant payee `0x9eee8683…4752875`; `claimVoucher()` tx
`0x99a1c655…e536d668` (block 72233956, 150 bps fee) paid the merchant net 0.0985 USDC
with the balance delta asserted. Circle developer-controlled wallet smoke
(`npm run e2e:circle-live`): ARC-TESTNET EOA `0x1D5C44CC…f2f060` signed the same
0.04 + 0.06 cumulative vouchers via Circle `signTypedData`; `claimVoucher()` tx
`0x6d18c951…9342eb` (block 72238450, 150 bps fee) paid net 0.0985 USDC, with the
Circle wallet holding zero USDC. A live marketplace probe against
`https://api.botpay.network/go` decoded the standard x402 v2 envelope, selected the
`eip155:5042002` USDC accept, and produced a `GatewayWalletBatched` authorization
(no payment sent); the matching buyer path is covered by
`sdk/typescript/tests/circle-marketplace.test.ts`.

## Architecture at a glance

1. **Vault (on-chain):** custody, policy enforcement, batch settlement. Cumulative EIP-712 vouchers; `claimVoucher()` enforces `delta > 0`, `delta <= maxPerTx`, and `spentToday + delta <= dailyLimit` over a 25-slot rolling window. Re-authorization bumps the delegation epoch, so stale vouchers never settle (INV-6).
2. **Agent SDK (TS + Python):** GOFER policy engine (spend authorization), `dryRun()` pre-flight, EIP-712 signing with cumulative ledgers, x402 v2 negotiation, metered `upto` streaming (YOPO), Transactability Index, Circle Discovery union firewall.
3. **Merchant middleware (Express / FastAPI):** challenge emission, in-memory voucher verification (INV-M1), highest-voucher accumulator, per-agent token-bucket throttling (INV-M6), credit wall (INV-M4), flush daemon with idempotent receipts (INV-M3).
4. **Agent surfaces:** MCP stdio server and LangChain / ElizaOS / AutoGen / CrewAI adapters.

INV-1 through INV-6 are the on-chain vault invariants. INV-M1 through INV-M6 are merchant-side checks enforced by the middleware. YOPO means "You Only Pay Outcome": no voucher is signed for output that was not delivered.

## Repository layout

```text
contracts/            Solidity (Foundry, OZ v5): vault, policy, fee routing, invariants
sdk/typescript/       TS SDK: client, signer, middleware, adapters, MCP server, ops scripts
sdk/python/           Python SDK: pydantic mirrors, FastAPI middleware, adapters
mcp-server/           One-block MCP install config for Claude Desktop / Cursor
site/                 Grant-level static website (no build step, no trackers)
SECURITY.md           Public invariants, threat model, disclosure policy
.github/workflows/    CI: Foundry (10k invariants), TS, Python
docs/                 Internal protocol spec (not distributed)
```

## Quickstart

### Tests

```bash
cd contracts && forge test                    # 38 tests
cd sdk/typescript && npm ci && npm test       # 156 tests
cd sdk/python && uv venv && uv pip install -e ".[dev]" && pytest   # 121 tests
```

TypeScript is strict (`exactOptionalPropertyTypes`, no `any` in exported APIs); Python mirrors the TS types 1:1 with pydantic.

### Grant website

The grant-level site is static and dependency-free:

```bash
python3 -m http.server 8099 --directory site
# http://localhost:8099
```

Copy is grounded in the live deployment and test evidence above; update the
`Proof` and deployment sections when those facts change.

### Agent pays an x402 resource (TypeScript)

```ts
import { AgentVoucherSigner, PaythosClient } from "@paythos/sdk";

const signer = new AgentVoucherSigner({
  privateKey: process.env.PAYTHOS_EPHEMERAL_KEY!,
  domain: { network: "eip155:5042002", vaultAddress: process.env.PAYTHOS_VAULT_ADDRESS! },
  epoch: 1,
});
const client = new PaythosClient(signer, {
  signer,
  network: "eip155:5042002",
  allowlist: new Set([process.env.PAYTHOS_MERCHANT!]),
});

const result = await client.fetchWithX402({ url: "https://api.example.com/premium", prompt });
// result.ok ? result.data : result.error.code / detail
```

Metered streaming (`scheme: "upto"`) uses `client.streamWithX402(...)`: the client holds only the ceiling, sends a client-chosen `X-PAYTHOS-STREAM` nonce on stream open, signs an **exact-consumption** voucher at completion, and signs nothing when the stream fails (INV-M5). The merchant must echo that nonce in a signed terminal frame:

```ts
import { attestStream } from "@paythos/sdk";

const attestation = await attestStream(merchantWallet, req.headers, consumedUsd);
res.end(attestation.body); // last stream frame; a different streamId is rejected as replay
```

Python parity: `attestation = attest_stream(merchant_account, request.headers, consumed_usd)`.

Client safety rails: `approvalTimeoutMs` (default 120s), `streamOpenTimeoutMs` (default 30s), and `holdTtlMs` (default 10min). Expired approval/stream-open deadlines release the hold; the TTL sweep prevents abandoned streams from pinning budget.

### Merchant gating (Express)

```ts
import { paythosMerchant } from "@paythos/sdk";

app.use(paythosMerchant({
  network: "eip155:5042002",
  vaultAddress: process.env.PAYTHOS_VAULT_ADDRESS!,
  settlementToken: "0x3600000000000000000000000000000000000000",
  merchantAddress: process.env.PAYTHOS_MERCHANT_ADDRESS!, // payee binding (fail closed)
  authorizedAgents: new Map([[agentKey, epoch]]),
  challengeFor: ({ url }) => ({ x402Version: 2, scheme: "exact", network, asset, payTo, max, resource: url }),
}));
```

Every mount gates: no payment headers gets a 402 challenge when `challengeFor` is set, and a 402 `payment_required` rejection when it is omitted (no pass-through).

**Behind a proxy**, set `app.set("trust proxy", 1)` (or the exact hop/subnet) so `req.ip` is the real client rather than Cloudflare/Render/Vercel. Otherwise every agent shares one per-IP bucket. FastAPI/uvicorn needs `--proxy-headers --forwarded-allow-ips=<proxy>`. The adapters warn once at runtime when they see a private/loopback client identity.

### MCP server

Copy the block in [`mcp-server/paythos.mcp.json`](mcp-server/paythos.mcp.json) into Claude Desktop / Cursor and set env vars only. No config code is needed. Tools: `get_agent_budget`, `dry_run_errand`, `settle_invoice`, `query_x402_resource`. Run locally with `cd sdk/typescript && npm run mcp`.

For a real funded Arc Testnet proof, run `npm run e2e:mcp-live` from `sdk/typescript` after setting `PAYTHOS_DEPLOYER_KEY`, an existing v3 `PAYTHOS_VAULT_ADDRESS`, and the actual merchant payee in `PAYTHOS_MERCHANT_ADDRESS`. The harness authorizes a fresh agent, boots the MCP server over stdio, reads the live on-chain budget, signs two cumulative vouchers against that merchant's `payTo`, settles them through `claimVoucher()`, and asserts `claimed()`, epoch, fee split, and the merchant's USDC balance delta. Keys come from `.env`/the environment only; the ephemeral key may be omitted and is generated per run.

To keep the agent key out of process memory, use `npm run e2e:circle-live` with `CIRCLE_API_KEY` and `CIRCLE_ENTITY_SECRET` set. It resolves (or creates) an `ARC-TESTNET` EOA in Circle Developer-Controlled Wallets, authorizes that address on the vault, asks Circle `signTypedData` for the EIP-712 vouchers, verifies the signature recovers to the Circle wallet, and settles on-chain. The Circle wallet holds no USDC, so signing and custody of funds stay separate. `createCircleWalletVoucherSigner()` is the reusable SDK entry point.

### Circle Agent Marketplace (standard x402 v2)

Marketplace services use the standard wire format (`PAYMENT-REQUIRED: base64({ x402Version, resource, accepts[], error, extensions })`), not the Paythos voucher envelope. `client.fetchWithCircleMarketplace()` bridges them: it selects only Arc Testnet USDC accepts, signs Circle Gateway batched authorizations (`GatewayWalletBatched`) or falls back to exact EIP-3009, and runs the same allowlist/tier/human-approval gate before any signature exists. These payments settle through Circle's rail, **not** `PaythosVault`; direct spend is tracked against the same client-side budget and the boundary is explicit (AGENTS.md rule 4). `PaythosClient.fetchWithX402()` remains the vault-settled merchant path. `npm run probe:marketplace` fetches a live service and signs locally **without settling**, which is useful for compatibility checks that must not move USDC.

## Chain constants

| Network | CAIP-2 | Chain ID | USDC |
| --- | --- | --- | --- |
| Arc Testnet | `eip155:5042002` | 5042002 | `0x3600000000000000000000000000000000000000` (native precompile) |
| Arc Mainnet | `arc:mainnet` | 5042 | unverified → SDK stays fail-closed (PROTOCOL-OPEN-Q1) |

RPC testnet: `https://rpc.testnet.arc.io` · explorer: `https://explorer.testnet.arc.io` / `https://testnet.arcscan.app`.

## Security model (summary)

- **Non-custodial:** owner keeps emergency withdrawal; no pooled liquidity, no yield, no rehypothecation.
- **Fail closed:** policy ambiguity halts; there is no default-allow path.
- **Deltas enforced on-chain:** never trust the client for ceilings, monotonicity, expiry, or epoch.
- **YOPO (You Only Pay Outcome):** no voucher for unrendered tokens or failed streams; every failure releases the hold.
- **Secrets hygiene:** ephemeral keys come only from environment variables and are never logged or committed.

Rebuild the verification baseline with `npm run bench:verify -- 2000 --enforce` on release hardware (the harness measures the in-memory verify path; p99 is ecrecover-bound).

## Prior work

The original demo repository (`github.com/Web3Manuel001/paythos`) validated the EIP-712 voucher flow end-to-end on Arc Testnet (vault `0xa9d5525BE440831c64695d30c915DF303E0151EF`, native USDC at `0x3600...0000`). This repository is a **fresh build** targeting the v3 spec; the demo is reference-only and is not migrated wholesale.
