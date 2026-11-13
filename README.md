# Paythos Protocol

**Enterprise spend-control and governance layer for AI agents transacting in USDC on Arc L1.** Cross-chain stablecoin funding arrives via Circle CCTP (burn-and-mint through Circle's rails), so other chains' USDC can fund a Paythos vault without Paythos ever operating a bridge.

Paythos sits between an AI agent and its money. It converts raw agent wallets into policy-enforced **Paythos Vaults**: non-custodial capital with on-chain daily ceilings, per-transaction bounds, session expiry, three-tier human approval gates, and a signed-every-thought verifiable-intent audit trail. A dedicated Circle Agent Wallets approval/audit adapter is on the Gate 5 integration list (the vault/SDK layer is wallet-agnostic today).

Where Circle's Agent Stack (agents.circle.com) provides the rails — the marketplace, the currency, the nanopayments — Paythos provides the buy-side defense layer: pre-spend simulation, counterparty scoring, monotonic state-channel settlement, and enterprise policy enforcement.

## Status

**Gates 1–4 complete; Gate 5 (Arc deployment, CCTP funding, public release, grant package) next.** The protocol spec suite lives in `docs/` and is internal — it is intentionally not distributed in this repo. Implementation follows the gated sequence in `docs/ROADMAP.md`.

| Gate | Scope | State |
| --- | --- | --- |
| 1 | `PaythosVault.sol` + invariant fuzz suite | complete — 36 Foundry tests green |
| 2 | Voucher channel, merchant middleware, INV-M6 throttling, verify benchmark | complete — TS 141 · Python 116 |
| 3 | GOFER policy engine, dryRun, 3-tier gate, verifiable intent, `upto`/YOPO (INV-M5), Transactability Index, Circle Discovery firewall | complete |
| 4 | LangChain / ElizaOS / AutoGen adapters, stdio MCP server, one-block install | complete |
| 5 | Arc deployment + Circle CCTP funding + SDK release + grant package | next (blocked on team treasury address and PROTOCOL-OPEN-Q1) |

Live evidence on Arc Testnet (PROTOCOL v3, epoch-bound vouchers): vault
`0xD69eA0ab9671549095D473E5176579ee879373Ce` (deploy tx `0x69e20da8…a7895`);
epoch-synced `claimVoucher` tx `0xa874d4f291be7a1eb2210e9c7ebda4f765e2f3bab8998095af7d17e597876c69`
(block 71523116, 150 bps fee, replay rejected), plus the live INV-6 proof: re-authorization
bumped epoch 1→2, a stale-epoch voucher reverted `SessionEpochMismatch`, and the
live-epoch claim settled.

## Architecture at a glance

1. **Vault (on-chain)** — custody, policy enforcement, batch settlement. Cumulative EIP-712 vouchers; `claimVoucher()` enforces `delta > 0`, `delta <= maxPerTx`, and `spentToday + delta <= dailyLimit` over a 25-slot rolling window. Re-authorization bumps the delegation epoch, so stale vouchers never settle (INV-6).
2. **Agent SDK (TS + Python)** — GOFER policy engine, `dryRun()` pre-flight, EIP-712 signing with cumulative ledgers, x402 v2 negotiation, `upto`/YOPO metered streaming, Transactability Index, Circle Discovery union firewall.
3. **Merchant middleware (Express / FastAPI)** — challenge emission, in-memory voucher verification (INV-M1), highest-voucher accumulator, per-agent token-bucket throttling (INV-M6), credit wall (INV-M4), flush daemon with idempotent receipts (INV-M3).
4. **Agent surfaces** — MCP stdio server and LangChain / ElizaOS / AutoGen / CrewAI adapters.

## Repository layout

```text
contracts/            Solidity (Foundry, OZ v5): vault, policy, fee routing, invariants
sdk/typescript/       TS SDK: client, signer, middleware, adapters, MCP server, ops scripts
sdk/python/           Python SDK: pydantic mirrors, FastAPI middleware, adapters
mcp-server/           One-block MCP install config for Claude Desktop / Cursor
SECURITY.md           Public invariants, threat model, disclosure policy
.github/workflows/    CI: Foundry (10k invariants), TS, Python
docs/                 Internal protocol spec (not distributed)
```

## Quickstart

### Tests

```bash
cd contracts && forge test                    # 36 tests
cd sdk/typescript && npm ci && npm test       # 141 tests
cd sdk/python && uv venv && uv pip install -e ".[dev]" && pytest   # 116 tests
```

TypeScript is strict (`exactOptionalPropertyTypes`, no `any` in exported APIs); Python mirrors the TS types 1:1 with pydantic.

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

Copy the block in [`mcp-server/paythos.mcp.json`](mcp-server/paythos.mcp.json) into Claude Desktop / Cursor and set env vars only — no config code. Tools: `get_agent_budget`, `dry_run_errand`, `settle_invoice`, `query_x402_resource`. Run locally with `cd sdk/typescript && npm run mcp`.

## Chain constants

| Network | CAIP-2 | Chain ID | USDC |
| --- | --- | --- | --- |
| Arc Testnet | `eip155:5042002` | 5042002 | `0x3600000000000000000000000000000000000000` (native precompile) |
| Arc Mainnet | `arc:mainnet` | 5042 | unverified → SDK stays fail-closed (PROTOCOL-OPEN-Q1) |

RPC testnet: `https://rpc.testnet.arc.io` · explorer: `https://explorer.testnet.arc.io` / `https://testnet.arcscan.app`.

## Security model (summary)

- **Non-custodial** — owner keeps emergency withdrawal; no pooled liquidity, no yield, no rehypothecation.
- **Fail closed** — policy ambiguity halts; there is no default-allow path.
- **Deltas enforced on-chain** — never trust the client for ceilings, monotonicity, expiry, or epoch.
- **YOPO** — no voucher for unrendered tokens or failed streams; every failure releases the hold.
- **Secrets hygiene** — ephemeral keys come only from environment variables and are never logged or committed.

Rebuild the verification baseline with `npm run bench:verify -- 2000 --enforce` on release hardware (the harness measures the in-memory verify path; p99 is ecrecover-bound).

## Prior work

The original demo repository (`github.com/Web3Manuel001/paythos`) validated the EIP-712 voucher flow end-to-end on Arc Testnet (vault `0xa9d5525BE440831c64695d30c915DF303E0151EF`, native USDC at `0x3600...0000`). This repository is a **fresh build** targeting the v3 spec; the demo is reference-only and is not migrated wholesale.
