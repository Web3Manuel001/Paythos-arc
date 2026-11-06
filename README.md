# Paythos Protocol

**Enterprise spend-control and governance layer for AI agents transacting in USDC on Arc L1.** Cross-chain stablecoin funding arrives via Circle CCTP (burn-and-mint through Circle's rails), so USDC from other chains can fund a Paythos vault without Paythos ever operating a bridge.

Paythos sits between an AI agent and its money. It converts raw agent wallets (or Circle Agent Wallets) into policy-enforced **Paythos Vaults**: non-custodial capital with mathematically enforced daily ceilings, per-transaction bounds, session expiry, three-tier human approval gates, and a signed-every-thought verifiable-intent audit trail.

Where Circle's Agent Stack (agents.circle.com) provides the rails — the marketplace, the currency, the nanopayments — Paythos provides the missing buy-side defense layer: pre-spend simulation, counterparty scoring, monotonic state-channel settlement, and enterprise policy enforcement.

## Status

**Phase 1 — Documentation & Protocol Design.** This repository currently contains the architecture specification suite built from the Paythos Protocol v2.0.0-RFC. Implementation follows the gated sequence in [docs/ROADMAP.md](docs/ROADMAP.md).

| Document | Contents |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 5-layer system topology, module-by-module specification |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | x402 v2 semantics, EIP-712 voucher schema, transport rules |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, formal security invariants, attack scenarios |
| [docs/CIRCLE-INTEGRATION.md](docs/CIRCLE-INTEGRATION.md) | agents.circle.com symbiosis, Discovery API ingestion, grant positioning |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Gate 1→5 implementation sequence with acceptance criteria |
| [AGENTS.md](AGENTS.md) | Repo conventions, toolchain, chain constants |

## Design in one paragraph

A human treasurer deposits USDC into `PaythosVault.sol` and delegates an ephemeral key with a policy struct (`dailyLimit`, `maxPerTx`, TTL). An agent runtime holding that key pays merchants over HTTP using x402 v2: merchants issue `402` challenges, the agent signs cumulative EIP-712 vouchers **off-chain at zero gas**, merchants verify signatures in memory and serve the data, and vouchers batch-flush to the vault for one on-chain settlement per few dollars accumulated. Prompt-injection attacks die at three independent layers: SDK policy checks, bytecode limits, and human review gates. Every spend carries a `keccak256` hash of the prompt that caused it, stamped as an Arc structured memo for enterprise accounting.

## Prior work

The original demo repository (`github.com/Web3Manuel001/paythos`) validated the EIP-712 voucher flow end-to-end on Arc Testnet (vault `0xa9d5525BE440831c64695d30c915DF303E0151EF`, native USDC at `0x3600...0000`). This repository is a **fresh build** targeting the v2.0.0-RFC spec above; the demo is reference-only.
