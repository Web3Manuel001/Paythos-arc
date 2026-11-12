# Paythos Protocol — Repository Conventions

Instructions for any AI coding agent or contributor working in this repository.

## Project Identity

Paythos is an enterprise spend-guardrail layer for AI agents. Vendors of the guardrails;
not a marketplace, not an exchange, not a custodian. Non-custodial at all times.

## Toolchain (locked)

| Component | Stack | Location (when built) |
| --- | --- | --- |
| On-chain core | Solidity + Foundry, OpenZeppelin v5 | `contracts/` |
| SDK / client / middleware / MCP | TypeScript (Node ≥ 18, strict TS) | `sdk/typescript/`, `mcp-server/` |
| Python SDK + FastAPI merchant middleware | Python ≥ 3.10, `uv` for tooling | `sdk/python/` |
| Testing | Foundry (forge, invariant fuzzing), Vitest (TS), pytest (Python) | per package |

## Chain Constants

**Deployment target: Arc L1 only.** Base was evaluated in the original RFC and has been
descoped by the team (reference material in the docs may mention Base historically —
assertions like "primary L2 target" apply to the old spec, not this build).

| Network | CAIP-2 | Chain ID | USDC | Notes |
| --- | --- | --- | --- | --- |
| Arc Testnet | `eip155:5042002` | 5042002 | `0x3600000000000000000000000000000000000000` (native USDC precompile) | RPC `https://rpc.testnet.arc.io`; explorer `https://explorer.testnet.arc.io`; chain-ID + precompile code verified live (docs.arc.io); dev/test target |
| Arc Mainnet | `arc:mainnet` per Circle x402 docs | **5042** (`0x13b2`, verified against docs.arc.io) | TBD — address not yet verified | RPC `https://rpc.mainnet.arc.io`; explorer `https://explorer.arc.io`; SDK stays fail-closed until USDC address is confirmed (PROTOCOL-OPEN-Q1) |

**Cross-chain funding (other chains' stablecoins):** exclusively via **Circle CCTP**.
Paythos never builds or operates a bridge — it calls Circle's attestation/minting rail
(AGENTS.md rule 4). See `docs/PROTOCOL.md §8`.

**Treasury wallet:** supplied by the team at deployment time via
`PAYTHOS_TREASURY_ADDRESS` (env / deploy config). Nothing in source or docs hardcodes a
treasury address; deployment scripts fail closed if it is missing or zero-address.

Reference prior deployment (historical, not to be migrated): Arc Testnet vault
`0xa9d5525BE440831c64695d30c915DF303E0151EF`, explorer `testnet.arcscan.app`.

**Current live build deployment** (PROTOCOL v3, 2026-11-09): Arc Testnet vault
`0xD69eA0ab9671549095D473E5176579ee879373Ce` (deploy tx `0x69e20da8b578feda290294edf9cf198a07b6cd8a97f9fb95a0d2d6913e3a7895`),
owner/treasury/merchant `0x7D6d956b4A57d8193Ad935E0B9382dF39efEFb2C` — owner key held
only in the operator's local `PAYTHOS_DEPLOYER_KEY` env, never committed. Settlement
token = native USDC precompile `0x3600…0000`. Full E2E PASS (epoch-synced claim tx
`0xa874d4f291be7a1eb2210e9c7ebda4f765e2f3bab8998095af7d17e597876c69`, block 71523116,
fee 150 bps, replay rejected) plus the INV-6 live proof via `scripts/arc-inv6-live.ts`:
re-authorization bumped epoch 1→2, a monotonic-valid stale-epoch voucher REVERTED
(`SessionEpochMismatch`), and the live-epoch claim settled under clean-slate semantics.
The 2026-11-07 v2 vault `0x5E7F…0c4C` predates epochs and is no longer the current build.

## Domain Vocabulary (use consistently)

- **Vault** — `PaythosVault.sol`; custody + policy enforcement + batch settlement.
- **Voucher** — EIP-712 signed struct (PROTOCOL v3 domain version `"3"`): `agentKey, merchant, token, cumulativeAmount, validUntil, epoch`. Always cumulative, never per-call amounts. `epoch` binds the voucher to one `authorizeAgent` generation (INV-6): re-authorization bumps it (stale vouchers revert `SessionEpochMismatch`), while revocation deactivates the agent immediately (claims revert `UnauthorizedAgent`).
- **Policy struct** — `dailyLimit`, `maxPerTx`, `expiresAt` (TTL), allowlist set.
- **Flush** — merchant-side batch settlement of accumulated vouchers to the vault.
- **Transactability Index** — merchant health score (uptime, response validity, latency, 5xx rate).
- **dryRun** — pre-execution financial simulation; never moves capital.
- **Verifiable Intent** — `keccak256(prompt || timestamp)` stamped into calldata/memo.
- **GOFER** — internal name for the policy/authorization engine (inherited from the demo repo: "Governing Financial Objectives Runtime"). Optional but preferred term.
- **YOPO** — "You Only Pay Outcome": no voucher for unrendered tokens / failed streams.

## Non-Negotiable Design Rules

1. **Non-custodial always.** The human owner retains emergency withdrawal rights. No pooled liquidity, no rehypothecation, no yield logic.
2. **Deltas are enforced on-chain.** `claimVoucher()` must require `cumulativeAmount > previousClaim`, `delta <= maxPerTx`, `spentToday + delta <= dailyLimit` against a rolling 24h window computed from `block.timestamp` on exact hour boundaries (25-slot `SlidingWindow` ring; no oracles, no cron). It must also require the ACTIVE delegation epoch (INV-6).
3. **Fail closed.** Policy ambiguity → halt. Never default to allow.
4. **Never build custody, bridging, or marketplace features** — that is Circle's lane. Cross-chain funding is done by calling Circle's CCTP attestation/minting rail only. Paythos ingests Circle's tools (Discovery API, CCTP); it never re-implements settlement rails Circle already provides.
5. **Secrets hygiene.** Ephemeral keys come from environment variables (`PAYTHOS_EPHEMERAL_KEY`, `PAYTHOS_VAULT_ADDRESS`, …). Nothing key-related is ever logged, committed, or embedded. EIP-712 messages may be logged; signatures of real spend cannot be replayed across sessions.
6. **Fee switch** — protocol fee capped at 5%, default 150 bps, deducted at source inside `claimVoucher()`, routed atomically to treasury.

## Verification (run before every commit)

```bash
cd contracts && forge test                        # 36 tests (unit + invariant fuzz)
cd sdk/typescript && npx tsc --noEmit && npm test # 136 tests, strict TS
cd sdk/python && .venv/bin/python -m pytest tests # 112 tests (asyncio_mode=auto)
cd sdk/typescript && npm run bench:verify -- 2000 --enforce   # release hardware only
```

Keep the three suites green; add an invariant-referencing test for every guard you touch.

## Code Style

- TypeScript: strict, no `any` in exported APIs, ESM, named exports. Route errors as typed results, not thrown strings.
- Solidity: OZ v5 EIP-712 (`EIP712` + `SignatureChecker`), solc 0.8.x, no `delegatecall` in vault logic. Events for every state change including fee routing and revocations.
- Python: `pydantic` models mirroring the TS types 1:1; `httpx` not `requests`.
- Comments: explain *why* (invariants, threat-model references) not *what*. Reference `docs/SECURITY.md` invariant identifiers (e.g. `INV-2 Daily Ceiling`) in guards.

## Documentation Rules

- All protocol facts must trace to `docs/PROTOCOL.md` or the Circle docs referenced in `docs/CIRCLE-INTEGRATION.md`. If the code contradicts a doc, fix or flag both — never silently diverge.
- Numbers in docs (thresholds like $1/$10/$25, $5 flush, $2 credit line, 1.5% fee) are spec defaults; code must expose them as configurable per-policy/vault parameters with these defaults.

## Build Order

Respect the gate sequence in `docs/ROADMAP.md`. Gate 1 (vault + invariant fuzz suite) blocks everything else. Do not start Gate 2 SDK signing code before the vault's EIP-712 domain/schema is finalized.
