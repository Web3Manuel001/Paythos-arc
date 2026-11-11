# Security Policy

Paythos is a non-custodial spend-guardrail layer for AI agents. This document is the
public, auditable summary of the protocol's security invariants and threat model.
Internal design notes are kept out of the public tree on purpose; everything below maps
directly to code and tests in this repository.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through this repository's
**GitHub Security Advisories** ("Report a vulnerability" under the *Security* tab).
Do not open a public issue for an unpatched vulnerability. Include:

- affected component (`contracts/`, `sdk/typescript/`, `sdk/python/`, `mcp-server/`),
- a minimal reproduction (transaction sequence, voucher headers, or test),
- impact assessment against the invariants below.

We aim to acknowledge reports within 72 hours and coordinate disclosure after a fix
ships. No bug bounty is currently offered.

## Invariants enforced on-chain (`PaythosVault.sol`)

| ID | Invariant | Enforcement |
| --- | --- | --- |
| **INV-1** | Monotonic claim: `cumulativeAmount` must exceed the previous claim for the `(agentKey, merchant)` pair in the active epoch | `claimVoucher` reverts `InvalidVoucherAmount()` |
| **INV-2** | Daily ceiling: no more than `dailyLimit` settles inside any rolling 24h span, measured in hourly buckets `[h−24, h]` (25-slot ring, no oracle/cron) | reverts `DailyLimitExceeded()` |
| **INV-3** | Per-transaction bound: `delta ≤ maxPerTx` | reverts `MaxPerTxExceeded()` |
| **INV-4** | Temporal expiry: `block.timestamp` within voucher and policy TTL | reverts `SessionExpired()` |
| **INV-5** | Non-custodial reserve: only the owner may withdraw capital except via `claimVoucher`; no pooled liquidity, rehypothecation, yield, or `delegatecall` | `emergencyWithdraw` is owner-only; invariant tests reconcile vault balance exactly |
| **INV-6** | Epoch binding: vouchers carry the delegation epoch; re-authorization/revocation bumps it and invalidates old vouchers and destination allowances | reverts `SessionEpochMismatch()` / `UnauthorizedMerchant()` |

The 24h window uses 25 hourly slots precisely because both `h` and `h−24` are inside the
pool; aliasing them would let a second claim in the same hour under-count live spend.

## Merchant-side invariants (`sdk/typescript`, `sdk/python`)

| ID | Invariant |
| --- | --- |
| **INV-M1** | Verification is in-memory and does no RPC on the hot path (<5ms target). |
| **INV-M2** | The accumulator stores the highest cumulative voucher per agent; flushes post that voucher exactly once. |
| **INV-M3** | Flush settlement is exactly-once; receipts persist only after confirmation and replays are no-ops. |
| **INV-M4** | Credit wall halts streaming when unsettled exposure exceeds `creditToleranceMicro` until a flush confirms. |
| **INV-M5** | YOPO: unrendered/failed streams release holds and sign no voucher. |
| **INV-M6** | Per-agent token buckets throttle loops with HTTP 429 before cryptographic work. |

Additional fail-closed properties:

- **Payee binding:** the middleware accepts a voucher only when `voucher.merchant` equals
  its configured `merchantAddress`/`merchant_address`. A voucher for any other merchant
  never unlocks the route and never enters this payee's ledger.
- **Epoch-scoped ledger:** merchant high-water marks, settled amounts, and flush receipts
  are scoped to the delegation epoch, matching the vault's clean-slate claim reset.
- **Gating:** an unpaid request without a challenge factory is rejected with `402`; there
  is no pass-through mode.
- **Rate limiter:** invalid bucket/refill and transactability config fail at construction,
  not per request.

## Key handling

- Ephemeral agent keys and deployer keys are supplied only through environment variables
  (`PAYTHOS_EPHEMERAL_KEY`, `PAYTHOS_DEPLOYER_KEY`, …), never committed or logged.
- EIP-712 messages may be logged; signatures over real spend cannot be replayed across
  sessions because vouchers are cumulative and epoch-bound.
- The vault's settlement token and treasury are immutable after deployment; deployment
  scripts fail closed if `PAYTHOS_TREASURY_ADDRESS` is unset or zero.

## Threat model (summary)

| Attacker | Bounded by |
| --- | --- |
| Stolen ephemeral agent key | INV-2 + INV-3 (drip, not drain) for the TTL in INV-4; owner kill-switch revokes. |
| Malicious merchant replaying old vouchers | INV-1 monotonic cumulative total; INV-M3 exactly-once settlement. |
| Merchant front-running or oversettling | INV-3/INV-2 bound per-claim and daily loss; INV-M4 bounds unflushed credit. |
| Agent paying the wrong payee | Destination allowlist on-chain + payee binding at the middleware. |
| Replay after re-authorization | INV-6 epoch bump orphans old signatures and allowances. |
| Loop / denial-of-wallet | INV-M6 local 429 throttle, then INV-2/INV-3 on-chain. |

## Verification

```bash
cd contracts && forge test                         # unit + invariant fuzz
cd sdk/typescript && npm run typecheck && npm test  # strict TS
cd sdk/python && python -m pytest tests             # pytest
```

CI runs all three suites on every push and pull request (`.github/workflows/ci.yml`),
including the 10,000-run Foundry invariant profile.

## Out of scope

- Custody, bridging, or marketplace features are not part of Paythos; cross-chain funding
  uses Circle CCTP only.
- Arc mainnet USDC address is not yet verified; the SDK stays fail-closed there until it is.
