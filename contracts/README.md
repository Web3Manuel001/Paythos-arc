# PaythosVault — on-chain core

Solidity 0.8.28 · Foundry · OpenZeppelin v5 (`EIP712` + `SignatureChecker`). No `delegatecall`,
no upgradeability, no custody beyond the vault's own USDC balance.

```text
src/core/PaythosVault.sol      custody + policy enforcement + batch settlement
src/libraries/SlidingWindow.sol  24-slot rolling daily window (exact hour boundaries)
src/libraries/FeeDistribution.sol  protocol fee split (default 150 bps, cap 5%)
src/types/PolicyTypes.sol     dailyLimit / maxPerTx / expiresAt + allowlist
src/types/VoucherTypes.sol    cumulative EIP-712 voucher (epoch-bound, INV-6)
test/unit/                    unit + reentrancy suites
test/invariant/               fuzz invariants (INV-1 … INV-6)
```

## Build and test

```bash
forge build
forge test            # 34 tests incl. invariant fuzz campaign
forge fmt
```

## Deploy (fails closed)

`script/deploy/DeployVault.s.sol` refuses to run without explicit config:

| Variable | Required | Notes |
| --- | --- | --- |
| `PAYTHOS_TREASURY_ADDRESS` | yes | non-zero; fee routing destination |
| `PAYTHOS_SETTLEMENT_TOKEN` | outside Arc Testnet | Arc Testnet defaults to the native USDC precompile |
| `PAYTHOS_DEPLOYER_KEY` | yes | broadcast key (env only, never committed) |

```bash
PAYTHOS_TREASURY_ADDRESS=0x… PAYTHOS_DEPLOYER_KEY=0x… \
  forge script script/deploy/DeployVault.s.sol:DeployVault \
  --rpc-url https://rpc.testnet.arc.io --broadcast
```

Deployment targets **Arc L1 only**. Arc Mainnet remains blocked until the USDC address is verified (PROTOCOL-OPEN-Q1).

## Invariants the bytecode enforces

- strictly increasing cumulative claims (`delta > 0`, INV-1)
- `delta <= maxPerTx` and `spentToday + delta <= dailyLimit` in the rolling 24h window (INV-2/INV-3)
- active delegation epoch only — re-authorization/revocation invalidates stale vouchers (INV-6)
- allowlisted merchant destinations only
- fee deducted at source and routed to treasury atomically
