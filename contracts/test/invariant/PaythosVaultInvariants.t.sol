// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";

import {PaythosVault} from "../../src/core/PaythosVault.sol";
import {PolicyTypes} from "../../src/types/PolicyTypes.sol";
import {PaythosVaultHandler} from "./handlers/PaythosVaultHandler.sol";
import {MockUSDC} from "../mocks/MockUSDC.sol";

/**
 * @title PaythosVaultInvariants
 * @notice Gate-1 requirement: ≥10,000-run invariant fuzz across midnight
 *      rollover, expiry boundaries, reentrancy surfaces, and capital
 *      conservation (docs/ROADMAP.md Gate 1 acceptance; docs/SECURITY.md §1).
 *
 * Run: `FOUNDRY_PROFILE=invariant-fuzz forge test --match-path "test/invariant/*"`
 */
contract PaythosVaultInvariants is Test {
    PaythosVault internal vault;
    PaythosVaultHandler internal handler;

    address internal owner;
    address internal treasury;

    address[] internal agentAccounts;
    address internal merchantA;
    address internal merchantB;
    address internal merchantC;

    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256[2] internal agentKeysForHandler = [uint256(0xB0BD), uint256(0xCAFE)];
    address[] internal merchantArr;
    uint256 internal constant SEED_DEPOSIT = 100_000e6; // $100,000.00 initial liquidity

    function setUp() public {
        owner = vm.addr(OWNER_KEY);
        treasury = makeAddr("inv-treasury");
        merchantA = makeAddr("inv-merchant-a");
        merchantB = makeAddr("inv-merchant-b");
        merchantC = makeAddr("inv-merchant-c");
        merchantArr.push(merchantA);
        merchantArr.push(merchantB);
        merchantArr.push(merchantC);
        agentAccounts.push(vm.addr(agentKeysForHandler[0]));
        agentAccounts.push(vm.addr(agentKeysForHandler[1]));

        usdcRef = new MockUSDC();
        MockUSDC usdc = usdcRef;
        usdc.mint(owner, SEED_DEPOSIT * 2); // headroom for handler deposits out of reserves

        vm.startPrank(owner);
        vault = new PaythosVault(usdc, treasury);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(SEED_DEPOSIT);
        // Both agents: generous TTLs, spec defaults.
        for (uint256 i; i < 2; ++i) {
            vault.authorizeAgent(
                vm.addr(agentKeysForHandler[i]),
                PolicyTypes.Policy({
                    dailyLimit: 20e6, maxPerTx: 2_500_000, expiresAt: uint64(block.timestamp + 60 days)
                })
            );
            for (uint256 m; m < 3; ++m) {
                vault.allowMerchant(vm.addr(agentKeysForHandler[i]), merchantArr[m]);
            }
        }
        vm.stopPrank();

        handler = new PaythosVaultHandler(
            vault, usdc, agentKeysForHandler, [merchantA, merchantB, merchantC], owner, treasury
        );
        targetContract(address(handler));
    }

    /**
     * @notice INV-5 / SOLVENCY: vault balance == seed + incremental deposits −
     *      (payouts + fees). Value may never appear or disappear elsewhere.
     */
    MockUSDC internal usdcRef;

    function invariant_fullValueConservation() public {
        console2.log("ghost deposits", handler.totalDeposits());
        console2.log("ghost payouts ", handler.totalPayouts());
        console2.log("ghost fees    ", handler.totalFees());
        console2.log("vault balance ", usdcRef.balanceOf(address(vault)));
        uint256 vaultBalance = usdcRef.balanceOf(address(vault));
        uint256 expected = SEED_DEPOSIT + handler.totalDeposits() - handler.totalPayouts() - handler.totalFees();
        assertEq(vaultBalance, expected, "INV-5 violation: value not conserved");
    }

    /**
     * @notice INV-2 daily ceiling: rolling tallies must never exceed policy.
     */
    function invariant_dailyCeilingsHold() public view {
        address[2] memory keys = handler.agentKeysArr();
        for (uint256 i; i < 2; ++i) {
            PolicyTypes.Policy memory p = vault.getPolicy(keys[i]);
            assertLe(vault.spentToday(keys[i]), p.dailyLimit);
        }
    }

    /**
     * @notice INV-2 STRONG form (reviewer regression): reconstructing the
     *      settlement history, no agent may hold more than `dailyLimit` within
     *      any true 24h span. Hourly buckets span at most 25 hour stamps, so
     *      the 25h window must hold ≤ dailyLimit — anything over would betray
     *      window-reset manipulation (the "40 USDC in one second" PoC).
     */
    function invariant_slidingWindowExactness() public view {
        uint256 count = handler.claimHistoryCount();
        for (uint256 i; i < count; ++i) {
            (uint64 atI, uint64 agentI,) = handler.claimRecord(i);
            uint256 span;
            for (uint256 j; j < count; ++j) {
                (uint64 atJ, uint64 agentJ, uint256 amountJ) = handler.claimRecord(j);
                if (agentJ != agentI) continue;
                unchecked {
                    if (atJ > atI ? atJ - atI < 25 hours : atI - atJ < 25 hours) span += amountJ;
                }
            }
            assertLe(span, DAILY_LIMIT_LIMIT(), "INV-2 VIOLATION: more than dailyLimit settled inside a 24h span");
        }
    }

    function DAILY_LIMIT_LIMIT() internal view returns (uint256) {
        return vault.getPolicy(handler.agentKeysArr()[0]).dailyLimit;
    }
}
