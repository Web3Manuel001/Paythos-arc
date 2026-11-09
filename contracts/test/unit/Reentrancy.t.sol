// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {PaythosVault} from "../../src/core/PaythosVault.sol";
import {VoucherTypes} from "../../src/types/VoucherTypes.sol";
import {PolicyTypes} from "../../src/types/PolicyTypes.sol";
import {HookableUSDC} from "../mocks/HookableUSDC.sol";
import {ReentrantMerchant} from "../mocks/ReentrantMerchant.sol";
import {VaultErrors} from "../../src/errors/VaultErrors.sol";

/**
 * @title ReentrancyVector
 * @notice Gate-1 requirement: an adversarial merchant that re-enters
 *      `claimVoucher` from a token-receipt hook, replaying the exact voucher it
 *      just settled, must not extract a second payout. Defensive layers under
 *      test: `nonReentrant` outer guard (SECURITY.md reentrancy vector) + the
 *      INV-1 replay wall.
 */
contract ReentrancyVector is Test {
    using VoucherTypes for VoucherTypes.Voucher;

    PaythosVault internal vault;
    HookableUSDC internal usdc;
    ReentrantMerchant internal attacker;

    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant AGENT_KEY = 0xB0BD;
    address internal owner;
    address internal agent;

    uint256 internal constant DEPOSIT = 100_000e6;

    function setUp() public {
        owner = vm.addr(OWNER_KEY);
        agent = vm.addr(AGENT_KEY);

        usdc = new HookableUSDC();
        usdc.mint(owner, DEPOSIT);

        vm.startPrank(owner);
        vault = new PaythosVault(usdc, makeAddr("treasury"));
        attacker = new ReentrantMerchant(usdc, address(vault), agent);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(DEPOSIT);
        vault.authorizeAgent(
            agent,
            PolicyTypes.Policy({dailyLimit: 20e6, maxPerTx: 2_500_000, expiresAt: uint64(block.timestamp + 30 days)})
        );
        vault.allowMerchant(agent, address(attacker));
        usdc.setHook(address(attacker), true); // SAFE reentry into hookable receiver
        vm.stopPrank();
    }

    function test_reentrant_replay_extraction_blocked() public {
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = _sign(2e6); // $2.00, whole cumulative amount to attacker

        // What the reentry will attempt: EXACT same voucher + signature replay (INV-1).
        bytes memory replayCall = abi.encodeCall(PaythosVault.claimVoucher, (voucher, sig));
        attacker.prime(replayCall);

        uint256 merchantBefore = usdc.balanceOf(address(attacker));
        uint256 treasuryBefore = usdc.balanceOf(makeAddr("treasury"));

        vm.prank(address(attacker));
        vault.claimVoucher(voucher, sig); // inside the transfer hook, attacker reenters

        uint256 merchantAfter = usdc.balanceOf(address(attacker));
        uint256 treasuryAfter = usdc.balanceOf(makeAddr("treasury"));

        // The reentry attempt DID happen; assert it was rejected.
        assertGt(attacker.reentryAttempts(), 0, "reentry did not occur (setup error)");
        // Payout happened EXACTLY once: net-of-fee single $2.00 delta.
        uint256 net = 2e6 - (2e6 * 150) / 10_000;
        assertEq(merchantAfter - merchantBefore, net, "double payout detected!");
        assertEq(treasuryAfter - treasuryBefore, (2e6 * 150) / 10_000);
        assertEq(vault.claimed(agent, address(attacker)), 2e6); // INV-1 intact
    }

    function _sign(uint256 cumulativeAmount)
        internal
        view
        returns (VoucherTypes.Voucher memory voucher, bytes memory sig)
    {
        voucher = VoucherTypes.Voucher({
            agentKey: agent,
            merchant: address(attacker),
            token: address(usdc),
            cumulativeAmount: cumulativeAmount,
            validUntil: block.timestamp + 1 hours,
            epoch: vault.epochOf(agent),
            memo: keccak256("reentrancy-vector")
        });
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), voucher.structHash()));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_KEY, digest);
        sig = abi.encodePacked(r, s, v);
    }
}
