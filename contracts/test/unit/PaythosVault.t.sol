// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {PaythosVault} from "../../src/core/PaythosVault.sol";
import {VoucherTypes} from "../../src/types/VoucherTypes.sol";
import {PolicyTypes} from "../../src/types/PolicyTypes.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {VaultErrors} from "../../src/errors/VaultErrors.sol";
import {VaultEvents} from "../../src/events/VaultEvents.sol";
import {VaultTestBase} from "./parts/VaultTestBase.sol";
import {MockUSDC} from "../mocks/MockUSDC.sol";

using VoucherTypes for VoucherTypes.Voucher;

/**
 * @title ClaimHappyPaths
 * @notice Gate-1: settlement lanes under normal operation.
 */
contract ClaimHappyPaths is VaultTestBase {
    function test_cumulative_claim_wires_net_and_fee() public {
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(AGENT_KEY, 2e6); // $2.00
        vm.prank(merchant);
        vm.expectEmit(true, true, true, true, address(vault));
        emit VaultEvents.VoucherClaimed(agent, merchant, 2e6, 2e6, (2e6 * FEE_BPS) / 10_000, keccak256("memo"));
        uint256 deltaPaid = vault.claimVoucher(voucher, sig);

        uint256 expectedFee = (2e6 * FEE_BPS) / 10_000; // $0.03
        assertEq(deltaPaid, 2e6 - expectedFee); // $1.97 net-of-fee
        assertEq(usdc.balanceOf(merchant), deltaPaid);
        assertEq(usdc.balanceOf(treasury), expectedFee);
        assertEq(vault.claimed(agent, merchant), 2e6);
        assertEq(vault.spentToday(agent), 2e6);
    }

    function test_second_accumulating_claim_pays_only_delta() public {
        (VoucherTypes.Voucher memory v1, bytes memory s1) = signVoucherSimple(AGENT_KEY, 2e6); // $2.00
        (VoucherTypes.Voucher memory v2, bytes memory s2) = signVoucherSimple(AGENT_KEY, 3e6); // $3.00

        vm.prank(merchant);
        vault.claimVoucher(v1, s1);

        vm.prank(merchant);
        uint256 secondNet = vault.claimVoucher(v2, s2);

        // Delta is exactly $1.00 minus its 1.5% fee.
        assertEq(secondNet, 1e6 - (1e6 * FEE_BPS) / 10_000);
        assertEq(vault.spentToday(agent), 3e6);
        assertEq(usdc.balanceOf(merchant), 3e6 - (3e6 * FEE_BPS) / 10_000);
    }

    function test_spend_accounted_across_merchants_sharing_state() public {
        // A second merchant under the SAME agent depletes the SESSION-wide window.
        address merchant2 = vm.addr(0xD02E);
        vm.prank(owner);
        vault.allowMerchant(agent, merchant2);

        (VoucherTypes.Voucher memory v1, bytes memory s1) = signVoucherSimple(AGENT_KEY, 2e6); // $2
        (VoucherTypes.Voucher memory v2, bytes memory s2) =
            signVoucher(AGENT_KEY, merchant2, 2_500_000, block.timestamp + 1 hours, keccak256("memo")); // $2.50 (its own pair, delta = whole)

        vm.prank(merchant);
        vault.claimVoucher(v1, s1);
        vm.prank(merchant2);
        uint256 delta = vault.claimVoucher(v2, s2);
        assertEq(delta, 2_500_000 - (2_500_000 * FEE_BPS) / 10_000); // full delta, fresh pair
        assertEq(vault.spentToday(agent), 4_500_000); // session-wide: $4.50
    }

    function test_rolling_window_resets_24h_after_start() public {
        // Drip inside maxPerTx bounds: 7 × $2.50 = $17.50, then +$2.40 = $19.90 spent.
        uint256 cum;
        VoucherTypes.Voucher memory v;
        bytes memory s;
        for (uint256 i; i < 7; ++i) {
            cum += 2_500_000;
            (v, s) = signVoucherSimple(AGENT_KEY, cum);
            vm.prank(merchant);
            vault.claimVoucher(v, s);
        }
        cum += 2_400_000; // $19.90 total
        (v, s) = signVoucherSimple(AGENT_KEY, cum);
        vm.prank(merchant);
        vault.claimVoucher(v, s);

        assertEq(vault.spentToday(agent), 19_900_000);
        assertEq(vault.remainingAllowance(agent), 100_000);

        // INV-2: window is rolling — a fresh 24h opens so the OLD tally never stacks:
        // with stacked windows $19.90 + $2.00 = $21.90 would revert DailyLimitExceeded.
        vm.warp(block.timestamp + 1 days);
        cum += 2_000_000;
        (v, s) = signVoucherSimple(AGENT_KEY, cum);
        vm.prank(merchant);
        vault.claimVoucher(v, s);
        assertEq(vault.spentToday(agent), 2_000_000); // fresh window only
        assertEq(vault.remainingAllowance(agent), DAILY_LIMIT - 2_000_000);
    }

    function test_settle_just_before_session_expiry_succeeds() public {
        PolicyTypes.Policy memory policy = vault.getPolicy(agent);
        (VoucherTypes.Voucher memory v, bytes memory s) =
            signVoucher(AGENT_KEY, merchant, 2e6, policy.expiresAt - 1, keccak256("memo"));
        vm.prank(merchant);
        assertTrue(vault.claimVoucher(v, s) > 0);
    }
}

/**
 * @title ClaimRevertPaths
 * @notice Gate-1: every documented vault revert reason has a dedicated test.
 */
contract ClaimRevertPaths is VaultTestBase {
    /// Corrupt the v byte of a signature to invalidate it cryptographically.
    function badV(bytes memory sig) internal pure returns (bytes memory) {
        sig[64] = bytes1(0x00);
        return sig;
    }

    function test_invalid_signature_rejected() public {
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(AGENT_KEY, 1e6);

        vm.prank(merchant);
        vm.expectRevert(VaultErrors.InvalidSignature.selector);
        vault.claimVoucher(voucher, badV(sig));
    }

    function test_wrong_signer_rejected() public {
        // Merchant signs with its own key — no delegation exists.
        (VoucherTypes.Voucher memory voucher,) = signVoucherSimple(AGENT_KEY, 1e6);
        bytes memory forged = signDigest(MERCHANT_KEY, voucher);

        vm.prank(merchant);
        vm.expectRevert(VaultErrors.InvalidSignature.selector);
        vault.claimVoucher(voucher, forged);
    }

    function test_stale_cumulative_amount_rejected() public {
        (VoucherTypes.Voucher memory hi, bytes memory hiSig) = signVoucherSimple(AGENT_KEY, 2e6);
        vm.prank(merchant);
        vault.claimVoucher(hi, hiSig);

        // INV-1: identical replay and lower amount both = InvalidVoucherAmount.
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.InvalidVoucherAmount.selector);
        vault.claimVoucher(hi, hiSig);
    }

    function test_voucher_past_validUntil_rejected() public {
        (VoucherTypes.Voucher memory voucher, bytes memory sig) =
            signVoucher(AGENT_KEY, merchant, 2e6, block.timestamp - 1, keccak256("memo"));
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.SessionExpired.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_policy_past_expiresAt_rejected() public {
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(AGENT_KEY, 1e6);
        vm.warp(block.timestamp + TTL + 1 seconds);
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.SessionExpired.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_unauthorized_agent_rejected_when_revoked() public {
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(AGENT_KEY, 1e6);
        vm.prank(owner);
        vault.revokeAgent(agent);
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.UnauthorizedAgent.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_unknown_agent_rejected_when_never_authorized() public {
        uint256 strangerPriv = 0x999E;
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(strangerPriv, 1e6);
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.UnauthorizedAgent.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_unauthorized_merchant_rejected() public {
        address badMerchant = makeAddr("badMerchant");
        (VoucherTypes.Voucher memory voucher, bytes memory sig) =
            signVoucher(AGENT_KEY, badMerchant, 1e6, block.timestamp + 1 hours, keccak256("memo"));
        vm.prank(badMerchant);
        vm.expectRevert(VaultErrors.UnauthorizedMerchant.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_token_mismatch_rejected() public {
        VoucherTypes.Voucher memory voucher = VoucherTypes.Voucher({
            agentKey: agent,
            merchant: merchant,
            token: makeAddr("not-the-settlement-token"),
            cumulativeAmount: 1e6,
            validUntil: block.timestamp + 1 hours,
            memo: keccak256("memo")
        });
        bytes memory sig = signDigest(AGENT_KEY, voucher);
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.TokenMismatch.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_delta_maximum_violation_rejected() public {
        // Single delta > maxPerTx — daily ceiling isn't even approached.
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(AGENT_KEY, MAX_PER_TX + 1);
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.MaxPerTxExceeded.selector);
        vault.claimVoucher(voucher, sig);
    }

    function test_daily_limit_violation_rejected() public {
        // Drip to $19.90 inside maxPerTx bounds; remaining allowance $0.10.
        uint256 cum;
        VoucherTypes.Voucher memory v;
        bytes memory s;
        for (uint256 i; i < 7; ++i) {
            cum += 2_500_000;
            (v, s) = signVoucherSimple(AGENT_KEY, cum);
            vm.prank(merchant);
            vault.claimVoucher(v, s);
        }
        cum += 2_400_000;
        (v, s) = signVoucherSimple(AGENT_KEY, cum);
        vm.prank(merchant);
        vault.claimVoucher(v, s);

        // INV-2: a $2.50 drip would overshoot the $20.00 ceiling → revert.
        cum += 2_500_000;
        (v, s) = signVoucherSimple(AGENT_KEY, cum);
        vm.prank(merchant);
        vm.expectRevert(VaultErrors.DailyLimitExceeded.selector);
        vault.claimVoucher(v, s);
    }
}

/**
 * @title DelegationLifecycle
 * @notice Gate-1: authorize/revoke/kill-switch policy hygiene.
 */
contract DelegationLifecycle is VaultTestBase {
    using PolicyTypes for PolicyTypes.Policy;

    function test_authorize_then_revoke_reauthorize_clean_window() public {
        PolicyTypes.Policy memory p =
            PolicyTypes.Policy({dailyLimit: 5e6, maxPerTx: 2_500_000, expiresAt: uint64(block.timestamp + 3 days)});
        vm.prank(owner);
        vault.authorizeAgent(agent, p);

        (VoucherTypes.Voucher memory v, bytes memory s) = signVoucherSimple(AGENT_KEY, 2e6);
        vm.prank(merchant);
        vault.claimVoucher(v, s);

        // Kill-switch then reauthorize — fresh window, zero claims (clean-slate rule).
        vm.prank(owner);
        vault.revokeAgent(agent);
        vm.prank(owner);
        vault.authorizeAgent(agent, p);
        assertEq(vault.claimed(agent, merchant), 0);
        assertEq(vault.remainingAllowance(agent), 5e6);
    }

    function test_double_revocation_fails_cleanly() public {
        vm.prank(owner);
        vault.revokeAgent(agent);
        vm.prank(owner);
        vm.expectRevert(VaultErrors.UnauthorizedAgent.selector);
        vault.revokeAgent(agent);
    }

    function test_maxPerTx_larger_than_dailyLimit_policy_rejected() public {
        PolicyTypes.Policy memory badPolicy =
            PolicyTypes.Policy({dailyLimit: 5e6, maxPerTx: 10e6, expiresAt: uint64(block.timestamp + 3 days)});
        vm.prank(owner);
        vm.expectRevert(VaultErrors.MaxPerTxExceeded.selector);
        vault.authorizeAgent(makeAddr("attackerKey"), badPolicy);
    }

    function test_policy_with_past_expiry_rejected() public {
        PolicyTypes.Policy memory pastPolicy =
            PolicyTypes.Policy({dailyLimit: 5e6, maxPerTx: 2_500_000, expiresAt: uint64(block.timestamp - 1)});
        vm.prank(owner);
        vm.expectRevert(VaultErrors.SessionExpired.selector);
        vault.authorizeAgent(makeAddr("attackerKey"), pastPolicy);
    }

    function test_zero_address_agent_key_rejected() public {
        vm.prank(owner);
        vm.expectRevert(VaultErrors.ZeroAddress.selector);
        vault.authorizeAgent(address(0), defaultPolicy());
    }
}

/**
 * @title AccessAndConfig
 * @notice Gate-1: owner-only guards, fee switch, emergency withdrawal.
 */
contract AccessAndConfig is VaultTestBase {
    function test_non_owner_operations_revert() public {
        vm.startPrank(agent);
        vm.expectRevert();
        vault.authorizeAgent(makeAddr("x"), defaultPolicy());
        vm.expectRevert();
        vault.revokeAgent(agent);
        vm.expectRevert();
        vault.emergencyWithdraw();
        vm.stopPrank();
    }

    function test_fee_cap_enforced() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(VaultErrors.FeeCapExceeded.selector, 501, 500));
        vault.setFeeBps(501);
    }

    function test_fee_capped_max_applies_to_next_claim() public {
        vm.prank(owner);
        vault.setFeeBps(500); // max 5% allowed
        (VoucherTypes.Voucher memory voucher, bytes memory sig) = signVoucherSimple(AGENT_KEY, 2e6);
        vm.prank(merchant);
        vault.claimVoucher(voucher, sig);
        assertEq(usdc.balanceOf(treasury), (2e6 * 500) / 10_000);
    }

    function test_emergency_withdraw_owner_only_and_full() public {
        vm.prank(agent);
        vm.expectRevert();
        vault.emergencyWithdraw();

        uint256 beforeOwner = usdc.balanceOf(owner);
        vm.prank(owner);
        vault.emergencyWithdraw();
        assertEq(usdc.balanceOf(owner), beforeOwner + DEPOSIT);
        assertEq(usdc.balanceOf(address(vault)), 0);
    }

    function test_rescue_token_cannot_drain_settlement_token() public {
        vm.startPrank(owner);
        vm.expectRevert(VaultErrors.DepositUnsupported.selector);
        vault.rescueToken(address(usdc), owner, DEPOSIT);
        vm.stopPrank();
    }

    function test_zero_address_constructor_config_rejected() public {
        vm.prank(owner);
        vm.expectRevert(VaultErrors.ZeroAddress.selector);
        new PaythosVault(usdc, address(0));
        vm.prank(owner);
        vm.expectRevert(VaultErrors.ZeroAddress.selector);
        new PaythosVault(IERC20(address(0)), treasury);
    }
}

