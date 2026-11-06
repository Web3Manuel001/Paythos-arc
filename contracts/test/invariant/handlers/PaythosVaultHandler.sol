// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {PaythosVault} from "../../../src/core/PaythosVault.sol";
import {VoucherTypes} from "../../../src/types/VoucherTypes.sol";
import {PolicyTypes} from "../../../src/types/PolicyTypes.sol";
import {MockUSDC} from "../../mocks/MockUSDC.sol";

/**
 * @title PaythosVaultHandler
 * @notice Actor simulation for the Gate-1 invariant fuzz suite. Every action is
 *      a plausible adversarial or patron move; ghost totals let the invariant
 *      checker audit conservation (docs/SECURITY.md INV-2, INV-5).
 */
contract PaythosVaultHandler is Test {
    using VoucherTypes for VoucherTypes.Voucher;

    PaythosVault internal vault;
    MockUSDC internal usdc;
    address internal owner;
    address internal treasury;

    uint256 internal constant AGENTS = 2;
    uint256 internal constant MERCHANTS = 3;
    uint256 internal constant DAILY_LIMIT = 20e6;
    uint256 internal constant MAX_PER_TX = 2_500_000;
    uint256 internal constant FEE_BPS = 150;

    uint256[AGENTS] internal agentPrivKeys;
    address[AGENTS] internal agentKeys;
    address[MERCHANTS] internal merchantKeys;

    // ---- Ghost ledgers (invariant audits read these) ----
    uint256 internal ghostDepositTotal;
    uint256 internal ghostPayoutTotal;
    uint256 internal ghostFeeTotal;

    mapping(address => uint256) internal paidByAgent;

    constructor(
        PaythosVault vault_,
        MockUSDC usdc_,
        uint256[AGENTS] memory privKeys,
        address[MERCHANTS] memory merchantAddrs,
        address owner_,
        address treasury_
    ) {
        vault = vault_;
        usdc = usdc_;
        owner = owner_;
        treasury = treasury_;
        for (uint256 i; i < AGENTS; ++i) {
            agentPrivKeys[i] = privKeys[i];
            agentKeys[i] = vm.addr(privKeys[i]);
        }
        for (uint256 m; m < MERCHANTS; ++m) {
            merchantKeys[m] = merchantAddrs[m];
        }
    }

    // ===== Ghost getters =====
    function totalDeposits() external view returns (uint256) {
        return ghostDepositTotal;
    }

    function totalPayouts() external view returns (uint256) {
        return ghostPayoutTotal;
    }

    function totalFees() external view returns (uint256) {
        return ghostFeeTotal;
    }

    function paidFor(address agentKey) external view returns (uint256) {
        return paidByAgent[agentKey];
    }

    function agentKeysArr() external view returns (address[2] memory) {
        return agentKeys;
    }

    // ===== Orders =====

    /**
     * @notice Well-formed cumulative voucher attempts signed by the real agent.
     *      Deltas stay ≤ maxPerTx so failures are policy outcomes, not bugs.
     *      Post-call ghost accounting lives OUTSIDE the try/catch so every
     *      successful settlement is ALWAYS counted regardless of assertions.
     */
    function claimSettlement(uint256 agentSeed, uint256 merchantSeed, uint256 incrementSeed) public {
        uint256 i = agentSeed % AGENTS;
        uint256 m = merchantSeed % MERCHANTS;
        address agentKey = agentKeys[i];
        address merchant = merchantKeys[m];
        if (!vault.isAgentActive(agentKey)) return; // revocation modeled separately

        PolicyTypes.Policy memory policy = vault.getPolicy(agentKey);
        uint256 claimedBefore = vault.claimed(agentKey, merchant);
        if (claimedBefore + 1 > type(uint256).max / 2) return; // overflow guard on cumulative
        uint256 delta = (incrementSeed % MAX_PER_TX) + 1;
        uint256 cumulative = claimedBefore + delta;

        VoucherTypes.Voucher memory voucher = _voucher(agentPrivKeys[i], merchant, cumulative);
        bytes memory sig = _sign(i, voucher);

        uint256 merchantBefore = usdc.balanceOf(merchant);
        uint256 treasuryBefore = usdc.balanceOf(treasury);
        uint256 spentTodayAfter = block.timestamp;

        try this._postClaim(merchant, voucher, sig) returns (uint256) {
            // Peg the current-block spentToday read at success-time (asserts happen below)
            spentTodayAfter = vault.spentToday(agentKey);
        } catch {
            // DailyLimitExceeded / SessionExpired are legitimate under fuzz.
            // No assertion work here — measurement below decides.
        }

        // ---- post-call measurement (OUTSIDE try/catch, authority for ghosts) ----
        uint256 merchantDelta = usdc.balanceOf(merchant) - merchantBefore;
        uint256 treasuryDelta = usdc.balanceOf(treasury) - treasuryBefore;
        bool settled = merchantDelta != 0 || treasuryDelta != 0;
        if (!settled) return; // clean revert, nothing to audit

        // INV accounting:
        assertGt(merchantDelta, 0, "INV: settlement paid nothing on a delta");
        uint256 expectedFee = (delta * FEE_BPS) / 10_000;
        assertEq(treasuryDelta, expectedFee, "INV: fee misroute");
        assertEq(merchantDelta, delta - expectedFee, "INV: net misroute");
        ghostPayoutTotal += merchantDelta;
        ghostFeeTotal += treasuryDelta;
        paidByAgent[agentKey] += merchantDelta;

        // INV-1/2/3 post-call integrity:
        assertEq(vault.claimed(agentKey, merchant), cumulative); // INV-1 monotonic
        assertLe(spentTodayAfter, policy.dailyLimit); // INV-2 ceiling
        assertLe(delta, policy.maxPerTx); // INV-3 per-tx bound
    }

    function _postClaim(address merchant_, VoucherTypes.Voucher memory voucher, bytes memory sig)
        external
        returns (uint256)
    {
        vm.prank(merchant_);
        return vault.claimVoucher(voucher, sig);
    }

    /**
     * @notice Adversarial replay path: a STALE lower-cumulative signature at a
     *      previously-settled pair must NEVER pay (INV-1).
     */
    function replayAttempt(uint256 agentSeed, uint256 merchantSeed, uint256 lowerAmount) public {
        uint256 i = agentSeed % AGENTS;
        uint256 m = merchantSeed % MERCHANTS;
        address agentKey = agentKeys[i];
        address merchant = merchantKeys[m];
        if (!vault.isAgentActive(agentKey)) return;

        uint256 currentClaimed = vault.claimed(agentKey, merchant);
        if (currentClaimed == 0) return; // nothing settled yet: no replay target
        uint256 staleAmount = lowerAmount % currentClaimed; // strictly lower cumulative

        VoucherTypes.Voucher memory voucher = _voucherStale(agentPrivKeys[i], merchant, staleAmount);
        bytes memory sig = _sign(i, voucher);
        uint256 merchantBefore = usdc.balanceOf(merchant);
        try this._postClaim(merchant, voucher, sig) {
            assertTrue(false, "INV-1 VIOLATION: replay paid out");
        } catch {}
        assertEq(usdc.balanceOf(merchant) - merchantBefore, 0);
    }

    /**
     * @notice Voucher to a merchant address NOT on the allowlist must never pay.
     */
    function unauthorizedMerchantAttempt(uint256 agentSeed, uint256 amount) public {
        uint256 i = agentSeed % AGENTS;
        if (!vault.isAgentActive(agentKeys[i])) return;
        address stranger = makeAddr("inv-stranger"); // never allowlisted
        VoucherTypes.Voucher memory voucher = _voucher(agentPrivKeys[i], stranger, amount);
        bytes memory sig = _sign(i, voucher);
        try this._postClaim(stranger, voucher, sig) {
            assertTrue(false, "UNAUTHORIZED merchant was paid");
        } catch {}
    }

    /**
     * @notice Owner tops up reserves from fee-vs-merchant ratio accounting.
     */
    function depositOrder(uint256 amount) public {
        amount = (amount % 100_000) + 1; // 1e6 micro-scale nuances
        vm.startPrank(owner);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(amount);
        ghostDepositTotal += amount;
        vm.stopPrank();
    }

    /**
     * @notice Owner warps 0..25h — the rollover boundary cycles constantly.
     */
    function warpOrder(uint256 hours_) public {
        vm.warp(block.timestamp + (hours_ % 25) * 1 hours);
    }

    /**
     * @notice Re-authorize an agent: fresh window + epoch (clean-slate rule).
     */
    function reauthorizeOrder(uint256 agentSeed, uint256 ttlHours) public {
        address agentKey = agentKeys[agentSeed % AGENTS];
        PolicyTypes.Policy memory fresh = PolicyTypes.Policy({
            dailyLimit: DAILY_LIMIT,
            maxPerTx: MAX_PER_TX,
            expiresAt: uint64(block.timestamp + (ttlHours % 48 + 1) * 1 hours)
        });
        vm.prank(owner);
        vault.authorizeAgent(agentKey, fresh);
        for (uint256 m; m < MERCHANTS; ++m) {
            vm.prank(owner);
            vault.allowMerchant(agentKey, merchantKeys[m]);
        }
    }

    /**
     * @notice Kill-switch a key: all its future claims must revert cleanly.
     */
    function revokeOrder(uint256 agentSeed) public {
        vm.prank(owner);
        vault.revokeAgent(agentKeys[agentSeed % AGENTS]);
    }

    // ===== internal signing =====

    function _voucher(uint256 agentPriv, address merchant, uint256 cumulative)
        internal
        view
        returns (VoucherTypes.Voucher memory voucher)
    {
        voucher = VoucherTypes.Voucher({
            agentKey: vm.addr(agentPriv),
            merchant: merchant,
            token: address(usdc),
            cumulativeAmount: cumulative,
            validUntil: block.timestamp + 5 hours,
            memo: keccak256(abi.encode("inv-fuzz", cumulative, merchant))
        });
    }

    function _voucherStale(uint256 agentPriv, address merchant, uint256 cumulative)
        internal
        view
        returns (VoucherTypes.Voucher memory voucher)
    {
        voucher = _voucher(agentPriv, merchant, cumulative);
        voucher.memo = keccak256(abi.encode("inv-stale", cumulative, merchant));
    }

    function _sign(uint256 i, VoucherTypes.Voucher memory voucher) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), voucher.structHash()));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPrivKeys[i], digest);
        return abi.encodePacked(r, s, v);
    }
}
