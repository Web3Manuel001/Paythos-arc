// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {PaythosVault} from "../../../src/core/PaythosVault.sol";
import {VoucherTypes} from "../../../src/types/VoucherTypes.sol";
import {PolicyTypes} from "../../../src/types/PolicyTypes.sol";
import {MockUSDC} from "../../mocks/MockUSDC.sol";

/**
 * @title VaultTestBase
 * @notice Shared fixture for Gate-1 unit + invariant tests.
 */
contract VaultTestBase is Test {
    using VoucherTypes for VoucherTypes.Voucher;

    PaythosVault internal vault;
    MockUSDC internal usdc;

    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant AGENT_KEY = 0xB0BD;
    uint256 internal constant MERCHANT_KEY = 0xC0DE;

    address internal owner;
    address internal agent;
    address internal merchant;
    address internal treasury;

    uint256 internal constant DEPOSIT = 1_000_000e6; // $1,000,000.00 seed
    uint256 internal constant DAILY_LIMIT = 20e6; // $20.00 rolling window
    uint256 internal constant MAX_PER_TX = 2_500_000; // $2.50 per delta
    uint64 internal constant TTL = 7 days;
    uint256 internal constant FEE_BPS = 150; // 1.5%

    function setUp() public virtual {
        owner = vm.addr(OWNER_KEY);
        agent = vm.addr(AGENT_KEY);
        merchant = vm.addr(MERCHANT_KEY);
        treasury = makeAddr("treasury");

        usdc = new MockUSDC();
        usdc.mint(owner, DEPOSIT);

        vm.startPrank(owner);
        vault = new PaythosVault(usdc, treasury);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(DEPOSIT);
        vault.authorizeAgent(agent, defaultPolicy());
        vault.allowMerchant(agent, merchant);
        vm.stopPrank();
    }

    /// @notice Spec-default policy struct relative to the CURRENT timestamp.
    function defaultPolicy() internal view returns (PolicyTypes.Policy memory) {
        return
            PolicyTypes.Policy({
                dailyLimit: DAILY_LIMIT, maxPerTx: MAX_PER_TX, expiresAt: uint64(block.timestamp + TTL)
            });
    }

    /// @notice Signs a voucher for `agent`'s privkey (`agentPriv` = AGENT_KEY style).
    function signVoucher(
        uint256 agentPriv,
        address voucherMerchant,
        uint256 cumulativeAmount,
        uint256 validUntil,
        bytes32 memo
    ) internal view returns (VoucherTypes.Voucher memory voucher, bytes memory signature) {
        voucher = VoucherTypes.Voucher({
            agentKey: vm.addr(agentPriv),
            merchant: voucherMerchant,
            token: address(usdc),
            cumulativeAmount: cumulativeAmount,
            validUntil: validUntil,
            memo: memo
        });
        signature = signDigest(agentPriv, voucher);
    }

    /// @notice Happy-shorthand signing: current session, merchant under test.
    function signVoucherSimple(uint256 agentPriv, uint256 cumulativeAmount)
        internal
        view
        returns (VoucherTypes.Voucher memory voucher, bytes memory signature)
    {
        (voucher, signature) =
            signVoucher(agentPriv, merchant, cumulativeAmount, block.timestamp + 1 hours, keccak256("memo"));
    }

    /// @notice Off-chain digest computation mirroring docs/PROTOCOL.md §1.2.
    function signDigest(uint256 agentPriv, VoucherTypes.Voucher memory voucher) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), voucher.structHash()));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPriv, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Warp helper keeping session validity consistent: re-authorizes and
    ///      re-allowlists the standard fixture agent so expiry is never the
    ///      failure under test unless explicitly asserted.
    function warpOverTTL() internal {
        vm.warp(block.timestamp + TTL + 1 seconds);
        vm.prank(owner);
        vault.authorizeAgent(agent, defaultPolicy());
        vm.prank(owner);
        vault.allowMerchant(agent, merchant);
    }
}
