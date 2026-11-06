// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {VoucherTypes} from "../types/VoucherTypes.sol";

/**
 * @title VaultEvents
 * @notice Every state change (including fee routing and revocations) emits here.
 *      Off-chain SDKs index these; the Arc explorer indexes `memoHash` natively
 *      (docs/ARCHITECTURE.md Module 1.5 — structured memo compatibility).
 */
library VaultEvents {
    using VoucherTypes for VoucherTypes.Voucher;

    event VaultDeposit(address indexed owner, address indexed token, uint256 amount);
    event EmergencyWithdrawal(address indexed owner, address indexed token, uint256 amount);
    event AgentAuthorized(address indexed agentKey, uint256 dailyLimit, uint256 maxPerTx, uint64 expiresAt);
    event AgentRevoked(address indexed agentKey, address indexed revoker);
    event MerchantAllowed(address indexed agentKey, address indexed merchant);
    event MerchantBlocked(address indexed agentKey, address indexed merchant);
    event FeeUpdated(uint256 previousFeeInBps, uint256 newFeeInBps);
    /// @param memoHash indexed so Arc explorer + accounting systems can group by intent.
    event VoucherClaimed(
        address indexed agentKey,
        address indexed merchant,
        uint256 cumulativeAmount,
        uint256 delta,
        uint256 feeAmount,
        bytes32 indexed memoHash
    );
}
