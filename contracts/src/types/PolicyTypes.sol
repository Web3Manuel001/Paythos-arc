// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

/**
 * @title PolicyTypes
 * @notice Per-ephemeral-key spend policy enforced by the vault (docs/PROTOCOL.md §2).
 * @dev Amounts are in atomic units of the settlement token (USDC = 6 decimals).
 *      Defaults per docs/PROTOCOL.md: dailyLimit 20e6, maxPerTx 2.5e6.
 */
library PolicyTypes {
    struct Policy {
        uint256 dailyLimit;
        uint256 maxPerTx;
        uint64 expiresAt;
    }
}
