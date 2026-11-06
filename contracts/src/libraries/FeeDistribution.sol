// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

/**
 * @title FeeDistribution
 * @notice Protocol take-rate math (docs/PROTOCOL.md §2.8 fee switch).
 * @dev Fee is deducted at source inside `claimVoucher` and routed atomically in
 *      the same transaction (docs/ARCHITECTURE.md Module 1.6). Rounds in the
 *      merchant's favor (floor) so the protocol never captures an extra wei.
 */
library FeeDistribution {
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant FEE_CAP_BPS = 500; // hard 5% cap (AGENTS.md rule 6)
    uint256 public constant DEFAULT_FEE_BPS = 150; // 1.5%

    function amountForBps(uint256 value, uint256 bps) internal pure returns (uint256) {
        return (value * bps) / BPS_DENOMINATOR;
    }

    /// @notice Splits `delta` into protocol fee (floor) + net merchant amount.
    function split(uint256 delta, uint256 feeBps) internal pure returns (uint256 fee, uint256 net) {
        fee = amountForBps(delta, feeBps);
        net = delta - fee;
    }
}
