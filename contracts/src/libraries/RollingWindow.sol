// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

/**
 * @title RollingWindow
 * @notice Rolling 24-hour windowing helper (docs/SECURITY.md INV-2 Daily Ceiling).
 * @dev Window logic executes INSIDE `claimVoucher` — no cron, no oracle. The window
 *      opens at the first settlement in the cycle and hard-resets after 24 hours.
 */
library RollingWindow {
    uint256 internal constant WINDOW = 1 days;

    /**
     * @notice Returns the effective `(spentToday, windowStart)` for a settlement
     *      evaluated at `now_`.
     * @param isFreshDelegation true right after `authorizeAgent` — the key opens
     *      a new window immediately at `now_` with a zero tally.
     * @return newSpent  zero once the horizon has elapsed; otherwise unchanged.
     * @return newStart  the next window boundary timestamp; otherwise unchanged.
     */
    function applyRollover(uint256 now_, uint256 spentToday, uint256 windowStart, bool isFreshDelegation)
        internal
        pure
        returns (uint256 newSpent, uint256 newStart)
    {
        if (isFreshDelegation) {
            // A fresh delegation cannot inherit a previous tally — prevents
            // authorize-then-instantly-hit-a-full-limit attacks.
            return (0, now_);
        }
        if (now_ >= windowStart + WINDOW) {
            // Rolling 24h reset (INV-2): dynamic, no admin cron.
            return (0, now_);
        }
        return (spentToday, windowStart);
    }

    /**
     * @notice View-time effective spend of a window (answer without mutation) —
     *      MCP `get_vault_budget` and `remainingAllowance` used by both.
     */
    function current(uint256 now_, uint256 spentToday, uint256 windowStart) internal pure returns (uint256) {
        if (now_ >= windowStart + WINDOW) return 0;
        return spentToday;
    }
}
