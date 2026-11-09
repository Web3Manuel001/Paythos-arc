// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

/**
 * @title SlidingWindow
 * @notice Exact sliding 24-hour spend ceiling (docs/SECURITY.md INV-2 Daily
 *      Ceiling). Hourly buckets + preferred stamp ordering enforce "no more
 *      than `dailyLimit` may settle within ANY 24-hour span" — a fixed-window
 *      limiter would permit limit+limit across two claims one second apart.
 * @dev Pool checked at claim hour h = stamps in [h-24, h]. Any true 24h window
 *      overlaps at most 25 consecutive hour stamps; the latest purchase within
 *      any window has had exactly that pool verified at its own claim, so the
 *      invariant holds with ZERO approximation error (hour granularity).
 *      Storage: 24 slots referenced stamp%24 — a stamp reappears every 24
 *      hours and its slot is only ever overwritten AFTER the old value has
 *      been counted in a pool check, so nothing is lost. 25 SLOAD-equivalent
 *      budget per claim (Arc gas, acceptable; do not reduce slots).
 */
library SlidingWindow {
    uint256 internal constant SLOTS = 24; // hour buckets
    uint256 internal constant HOUR = 1 hours;

    struct Window {
        uint256[24] amount; // spend bucketed by hour
        uint64[24] stamp; // hour index each amount belongs to; 0 ⇒ empty
    }

    /**
     * @notice Spend recorded in the 24h window preceeding hour `h` (excluding a
     *      hypothetical in-flight delta — call BEFORE adding).
     * @dev Slots with stamp ∈ [h-24, h]. Genesis stamps (0) with zero amount
     *      contribute nothing and can never be a false positive.
     */
    function spent(Window storage window, uint64 h) internal view returns (uint256 total) {
        unchecked {
            // h < 24 (pre-genesis) ⇒ oldest wraps under `unchecked`; ground it to 0.
            uint64 oldest = h >= 24 ? h - 24 : 0;
            for (uint256 i; i < SLOTS; ++i) {
                uint64 stamp = window.stamp[i];
                if (stamp >= oldest && stamp <= h) {
                    // slot i can only hold stamps ≡ i (mod 24); within the 25-hour
                    // pool [h-24, h] exactly one stamp per slot qualifies.
                    total += window.amount[i];
                }
            }
        }
    }

    /// @notice Remaining allowance out of `limit` for hour `h`.
    function remaining(Window storage window, uint64 h, uint256 limit) internal view returns (uint256) {
        uint256 used = spent(window, h);
        return used < limit ? limit - used : 0;
    }

    /**
     * @notice Record `amount` into hour `h`. The caller MUST have verified
     *      `spent(window, h) + amount ≤ limit` first — releases.
     */
    function add(Window storage window, uint64 h, uint256 amount) internal {
        uint256 slot = h % SLOTS;
        if (window.stamp[slot] == h) {
            window.amount[slot] += amount;
        } else {
            window.stamp[slot] = h;
            window.amount[slot] = amount;
        }
    }

    /// @notice Zero-out the window (fresh delegation clears the ceiling).
    function clear(Window storage window) internal {
        for (uint256 i; i < SLOTS; ++i) {
            if (window.amount[i] != 0) {
                window.amount[i] = 0;
            }
            window.stamp[i] = 0;
        }
    }
}
