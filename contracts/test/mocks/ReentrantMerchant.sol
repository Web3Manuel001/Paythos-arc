// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {HookableUSDC, ITransferHook} from "./HookableUSDC.sol";

/**
 * @title ReentrantMerchant
 * @notice Attack contract: when the vault wires it a settlement, it reenters
 *      `claimVoucher` with the SAME (stale) voucher it just paid out.
 *      Vault defense under test: `nonReentrant` outer guard + INV-1 monotonicity
 *      (SECURITY.md reentrancy vector, Gate 1 acceptance).
 */
contract ReentrantMerchant is ITransferHook {
    // function selector for `claimVoucher` is built manually to avoid a full ABI dep
    HookableUSDC public immutable TOKEN;
    address public immutable VAULT;
    address public immutable AGENT;

    bytes public staleCall;
    bool public attackArmed = true;
    uint256 public reentryAttempts;

    constructor(HookableUSDC token, address vault, address agent) {
        TOKEN = token;
        VAULT = vault;
        AGENT = agent;
    }

    /// Arm with the exact calldata to replay (same voucher = INV-1 violation attempt).
    function prime(bytes memory payload) external {
        staleCall = payload;
    }

    function disarm() external {
        attackArmed = false;
    }

    function onAfterTokenTransfer(address, address, uint256) external {
        if (!attackArmed) return;
        attackArmed = false;
        reentryAttempts++;
        (bool ok,) = VAULT.call(staleCall);
        // We swallow the result; the OUTER call must still settle net-to-zero.
        // The test itself asserts `ok == false` (== INV-1 replay blocked).
        ok; // silence
        attackArmed = true;
    }
}
