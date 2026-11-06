// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface ITransferHook {
    function onAfterTokenTransfer(address from, address to, uint256 amount) external;
}

/**
 * @title HookableUSDC
 * @notice Test-only ERC-20 that invokes a post-transfer hook on contract
 *      receivers. This is how we construct a REALISTIC reentrancy vector for
 *      `claimVoucher` (merchant contracts that react on receipt) — real USDC
 *      has no hook, but our invariant suite must exclude it anyway (defense in
 *      depth, SECURITY.md INV-5).
 */
contract HookableUSDC is ERC20 {
    mapping(address => bool) public hooked;

    constructor() ERC20("Hookable USDC", "USDC") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setHook(address receiver, bool on) external {
        hooked[receiver] = on;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        bool ok = super.transfer(to, amount);
        if (hooked[to]) {
            // Return-bomb resistance NOT tested here; the vault is only
            // required to survive reentry, not malicious revert bombs (SafeERC20
            // would revert on a non-true outer return, which is fine).
            ITransferHook(to).onAfterTokenTransfer(msg.sender, to, amount);
        }
        return ok;
    }
}
