// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockUSDC
 * @notice 6-decimal ERC-20 mirroring USDC for tests. On Arc testnet the real
 *      native-USDC precompile plays this role.
 */
contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {}

    // Faucet-style mint for test isolation.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
