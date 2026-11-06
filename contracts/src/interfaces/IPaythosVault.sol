// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {VoucherTypes} from "../types/VoucherTypes.sol";
import {PolicyTypes} from "../types/PolicyTypes.sol";

/**
 * @title IPaythosVault
 * @notice ABI surface for the TS/Python SDKs and the merchant accumulator.
 *      Mirrors docs/PROTOCOL.md §2 one-to-one.
 */
interface IPaythosVault {
    // ===== Human capital layer (Layer 1 trust) =====
    function deposit(uint256 amount) external;
    function emergencyWithdraw() external; // INV-5: owner-only capital exit

    // ===== Delegation lifecycle =====
    function authorizeAgent(address agentKey, PolicyTypes.Policy calldata policy) external;
    function revokeAgent(address agentKey) external;
    function allowMerchant(address agentKey, address merchant) external;
    function blockMerchant(address agentKey, address merchant) external;

    // ===== Merchant settlement =====
    function claimVoucher(VoucherTypes.Voucher calldata voucher, bytes calldata signature)
        external
        returns (uint256 deltaPaid);

    // ===== Protocol configuration =====
    function setFeeBps(uint256 newFeeBps) external;

    // ===== Telemetry for MCP `get_vault_budget` =====
    function isAgentActive(address agentKey) external view returns (bool);
    function getPolicy(address agentKey) external view returns (PolicyTypes.Policy memory);
    function spentToday(address agentKey) external view returns (uint256);
    function claimed(address agentKey, address merchant) external view returns (uint256);
    function remainingAllowance(address agentKey) external view returns (uint256);
    function feeBps() external view returns (uint256);
}
