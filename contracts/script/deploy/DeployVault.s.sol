// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PaythosVault} from "../../src/core/PaythosVault.sol";

/**
 * @title DeployVault
 * @notice Gate-1 deployment script. FAILS CLOSED on missing config per AGENTS.md:
 *      `PAYTHOS_TREASURY_ADDRESS` and (non-test) `PAYTHOS_SETTLEMENT_TOKEN` are
 *      read from the environment; a missing/zero treasury aborts before deploy.
 */
contract DeployVault is Script {
    /// Arc Testnet native USDC precompile (docs/AGENTS.md chain constants).
    address constant ARC_TESTNET_USDC = 0x3600000000000000000000000000000000000000;
    uint256 constant ARC_TESTNET_CHAIN_ID = 5_042_002;

    function run() external returns (PaythosVault vault) {
        // ---- Treasury (mandatory, fail closed) ----
        address treasury = vm.envAddress("PAYTHOS_TREASURY_ADDRESS");
        require(treasury != address(0), "FAIL CLOSED: PAYTHOS_TREASURY_ADDRESS missing/zero");

        // ---- Settlement token: env override, else Arc testnet default ----
        address token;
        if (vm.envOr("PAYTHOS_SETTLEMENT_TOKEN", address(0)) != address(0)) {
            token = vm.envAddress("PAYTHOS_SETTLEMENT_TOKEN");
        } else if (block.chainid == ARC_TESTNET_CHAIN_ID) {
            token = ARC_TESTNET_USDC;
        } else {
            token = vm.envAddress("PAYTHOS_SETTLEMENT_TOKEN"); // required elsewhere
        }
        require(token != address(0), "FAIL CLOSED: PAYTHOS_SETTLEMENT_TOKEN unresolvable on this chain");

        uint256 deployerKey = vm.envUint("PAYTHOS_DEPLOYER_KEY");
        vm.startBroadcast(deployerKey);

        vault = new PaythosVault(IERC20(token), treasury);

        console2.log("PaythosVault deployed:");
        console2.log("   chainId       ", block.chainid);
        console2.log("   vault         ", address(vault));
        console2.log("   token         ", address(vault.SETTLEMENT_TOKEN()));
        console2.log("   treasury      ", address(vault.TREASURY()));
        console2.log("   owner         ", vault.owner());

        vm.stopBroadcast();
    }
}
