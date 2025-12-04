// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {GlassNodeRegistry} from "../src/GlassNodeRegistry.sol";

/// @notice Deployment script for GlassNodeRegistry.
/// @dev Expects these env vars (all prefixed with REG_):
///      - REG_ADMIN        (address) admin to receive DEFAULT_ADMIN_ROLE
///      - REG_STAKE_TOKEN  (address) ERC20 used for staking
///      - REG_MIN_STAKE    (uint256) minimum stake amount
///      Optional:
///      - REG_PRIVATE_KEY  (uint256) if you want script to pick broadcaster automatically.
///        Otherwise pass `--private-key` / `--mnemonic` to forge.
///      Example usage:
///        REG_ADMIN=0x... REG_STAKE_TOKEN=0x... REG_MIN_STAKE=100e18 \
///        forge script script/DeployRegistry.s.sol:GlassNodeRegistryScript --broadcast
contract GlassNodeRegistryScript is Script {
    GlassNodeRegistry public reg;

    function run() public {
        address admin = vm.envOr("REG_ADMIN", address(0));
        address stakeToken = vm.envOr("REG_STAKE_TOKEN", address(0));
        uint256 minStake = vm.envOr("REG_MIN_STAKE", uint256(0));

        if (admin == address(0)) {
            console2.log("Missing/invalid REG_ADMIN env var.");
            console2.log("Set REG_ADMIN to a non-zero address.");
            revert("REG_ADMIN env var required");
        }
        if (stakeToken == address(0)) {
            console2.log("Missing/invalid REG_STAKE_TOKEN env var.");
            console2.log("Set REG_STAKE_TOKEN to the ERC20 staking token address.");
            revert("REG_STAKE_TOKEN env var required");
        }
        if (minStake == 0) {
            console2.log("Missing/invalid REG_MIN_STAKE env var.");
            console2.log("Set REG_MIN_STAKE to a non-zero uint (token base units).");
            revert("REG_MIN_STAKE env var required");
        }

        uint256 pk = vm.envOr("REG_PRIVATE_KEY", uint256(0));
        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        reg = new GlassNodeRegistry(admin, stakeToken, minStake);

        vm.stopBroadcast();

        console2.log("GlassNodeRegistry deployed at:", address(reg));
        console2.log("admin:", admin);
        console2.log("stakeToken:", stakeToken);
        console2.log("minStake:", minStake);
    }
}
