// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {GlassNodeRegistryDeployScript, GlassNodeRegistry} from "../script/DeployRegistry.s.sol";

contract DeployScriptTest is Test {
    GlassNodeRegistryDeployScript script;

    function setUp() public {
        script = new GlassNodeRegistryDeployScript();
    }

    function test_run_reads_env_and_deploys_in_test_context() public {
        // Provide env vars expected by your script
        /// forge-lint: disable-start(unsafe-cheatcode)
        vm.setEnv("REG_ADMIN", vm.toString(address(0xA11CE)));
        vm.setEnv("REG_STAKE_TOKEN", vm.toString(address(new MockERC20())));
        vm.setEnv("REG_MIN_STAKE", "100000000000000000000"); // 100e18
        /// forge-lint: disable-end

        // run() will deploy to the in-memory test EVM, not a real chain
        script.run();

        GlassNodeRegistry reg = script.reg();

        assertEq(reg.minStake(), 100e18);
        assertEq(reg.stakeToken(), vm.parseAddress(vm.envString("REG_STAKE_TOKEN")));
        assertTrue(reg.hasRole(reg.ADMIN_ROLE(), vm.parseAddress(vm.envString("REG_ADMIN"))));
    }

    function test_run_reverts_when_env_missing() public {
        vm.setEnv("REG_ADMIN", vm.toString(address(0xA11CE)));
        // omit REG_STAKE_TOKEN / REG_MIN_STAKE

        vm.expectRevert(); // or a specific error string/selector from your script
        script.run();
    }
}

// small mock so the stake token is a contract address
contract MockERC20 {}
