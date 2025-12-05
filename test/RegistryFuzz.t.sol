// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {GlassNodeRegistry, IERC20} from "../src/GlassNodeRegistry.sol";

contract MockERC20 is IERC20 {
    string public name = "Mock";
    string public symbol = "MOCK";
    uint8 public decimals = 18;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;
    uint256 public override totalSupply;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        totalSupply += amt;
        emit Transfer(address(0), to, amt);
    }

    function approve(address spender, uint256 amt) public virtual override returns (bool) {
        allowance[msg.sender][spender] = amt;
        emit Approval(msg.sender, spender, amt);
        return true;
    }

    function transfer(address to, uint256 amt) public virtual override returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) public virtual override returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        allowance[from][msg.sender] = a - amt;
        _transfer(from, to, amt);
        return true;
    }

    function _transfer(address from, address to, uint256 amt) internal {
        require(balanceOf[from] >= amt, "balance");
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        emit Transfer(from, to, amt);
    }
}

    contract MockVault {}

    /// Handler is the thing Foundry will fuzz-call in random sequences.
    /// Keep functions small and “safe to call anytime”.
    contract RegistryHandler is Test {
        GlassNodeRegistry public reg;
        MockERC20 public stake;
        MockERC20 public pay1;
        MockERC20 public pay2;
        MockVault public vault1;
        MockVault public vault2;

        address public admin;
        uint256 public minStake;

        bytes32 internal constant mA = keccak256("modelA");
        bytes32 internal constant mB = keccak256("modelB");

        constructor(
            GlassNodeRegistry _reg,
            MockERC20 _stake,
            MockERC20 _pay1,
            MockERC20 _pay2,
            MockVault _vault1,
            MockVault _vault2,
            address _admin,
            uint256 _minStake
        ) {
            reg = _reg;
            stake = _stake;
            pay1 = _pay1;
            pay2 = _pay2;
            vault1 = _vault1;
            vault2 = _vault2;
            admin = _admin;
            minStake = _minStake;
        }

        // -------- helpers --------

        function _pickEOA(uint256 seed) internal pure returns (address) {
            // derive a pseudo-random EOA from seed
            return address(uint160(uint256(keccak256(abi.encode(seed)))));
        }

        function _prepStake(address who) internal {
            // mint & approve enough stake so register can succeed
            stake.mint(who, minStake * 5);
            vm.startPrank(who);
            stake.approve(address(reg), type(uint256).max);
            vm.stopPrank();
        }

        function _anyNodeId(uint256 seed) internal view returns (uint256) {
            uint256 n = reg.nextNodeId();
            if (n == 0) return 0;
            return seed % n;
        }

        // -------- actions --------

        function actionRegister(uint256 whoSeed, uint256 vaultSeed, string calldata meta) external {
            address who = _pickEOA(whoSeed);
            vm.assume(who != address(0));
            vm.assume(who.code.length == 0);

            _prepStake(who);

            address v = (vaultSeed % 2 == 0) ? address(vault1) : address(vault2);

            vm.prank(who);
            // if paused or allowlist blocks, this may revert; invariants still must hold
            try reg.registerNode(meta, v) {} catch {}
        }

        function actionRemove(uint256 callerSeed, uint256 nodeSeed) external {
            uint256 id = _anyNodeId(nodeSeed);
            if (reg.nextNodeId() == 0) return;

            GlassNodeRegistry.Node memory n;
            try reg.getNode(id) returns (GlassNodeRegistry.Node memory nn) {
                n = nn;
            } catch {
                return;
            }

            // pick either operator or random (50/50)
            address caller = (callerSeed % 2 == 0) ? n.operator : _pickEOA(callerSeed);
            vm.assume(caller != address(0));
            vm.assume(caller.code.length == 0);

            vm.prank(caller);
            try reg.removeNode(id) {} catch {}
        }

        function actionUpdateNode(uint256 callerSeed, uint256 nodeSeed, string calldata meta, bool active) external {
            uint256 id = _anyNodeId(nodeSeed);
            if (reg.nextNodeId() == 0) return;

            GlassNodeRegistry.Node memory n;
            try reg.getNode(id) returns (GlassNodeRegistry.Node memory nn) {
                n = nn;
            } catch {
                return;
            }

            address caller = (callerSeed % 2 == 0) ? n.operator : _pickEOA(callerSeed);
            vm.assume(caller != address(0));
            vm.assume(caller.code.length == 0);

            vm.prank(caller);
            try reg.updateNode(id, meta, active) {} catch {}
        }

        function actionRotateOperator(uint256 callerSeed, uint256 nodeSeed, uint256 newOpSeed) external {
            uint256 id = _anyNodeId(nodeSeed);
            if (reg.nextNodeId() == 0) return;

            GlassNodeRegistry.Node memory n;
            try reg.getNode(id) returns (GlassNodeRegistry.Node memory nn) {
                n = nn;
            } catch {
                return;
            }

            address caller = (callerSeed % 2 == 0) ? n.operator : _pickEOA(callerSeed);
            address newOp = _pickEOA(newOpSeed);

            vm.assume(caller != address(0) && newOp != address(0));
            vm.assume(caller.code.length == 0 && newOp.code.length == 0);

            vm.prank(caller);
            try reg.rotateOperator(id, newOp) {} catch {}
        }

        function actionSetPaymentVault(uint256 callerSeed, uint256 nodeSeed, uint256 vaultSeed) external {
            uint256 id = _anyNodeId(nodeSeed);
            if (reg.nextNodeId() == 0) return;

            GlassNodeRegistry.Node memory n;
            try reg.getNode(id) returns (GlassNodeRegistry.Node memory nn) {
                n = nn;
            } catch {
                return;
            }

            address caller = (callerSeed % 2 == 0) ? n.operator : _pickEOA(callerSeed);
            address v = (vaultSeed % 2 == 0) ? address(vault1) : address(vault2);

            vm.assume(caller != address(0));
            vm.assume(caller.code.length == 0);

            vm.prank(caller);
            try reg.setPaymentVault(id, v) {} catch {}
        }

        function actionSetModelPrice(
            uint256 callerSeed,
            uint256 nodeSeed,
            uint256 modelSeed,
            uint256 tokenSeed,
            uint256 priceSeed
        ) external {
            uint256 id = _anyNodeId(nodeSeed);
            if (reg.nextNodeId() == 0) return;

            GlassNodeRegistry.Node memory n;
            try reg.getNode(id) returns (GlassNodeRegistry.Node memory nn) {
                n = nn;
            } catch {
                return;
            }

            address caller = (callerSeed % 3 == 0) ? n.operator : _pickEOA(callerSeed);
            vm.assume(caller != address(0));
            vm.assume(caller.code.length == 0);

            bytes32 modelId = (modelSeed % 2 == 0) ? mA : mB;
            address payTok = (tokenSeed % 2 == 0) ? address(pay1) : address(pay2);

            uint256 price = priceSeed % (1_000e18);
            // allow price == 0 to exercise removal paths

            vm.prank(caller);
            try reg.setModelPrice(id, modelId, payTok, price) {} catch {}
        }

        // Optional admin actions. If your rewrite added these roles, keep them.
        function actionPauseUnpause(uint256 seed) external {
            bool doPause = (seed % 2 == 0);
            vm.prank(admin);
            if (doPause) {
                try reg.pause() {} catch {}
            } else {
                try reg.unpause() {} catch {}
            }
        }

        function actionSetMinStake(uint256 seed) external {
            uint256 newStake = (seed % 1_000e18) + 1; // never 0
            vm.prank(admin);
            try reg.setMinStake(newStake) {
                minStake = newStake;
            } catch {}
        }
    }

    contract GlassNodeRegistryFuzz is StdInvariant, Test {
        GlassNodeRegistry reg;
        MockERC20 stake;
        MockERC20 pay1;
        MockERC20 pay2;
        MockVault vault1;
        MockVault vault2;

        RegistryHandler handler;

        address admin = address(0xA11CE);
        uint256 minStake = 100e18;

        function setUp() public {
            stake = new MockERC20();
            pay1 = new MockERC20();
            pay2 = new MockERC20();
            vault1 = new MockVault();
            vault2 = new MockVault();

            reg = new GlassNodeRegistry(admin, address(stake), minStake);

            handler = new RegistryHandler(reg, stake, pay1, pay2, vault1, vault2, admin, minStake);

            targetContract(address(handler));
        }

        // ---------------- invariants ----------------

        /// Invariant: registry stake token balance == sum(stakedAmount for all nodes)
        function invariant_registryStakeMatchesSum() public view {
            uint256 n = reg.nextNodeId();
            uint256 sum;
            for (uint256 i = 0; i < n; i++) {
                sum += reg.stakedAmount(i);
            }
            assertEq(stake.balanceOf(address(reg)), sum);
        }

        /// Invariant: for every active node, stakedAmount >= minStake at time of registration.
        /// (We can only check nonzero stake implies node exists; exact minStake at reg time is not stored.)
        function invariant_nonzeroStakeImpliesNodeExists() public view {
            uint256 n = reg.nextNodeId();
            for (uint256 i = 0; i < n; i++) {
                if (reg.stakedAmount(i) > 0) {
                    // getNode must not revert for any i < nextNodeId
                    GlassNodeRegistry.Node memory node = reg.getNode(i);
                    // operator must be nonzero for any existing node
                    assertTrue(node.operator != address(0));
                }
            }
        }

        /// Invariant: node models list contains no duplicates.
        function invariant_noDuplicateModelsPerNode() public view {
            uint256 n = reg.nextNodeId();
            for (uint256 i = 0; i < n; i++) {
                bytes32[] memory models = reg.getNodeModels(i);
                for (uint256 a = 0; a < models.length; a++) {
                    for (uint256 b = a + 1; b < models.length; b++) {
                        assertTrue(models[a] != models[b]);
                    }
                }
            }
        }
    }

