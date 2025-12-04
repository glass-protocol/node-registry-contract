// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
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

    function approve(
        address spender,
        uint256 amt
    ) public virtual override returns (bool) {
        allowance[msg.sender][spender] = amt;
        emit Approval(msg.sender, spender, amt);
        return true;
    }

    function transfer(
        address to,
        uint256 amt
    ) public virtual override returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amt
    ) public virtual override returns (bool) {
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

contract MaliciousReenterERC20 is MockERC20 {
    GlassNodeRegistry public registry;
    address public vault;
    bool public armedRegister;
    bool public armedRemove;

    function setTarget(GlassNodeRegistry r, address v) external {
        registry = r;
        vault = v;
    }

    function armRegister(bool v) external {
        armedRegister = v;
    }
    function armRemove(bool v) external {
        armedRemove = v;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amt
    ) public override returns (bool) {
        if (armedRegister) {
            registry.registerNode("reenter", vault);
        }
        return super.transferFrom(from, to, amt);
    }

    function transfer(address to, uint256 amt) public override returns (bool) {
        if (armedRemove) {
            registry.removeNode(0);
        }
        return super.transfer(to, amt);
    }
}

contract MockVault {}

contract GlassNodeRegistryTest is Test {
    GlassNodeRegistry reg;
    MockERC20 stake;
    MockERC20 pay1;
    MockERC20 pay2;
    MockVault vault1;
    MockVault vault2;

    address admin = address(0xA11CE);
    address op1 = address(0xB0B);
    address op2 = address(0xCAFE);
    address rand = address(0xD00D);

    uint256 minStake = 100e18;
    bytes32 mA = keccak256("modelA");
    bytes32 mB = keccak256("modelB");

    bytes4 constant REENTRANCY_ERR =
        bytes4(keccak256("ReentrancyGuardReentrantCall()"));

    function setUp() public {
        stake = new MockERC20();
        pay1 = new MockERC20();
        pay2 = new MockERC20();
        vault1 = new MockVault();
        vault2 = new MockVault();

        reg = new GlassNodeRegistry(admin, address(stake), minStake);

        stake.mint(op1, 1_000e18);
        stake.mint(op2, 1_000e18);

        vm.prank(op1);
        stake.approve(address(reg), type(uint256).max);
        vm.prank(op2);
        stake.approve(address(reg), type(uint256).max);
    }

    function _makeNode(address who, address v) internal returns (uint256) {
        vm.prank(who);
        return reg.registerNode("meta", v);
    }

    // -------- constructor --------

    function test_constructor_sets_state_and_admin_role() public view {
        assertEq(reg.minStake(), minStake);
        assertEq(reg.stakeToken(), address(stake));
        assertTrue(reg.hasRole(reg.ADMIN_ROLE(), admin));
    }

    function test_constructor_revert_minStake_zero() public {
        vm.expectRevert(GlassNodeRegistry.MinStakeNotSet.selector);
        new GlassNodeRegistry(admin, address(stake), 0);
    }

    function test_constructor_revert_stakeToken_zero_or_eoa() public {
        vm.expectRevert(GlassNodeRegistry.InvalidStakeToken.selector);
        new GlassNodeRegistry(admin, address(0), minStake);

        vm.expectRevert(GlassNodeRegistry.InvalidStakeToken.selector);
        new GlassNodeRegistry(admin, address(0x1234), minStake);
    }

    function test_constructor_revert_admin_zero() public {
        vm.expectRevert(GlassNodeRegistry.InvalidAddress.selector);
        new GlassNodeRegistry(address(0), address(stake), minStake);
    }

    // -------- allowlist --------

    function test_allowlist_only_admin_and_effective() public {
        vm.prank(rand);
        vm.expectRevert();
        reg.setAllowlistEnabled(true);

        vm.prank(admin);
        reg.setAllowlistEnabled(true);
        assertTrue(reg.allowlistEnabled());

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.NotAllowedRegistrant.selector);
        reg.registerNode("x", address(vault1));

        vm.prank(admin);
        reg.setAllowedRegistrant(op1, true);

        vm.prank(op1);
        reg.registerNode("x", address(vault1));
    }

    // -------- registerNode --------

    function test_registerNode_success_stakes_and_emits() public {
        uint256 balBefore = stake.balanceOf(op1);

        vm.prank(op1);
        vm.expectEmit(true, true, true, true);
        emit GlassNodeRegistry.NodeRegistered(
            0,
            op1,
            address(vault1),
            "meta",
            minStake
        );
        uint256 id = reg.registerNode("meta", address(vault1));

        assertEq(id, 0);
        assertEq(reg.nextNodeId(), 1);

        GlassNodeRegistry.Node memory n = reg.getNode(0);
        assertEq(n.operator, op1);
        assertEq(n.paymentVault, address(vault1));
        assertEq(n.metadataURI, "meta");
        assertTrue(n.active);

        assertEq(reg.stakedAmount(0), minStake);
        assertEq(stake.balanceOf(op1), balBefore - minStake);
        assertEq(stake.balanceOf(address(reg)), minStake);
    }

    function test_registerNode_revert_invalid_vault() public {
        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.InvalidAddress.selector);
        reg.registerNode("m", address(0));

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.NotAContract.selector);
        reg.registerNode("m", address(0x1234));
    }

    function test_registerNode_nonReentrant_blocks_reentry() public {
        MaliciousReenterERC20 evil = new MaliciousReenterERC20();
        MockVault v = new MockVault();
        GlassNodeRegistry r2 = new GlassNodeRegistry(
            admin,
            address(evil),
            minStake
        );

        evil.mint(op1, 1_000e18);
        vm.prank(op1);
        evil.approve(address(r2), type(uint256).max);

        evil.setTarget(r2, address(v));
        evil.armRegister(true);

        vm.prank(op1);
        vm.expectRevert(REENTRANCY_ERR);
        r2.registerNode("m", address(v));
    }

    // -------- updateNode --------

    function test_updateNode_operator_or_admin() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectEmit(true, false, false, true);
        emit GlassNodeRegistry.NodeUpdated(id, "new", false);
        reg.updateNode(id, "new", false);

        GlassNodeRegistry.Node memory n = reg.getNode(id);
        assertEq(n.metadataURI, "new");
        assertFalse(n.active);

        vm.prank(admin);
        reg.updateNode(id, "admin", true);
        n = reg.getNode(id);
        assertEq(n.metadataURI, "admin");
        assertTrue(n.active);
    }

    function test_updateNode_revert_not_authorized_or_invalid_node() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(rand);
        vm.expectRevert(GlassNodeRegistry.NotAuthorized.selector);
        reg.updateNode(id, "x", true);

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.InvalidNode.selector);
        reg.updateNode(999, "x", true);
    }

    // -------- removeNode --------

    function test_removeNode_refunds_and_inactivates() public {
        uint256 id = _makeNode(op1, address(vault1));
        uint256 balBefore = stake.balanceOf(op1);

        vm.prank(op1);
        vm.expectEmit(true, true, false, true);
        emit GlassNodeRegistry.NodeRemoved(id, op1, minStake);
        reg.removeNode(id);

        GlassNodeRegistry.Node memory n = reg.getNode(id);
        assertFalse(n.active);
        assertEq(reg.stakedAmount(id), 0);
        assertEq(stake.balanceOf(op1), balBefore + minStake);
        assertEq(stake.balanceOf(address(reg)), 0);
    }

    function test_removeNode_revert_already_inactive() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.removeNode(id);

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.AlreadyInactive.selector);
        reg.removeNode(id);
    }

    function test_removeNode_nonReentrant_blocks_reentry() public {
        MaliciousReenterERC20 evil = new MaliciousReenterERC20();
        MockVault v = new MockVault();
        GlassNodeRegistry r2 = new GlassNodeRegistry(
            admin,
            address(evil),
            minStake
        );

        evil.mint(op1, 1_000e18);
        vm.prank(op1);
        evil.approve(address(r2), type(uint256).max);

        vm.prank(op1);
        r2.registerNode("m", address(v));

        evil.setTarget(r2, address(v));
        evil.armRemove(true);

        vm.prank(op1);
        vm.expectRevert(REENTRANCY_ERR);
        r2.removeNode(0);
    }

    // -------- rotateOperator --------

    function test_rotateOperator_by_operator_or_admin() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectEmit(true, true, true, true);
        emit GlassNodeRegistry.OperatorRotated(id, op1, op2);
        reg.rotateOperator(id, op2);
        assertEq(reg.getNode(id).operator, op2);

        vm.prank(admin);
        reg.rotateOperator(id, op1);
        assertEq(reg.getNode(id).operator, op1);
    }

    function test_rotateOperator_revert_bad_caller_or_zero_new() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(rand);
        vm.expectRevert(GlassNodeRegistry.NotAuthorized.selector);
        reg.rotateOperator(id, op2);

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.InvalidAddress.selector);
        reg.rotateOperator(id, address(0));
    }

    // -------- setPaymentVault --------

    function test_setPaymentVault_success() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectEmit(true, true, true, true);
        emit GlassNodeRegistry.PaymentVaultUpdated(
            id,
            address(vault1),
            address(vault2)
        );
        reg.setPaymentVault(id, address(vault2));
        assertEq(reg.getNode(id).paymentVault, address(vault2));
    }

    function test_setPaymentVault_revert_zero_or_eoa_or_unauth() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.InvalidAddress.selector);
        reg.setPaymentVault(id, address(0));

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.NotAContract.selector);
        reg.setPaymentVault(id, address(0x1234));

        vm.prank(rand);
        vm.expectRevert(GlassNodeRegistry.NotAuthorized.selector);
        reg.setPaymentVault(id, address(vault2));
    }

    // -------- models / pricing --------

    function test_setModelPrice_adds_model_and_token() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectEmit(true, true, false, true);
        emit GlassNodeRegistry.ModelAdded(id, mA);
        vm.expectEmit(true, true, true, true);
        emit GlassNodeRegistry.ModelPriceUpdatedForToken(
            id,
            mA,
            address(pay1),
            10
        );
        reg.setModelPrice(id, mA, address(pay1), 10);

        bytes32[] memory models = reg.getNodeModels(id);
        assertEq(models.length, 1);
        assertEq(models[0], mA);

        address[] memory tokens = reg.getModelPriceTokens(id, mA);
        assertEq(tokens.length, 1);
        assertEq(tokens[0], address(pay1));

        assertEq(reg.getModelPrice(id, mA, address(pay1)), 10);
    }

    function test_setModelPrice_add_second_token_no_dup_model() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 10);

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay2), 20);

        assertEq(reg.getNodeModels(id).length, 1);

        address[] memory tokens = reg.getModelPriceTokens(id, mA);
        assertEq(tokens.length, 2);
        assertEq(tokens[0], address(pay1));
        assertEq(tokens[1], address(pay2));
    }

    function test_setModelPrice_update_existing_no_dup_token() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 10);

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 15);

        address[] memory tokens = reg.getModelPriceTokens(id, mA);
        assertEq(tokens.length, 1);
        assertEq(reg.getModelPrice(id, mA, address(pay1)), 15);
    }

    function test_setModelPrice_zero_removes_token_only() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 10);
        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay2), 20);

        vm.prank(op1);
        vm.expectEmit(true, true, true, true);
        emit GlassNodeRegistry.ModelPriceUpdatedForToken(
            id,
            mA,
            address(pay1),
            0
        );
        reg.setModelPrice(id, mA, address(pay1), 0);

        address[] memory tokens = reg.getModelPriceTokens(id, mA);
        assertEq(tokens.length, 1);
        assertEq(tokens[0], address(pay2));
        assertEq(reg.getModelPrice(id, mA, address(pay1)), 0);
    }

    function test_setModelPrice_zero_last_token_removes_model() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 10);

        vm.prank(op1);
        vm.expectEmit(true, true, false, true);
        emit GlassNodeRegistry.ModelRemoved(id, mA);
        reg.setModelPrice(id, mA, address(pay1), 0);

        assertEq(reg.getNodeModels(id).length, 0);
        assertEq(reg.getModelPriceTokens(id, mA).length, 0);
    }

    function test_removeModel_removes_all_prices_and_model() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 10);
        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay2), 20);

        vm.prank(op1);
        vm.expectEmit(true, true, false, true);
        emit GlassNodeRegistry.ModelRemoved(id, mA);
        reg.removeModel(id, mA);

        assertEq(reg.getNodeModels(id).length, 0);
        assertEq(reg.getModelPrice(id, mA, address(pay1)), 0);
        assertEq(reg.getModelPrice(id, mA, address(pay2)), 0);
        assertEq(reg.getModelPriceTokens(id, mA).length, 0);
    }

    function test_removeModel_revert_if_missing() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.ModelNotFound.selector);
        reg.removeModel(id, mA);
    }

    function test_setModelPrice_revert_payToken_zero_or_unauth_or_invalid_node()
        public
    {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.InvalidAddress.selector);
        reg.setModelPrice(id, mA, address(0), 1);

        vm.prank(rand);
        vm.expectRevert(GlassNodeRegistry.NotAuthorized.selector);
        reg.setModelPrice(id, mA, address(pay1), 1);

        vm.prank(op1);
        vm.expectRevert(GlassNodeRegistry.InvalidNode.selector);
        reg.setModelPrice(999, mA, address(pay1), 1);
    }

    function test_multiple_models_independent_enumeration() public {
        uint256 id = _makeNode(op1, address(vault1));

        vm.prank(op1);
        reg.setModelPrice(id, mA, address(pay1), 10);
        vm.prank(op1);
        reg.setModelPrice(id, mB, address(pay1), 30);

        bytes32[] memory models = reg.getNodeModels(id);
        assertEq(models.length, 2);
        assertEq(models[0], mA);
        assertEq(models[1], mB);
    }

    // -------- admin / minStake --------

    function test_setAdmin_only_admin_and_transfers_role() public {
        vm.prank(rand);
        vm.expectRevert();
        reg.setAdmin(op1);

        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit GlassNodeRegistry.AdminChanged(admin, op1);
        reg.setAdmin(op1);

        assertTrue(reg.hasRole(reg.ADMIN_ROLE(), op1));
        assertFalse(reg.hasRole(reg.ADMIN_ROLE(), admin));
    }

    function test_setAdmin_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(GlassNodeRegistry.InvalidAddress.selector);
        reg.setAdmin(address(0));
    }

    function test_setMinStake_only_admin_and_nonzero() public {
        vm.prank(rand);
        vm.expectRevert();
        reg.setMinStake(1);

        vm.prank(admin);
        vm.expectRevert(GlassNodeRegistry.MinStakeNotSet.selector);
        reg.setMinStake(0);

        vm.prank(admin);
        reg.setMinStake(55);
        assertEq(reg.minStake(), 55);
    }

    // -------- view reverts --------

    function test_view_reverts_on_invalid_node() public {
        vm.expectRevert(GlassNodeRegistry.InvalidNode.selector);
        reg.getNode(0);

        vm.expectRevert(GlassNodeRegistry.InvalidNode.selector);
        reg.getNodeModels(0);

        vm.expectRevert(GlassNodeRegistry.InvalidNode.selector);
        reg.getModelPrice(0, mA, address(pay1));

        vm.expectRevert(GlassNodeRegistry.InvalidNode.selector);
        reg.getModelPriceTokens(0, mA);
    }
}
