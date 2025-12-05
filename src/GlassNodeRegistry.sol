// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract GlassNodeRegistry is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // ============================================
    // ROLES
    // ============================================
    /// @notice Super-admin role (inherits from DEFAULT_ADMIN_ROLE)
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    /// @notice Can enable/disable allowlist and manage registrants
    bytes32 public constant ALLOWLIST_ROLE = keccak256("ALLOWLIST_ROLE");

    /// @notice Can update staking configuration (minStake)
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");

    /// @notice Can pause/unpause the registry in emergencies
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ============================================
    // TYPES
    // ============================================
    struct Node {
        address operator;
        address paymentVault;
        string metadataURI;
        bool active;
    }

    struct NodeSummary {
        Node node;
        uint256 stake;
    }

    struct ModelInfo {
        bytes32 modelId;
        address[] payTokens;
        uint256[] prices; // aligned with payTokens
    }

    struct NodeFullState {
        Node node;
        uint256 stake;
        ModelInfo[] models;
    }

    // ============================================
    // STATE
    // ============================================

    // nodes by id
    mapping(uint256 => Node) private _nodes;
    uint256 private _nextNodeId;

    // per-node stake
    mapping(uint256 => uint256) public stakedAmount;

    // price per model per payment token
    mapping(uint256 => mapping(bytes32 => mapping(address => uint256))) public modelPricePerToken;

    // enumerate payment tokens per model for each node
    mapping(uint256 => mapping(bytes32 => address[])) private _modelPayTokens;
    mapping(uint256 => mapping(bytes32 => mapping(address => uint256))) private _modelPayTokenIndex; // index+1

    mapping(uint256 => bytes32[]) private _nodeModels;
    mapping(uint256 => mapping(bytes32 => uint256)) private _nodeModelIndex; // index+1

    // allowlist
    bool public allowlistEnabled;
    mapping(address => bool) public isAllowedRegistrant;

    // staking config
    address public immutable stakeToken;
    uint256 public minStake;

    // ============================================
    // ERRORS
    // ============================================
    error InvalidAddress();
    error NotAContract();
    error NotAuthorized();
    error NotAllowedRegistrant();
    error InvalidNode();
    error AlreadyInactive();
    error StakeTokenNotSet();
    error MinStakeNotSet();
    error InvalidStakeToken();
    error ModelNotFound();

    // ============================================
    // EVENTS
    // ============================================
    event NodeRegistered(
        uint256 indexed nodeId,
        address indexed operator,
        address indexed paymentVault,
        string metadataURI,
        uint256 stakedAmount
    );
    event NodeUpdated(uint256 indexed nodeId, string metadataURI, bool active);
    event NodeRemoved(uint256 indexed nodeId, address indexed refundedTo, uint256 refundedAmount);

    event OperatorRotated(uint256 indexed nodeId, address indexed oldOp, address indexed newOp);
    event PaymentVaultUpdated(uint256 indexed nodeId, address indexed oldVault, address indexed newVault);

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event AllowlistStatusChanged(bool enabled);
    event AllowlistUpdated(address indexed registrant, bool allowed);

    event MinStakeUpdated(uint256 oldMinStake, uint256 newMinStake);

    event ModelAdded(uint256 indexed nodeId, bytes32 indexed modelId);
    event ModelPriceUpdatedForToken(
        uint256 indexed nodeId, bytes32 indexed modelId, address indexed payToken, uint256 price
    );
    event ModelRemoved(uint256 indexed nodeId, bytes32 indexed modelId);

    // ============================================
    // CONSTRUCTOR
    // ============================================
    constructor(address admin_, address stakeToken_, uint256 minStake_) {
        if (minStake_ == 0) revert MinStakeNotSet();
        if (stakeToken_ == address(0)) revert InvalidStakeToken();
        if (stakeToken_.code.length == 0) revert InvalidStakeToken();
        if (admin_ == address(0)) revert InvalidAddress();

        // Super admin
        _grantRole(ADMIN_ROLE, admin_);

        // Operational roles initially assigned to the same address
        _grantRole(ALLOWLIST_ROLE, admin_);
        _grantRole(CONFIG_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);

        stakeToken = stakeToken_;
        minStake = minStake_;
    }

    // ============================================
    // MODIFIERS
    // ============================================
    modifier onlyOperatorOrAdmin(uint256 nodeId) {
        _onlyOperatorOrAdmin(nodeId);
        _;
    }

    function _onlyOperatorOrAdmin(uint256 nodeId) internal view {
        if (!_exists(nodeId)) revert InvalidNode();
        if (msg.sender != _nodes[nodeId].operator && !hasRole(ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized();
        }
    }

    // ============================================
    // NODE MANAGEMENT
    // ============================================

    /// @notice Register a new node controlled by the caller.
    /// @dev Requires a `paymentVault` that is a contract, allowlist compliance if enabled,
    ///      and an ERC-20 stake transfer of exactly `minStake` `stakeToken` from caller to registry.
    /// @param metadataURI Arbitrary metadata for the node (endpoint/region/JSON/etc.).
    /// @param paymentVault Address of the payment channel vault contract for this node.
    /// @return nodeId The newly assigned node id.
    function registerNode(string calldata metadataURI, address paymentVault)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 nodeId)
    {
        // Best effort to ensure the paymentVault is a smartContract, and hopefully implements IPaymentChannelVault
        if (paymentVault == address(0)) revert InvalidAddress();
        if (paymentVault.code.length == 0) revert NotAContract();

        if (allowlistEnabled && !isAllowedRegistrant[msg.sender]) {
            revert NotAllowedRegistrant();
        }

        nodeId = _nextNodeId++;
        _nodes[nodeId] =
            Node({operator: msg.sender, paymentVault: paymentVault, metadataURI: metadataURI, active: true});
        stakedAmount[nodeId] = minStake;

        // transfer stake
        IERC20(stakeToken).safeTransferFrom(msg.sender, address(this), minStake);

        emit NodeRegistered(nodeId, msg.sender, paymentVault, metadataURI, minStake);
    }

    /// @notice Update a node’s metadata and/or active flag.
    /// @dev Callable by current node operator or ADMIN_ROLE.
    ///      Does not move stake; setting `active=false` is a soft-disable only.
    /// @param nodeId Id of the node to update.
    /// @param metadataURI New metadata string.
    /// @param active New active status.
    function updateNode(uint256 nodeId, string calldata metadataURI, bool active) external onlyOperatorOrAdmin(nodeId) {
        Node storage n = _nodes[nodeId];
        n.metadataURI = metadataURI;
        n.active = active;

        emit NodeUpdated(nodeId, metadataURI, active);
    }

    /// @notice Remove (deactivate) a node and refund its full stake.
    /// @dev Callable by operator or admin. Marks node inactive, zeroes `stakedAmount`,
    ///      and transfers refund to the *current* operator.
    ///      Uses nonReentrant around the ERC-20 refund transfer.
    /// @param nodeId Id of the node to remove.
    function removeNode(uint256 nodeId) external nonReentrant whenNotPaused onlyOperatorOrAdmin(nodeId) {
        Node storage n = _nodes[nodeId];
        if (!n.active) revert AlreadyInactive();

        n.active = false;

        uint256 refund = stakedAmount[nodeId];
        stakedAmount[nodeId] = 0;

        if (refund > 0) {
            IERC20(stakeToken).safeTransfer(n.operator, refund);
        }

        emit NodeRemoved(nodeId, n.operator, refund);
    }

    // ============================================
    // OPERATOR / VAULT UPDATES
    // ============================================

    /// @notice Rotate the operator key for a node.
    /// @dev Callable by operator or admin. Does not affect stake or models.
    /// @param nodeId Id of the node.
    /// @param newOperator New operator address.
    function rotateOperator(uint256 nodeId, address newOperator) external onlyOperatorOrAdmin(nodeId) {
        if (newOperator == address(0)) revert InvalidAddress();
        Node storage n = _nodes[nodeId];

        address old = n.operator;
        n.operator = newOperator;

        emit OperatorRotated(nodeId, old, newOperator);
    }

    /// @notice Update the payment vault address for a node.
    /// @dev Callable by operator or admin. Vault must be non-zero and a contract.
    /// @param nodeId Id of the node.
    /// @param newVault New payment vault address.
    function setPaymentVault(uint256 nodeId, address newVault) external onlyOperatorOrAdmin(nodeId) {
        // Best effort to ensure the vault is a smart contract.
        if (newVault == address(0)) revert InvalidAddress();
        if (newVault.code.length == 0) revert NotAContract();

        Node storage n = _nodes[nodeId];

        address old = n.paymentVault;
        n.paymentVault = newVault;

        emit PaymentVaultUpdated(nodeId, old, newVault);
    }

    // ============================================
    // MODEL & PRICING
    // ============================================

    /// @notice Add or update a model price for a specific payment token.
    /// @dev Callable by operator or admin.
    ///      - If `price > 0`: sets/updates price, adds model and/or payToken to enumerations if new.
    ///      - If `price == 0`: removes only this `payToken` price; if it was the last token,
    ///        the model is removed from enumeration.
    /// @param nodeId Id of the node.
    /// @param modelId Model identifier (bytes32).
    /// @param payToken ERC-20 token address used for payments.
    /// @param price Price per token for `modelId` in `payToken` units.
    function setModelPrice(uint256 nodeId, bytes32 modelId, address payToken, uint256 price)
        external
        onlyOperatorOrAdmin(nodeId)
    {
        if (payToken == address(0)) revert InvalidAddress();

        // if price==0, remove price for that payToken only
        if (price == 0) {
            _removeModelPriceToken(nodeId, modelId, payToken);
            emit ModelPriceUpdatedForToken(nodeId, modelId, payToken, 0);
            return;
        }

        // add model to node enumeration if new (same as before)
        if (_nodeModelIndex[nodeId][modelId] == 0) {
            _nodeModels[nodeId].push(modelId);
            _nodeModelIndex[nodeId][modelId] = _nodeModels[nodeId].length;
            emit ModelAdded(nodeId, modelId);
        }

        // add payToken to model enumeration if new
        if (_modelPayTokenIndex[nodeId][modelId][payToken] == 0) {
            _modelPayTokens[nodeId][modelId].push(payToken);
            _modelPayTokenIndex[nodeId][modelId][payToken] = _modelPayTokens[nodeId][modelId].length;
        }

        modelPricePerToken[nodeId][modelId][payToken] = price;
        emit ModelPriceUpdatedForToken(nodeId, modelId, payToken, price);
    }

    /// @notice Remove a model entirely (all payment tokens/prices).
    /// @dev Callable by operator or admin. Removes all prices and model enumeration entry.
    /// @param nodeId Id of the node.
    /// @param modelId Model identifier to remove.
    function removeModel(uint256 nodeId, bytes32 modelId) external onlyOperatorOrAdmin(nodeId) {
        uint256 idxPlusOne = _nodeModelIndex[nodeId][modelId];
        if (idxPlusOne == 0) revert ModelNotFound();

        _removeModelAllPrices(nodeId, modelId);
    }

    /// @notice Get all models a node currently supports.
    /// @param nodeId Id of the node.
    /// @return models Array of model ids.
    function getNodeModels(uint256 nodeId) external view returns (bytes32[] memory models) {
        if (!_exists(nodeId)) revert InvalidNode();
        return _nodeModels[nodeId];
    }

    /// @notice Get the price for a model when paying with a specific token.
    /// @param nodeId Id of the node.
    /// @param modelId Model identifier.
    /// @param payToken Payment token address.
    /// @return price Stored per-token price (0 if unset).
    function getModelPrice(uint256 nodeId, bytes32 modelId, address payToken) external view returns (uint256 price) {
        if (!_exists(nodeId)) revert InvalidNode();
        return modelPricePerToken[nodeId][modelId][payToken];
    }

    /// @notice Returns all payment tokens this node supports for a given model.
    /// @param nodeId Id of the node.
    /// @param modelId Model identifier.
    /// @return payTokens Array of ERC-20 token addresses accepted for the model.
    function getModelPriceTokens(uint256 nodeId, bytes32 modelId) external view returns (address[] memory payTokens) {
        if (!_exists(nodeId)) revert InvalidNode();
        return _modelPayTokens[nodeId][modelId];
    }

    // ============================================
    // ALLOWLIST (ALLOWLIST_ROLE)
    // ============================================

    /// @notice Enable or disable allowlist enforcement for node registration.
    /// @dev `ALLOWLIST_ROLE` only. When enabled, only `isAllowedRegistrant[addr]=true`
    ///      can call `registerNode`.
    /// @param enabled New allowlist status.
    function setAllowlistEnabled(bool enabled) external onlyRole(ALLOWLIST_ROLE) {
        allowlistEnabled = enabled;
        emit AllowlistStatusChanged(enabled);
    }

    /// @notice Set (or clear) an address as an allowed registrant.
    /// @dev `ALLOWLIST_ROLE` only. Has no effect if allowlist is disabled.
    /// @param registrant Address to update.
    /// @param allowed Whether the address may register nodes while allowlist is enabled.
    function setAllowedRegistrant(address registrant, bool allowed) external onlyRole(ALLOWLIST_ROLE) {
        if (registrant == address(0)) revert InvalidAddress();
        isAllowedRegistrant[registrant] = allowed;
        emit AllowlistUpdated(registrant, allowed);
    }

    // ============================================
    // ADMIN & STAKING CONFIG
    // ============================================

    /// @notice Transfer admin privileges (and operational roles) to a new address.
    /// @dev `ADMIN_ROLE` only. Grants all roles to `newAdmin` and revokes them from caller.
    /// @param newAdmin Address to receive admin and ops roles.
    function setAdmin(address newAdmin) external onlyRole(ADMIN_ROLE) {
        if (newAdmin == address(0)) revert InvalidAddress();
        address old = msg.sender;

        // grant new
        _grantRole(ADMIN_ROLE, newAdmin);
        _grantRole(ALLOWLIST_ROLE, newAdmin);
        _grantRole(CONFIG_ROLE, newAdmin);
        _grantRole(PAUSER_ROLE, newAdmin);

        // revoke from old
        _revokeRole(ADMIN_ROLE, old);
        _revokeRole(ALLOWLIST_ROLE, old);
        _revokeRole(CONFIG_ROLE, old);
        _revokeRole(PAUSER_ROLE, old);

        emit AdminChanged(old, newAdmin);
    }

    /// @notice Update the global minimum stake required for new node registrations.
    /// @dev `CONFIG_ROLE` only. Does not retroactively change stake on existing nodes.
    /// @param newMinStake New required stake amount.
    function setMinStake(uint256 newMinStake) external onlyRole(CONFIG_ROLE) {
        if (newMinStake == 0) revert MinStakeNotSet();
        uint256 old = minStake;
        minStake = newMinStake;
        emit MinStakeUpdated(old, newMinStake);
    }

    // ============================================
    // PAUSING (PAUSER_ROLE)
    // ============================================

    /// @notice Pause state-changing operations on the registry.
    /// @dev `PAUSER_ROLE` only. Affects functions with `whenNotPaused`.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the registry.
    /// @dev `PAUSER_ROLE` only.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ============================================
    // VIEWS
    // ============================================

    /// @notice Fetch a node by id.
    /// @param nodeId Id of the node.
    /// @return node The node struct (operator, paymentVault, metadataURI, active).
    function getNode(uint256 nodeId) external view returns (Node memory node) {
        if (!_exists(nodeId)) revert InvalidNode();
        return _nodes[nodeId];
    }

    /// @notice Get the next node id that will be assigned on registration.
    /// @return id The next node id (also equals total nodes ever registered).
    function nextNodeId() external view returns (uint256 id) {
        return _nextNodeId;
    }

    /// @notice Total number of nodes ever registered (including inactive).
    function totalNodes() external view returns (uint256) {
        return _nextNodeId;
    }

    /// @notice Returns a summary for every node (node struct + stake).
    /// @dev Intended for off-chain monitoring; can be expensive onchain.
    function getAllNodes() external view returns (NodeSummary[] memory out) {
        uint256 n = _nextNodeId;
        out = new NodeSummary[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = NodeSummary({node: _nodes[i], stake: stakedAmount[i]});
        }
    }

    /// @notice Returns the full state of a node: Node struct, stake, models, pay tokens, prices.
    /// @dev Intended for off-chain monitoring; can be expensive onchain.
    function getNodeFullState(uint256 nodeId) external view returns (NodeFullState memory state) {
        if (!_exists(nodeId)) revert InvalidNode();

        bytes32[] storage models = _nodeModels[nodeId];
        ModelInfo[] memory infos = new ModelInfo[](models.length);

        for (uint256 i = 0; i < models.length; i++) {
            bytes32 m = models[i];
            address[] storage tokens = _modelPayTokens[nodeId][m];

            uint256[] memory ps = new uint256[](tokens.length);
            for (uint256 j = 0; j < tokens.length; j++) {
                ps[j] = modelPricePerToken[nodeId][m][tokens[j]];
            }

            infos[i] = ModelInfo({modelId: m, payTokens: tokens, prices: ps});
        }

        state = NodeFullState({node: _nodes[nodeId], stake: stakedAmount[nodeId], models: infos});
    }

    // ============================================
    // INTERNALS
    // ============================================

    function _exists(uint256 nodeId) internal view returns (bool) {
        return nodeId < _nextNodeId;
    }

    function _removeModel(uint256 nodeId, bytes32 modelId) internal {
        uint256 idxPlusOne = _nodeModelIndex[nodeId][modelId];
        if (idxPlusOne == 0) {
            // already absent
            return;
        }

        uint256 idx = idxPlusOne - 1;
        uint256 lastIdx = _nodeModels[nodeId].length - 1;

        if (idx != lastIdx) {
            bytes32 lastModel = _nodeModels[nodeId][lastIdx];
            _nodeModels[nodeId][idx] = lastModel;
            _nodeModelIndex[nodeId][lastModel] = idx + 1;
        }

        _nodeModels[nodeId].pop();
        delete _nodeModelIndex[nodeId][modelId];

        // clear pay-token enumeration array for this model (prices already cleared per token)
        delete _modelPayTokens[nodeId][modelId];
    }

    function _removeModelPriceToken(uint256 nodeId, bytes32 modelId, address payToken) internal {
        uint256 idxPlusOne = _modelPayTokenIndex[nodeId][modelId][payToken];
        if (idxPlusOne == 0) {
            modelPricePerToken[nodeId][modelId][payToken] = 0;
            return;
        }

        uint256 idx = idxPlusOne - 1;
        uint256 lastIdx = _modelPayTokens[nodeId][modelId].length - 1;

        if (idx != lastIdx) {
            address lastToken = _modelPayTokens[nodeId][modelId][lastIdx];
            _modelPayTokens[nodeId][modelId][idx] = lastToken;
            _modelPayTokenIndex[nodeId][modelId][lastToken] = idx + 1;
        }

        _modelPayTokens[nodeId][modelId].pop();
        delete _modelPayTokenIndex[nodeId][modelId][payToken];
        modelPricePerToken[nodeId][modelId][payToken] = 0;

        // if that was the last payToken, also remove the model itself
        if (_modelPayTokens[nodeId][modelId].length == 0) {
            _removeModel(nodeId, modelId);
            emit ModelRemoved(nodeId, modelId);
        }
    }

    function _removeModelAllPrices(uint256 nodeId, bytes32 modelId) internal {
        address[] storage tokens = _modelPayTokens[nodeId][modelId];
        for (uint256 i = tokens.length; i > 0; i--) {
            address t = tokens[i - 1];
            // this will pop from tokens, so always take last
            _removeModelPriceToken(nodeId, modelId, t);
        }
    }
}
