# Glass AI Node Registry Smart Contract

This repo contains the Glass AI Node Registry smart contract and its Foundry project setup. The registry lets inference-node operators register nodes with a payment vault, stake collateral, and publish per-model, per-token pricing.

---

## What this contract does (high level)

A **Node** is a record with:

* operator address (can be rotated)
* payment vault address (must be a contract, non-zero)
* metadata URI (off-chain JSON / endpoint info)
* active flag (soft-delete / pausing)

Nodes must stake `minStake` of `stakeToken` on registration. When a node is removed, the full stake is returned to the current operator.

Each node can advertise multiple models, and each model can be priced in multiple ERC-20 payment tokens. Setting a model price to 0 for a given payment token removes that token-price; if the last token-price is removed, the model is removed from that node.

---

## Repo layout

* src/GlassNodeRegistry.sol
  Main contract.
* script/GlassNodeRegistry.s.sol (or similar)
  Deployment script using env vars prefixed with `REG_`.
* test/
  Foundry test suite.
* foundry.toml
  Foundry configuration (solc version, remappings, etc.).

---

## Prerequisites

You’ll need Foundry installed:

curl -L [https://foundry.paradigm.xyz](https://foundry.paradigm.xyz) | bash
foundryup

OpenZeppelin contracts are pulled via remappings. If you’re missing deps:

forge install OpenZeppelin/openzeppelin-contracts --no-commit

---

## Build

forge build

---

## Test

forge test

Useful flags:

forge test -vvv
forge test --match-test testRegisterNode
forge test --gas-report

---

## Deploy

Deployment is done through the script `DeployRegistry.s.sol` and requires three env vars, all prefixed with `REG_`:

* REG_ADMIN
  Address that receives DEFAULT_ADMIN_ROLE.
* REG_STAKE_TOKEN
  ERC-20 token address used for staking.
* REG_MIN_STAKE
  Minimum stake amount in token base units (e.g., for 18-decimals tokens, “100e18”).

Optional:

* REG_PRIVATE_KEY
  Broadcaster key if you want the script to auto-select it. If you omit this, pass `--private-key` or `--mnemonic` directly to forge.

### Example: deploy to a live network

export REG_ADMIN=0xYourAdminAddress
export REG_STAKE_TOKEN=0xYourStakeToken
export REG_MIN_STAKE=100000000000000000000
export REG_PRIVATE_KEY=0xYOUR_PRIVATE_KEY

forge script script/GlassNodeRegistry.s.sol:GlassNodeRegistryDeployScript
--rpc-url [https://your.rpc.url](https://your.rpc.url)
--broadcast
-vvv

The script will revert if any required env var is missing or zero.

### Example: deploy to Anvil

Terminal 1:

anvil

Terminal 2 (Anvil’s default first key works):

export REG_ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
export REG_STAKE_TOKEN=0xYourMockOrDeployedToken
export REG_MIN_STAKE=100e18
export REG_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

forge script script/GlassNodeRegistry.s.sol:GlassNodeRegistryDeployScript
--rpc-url [http://127.0.0.1:8545](http://127.0.0.1:8545)
--broadcast
-vvv

---

## Help

Foundry docs: [https://book.getfoundry.sh/](https://book.getfoundry.sh/)
Common commands:

forge --help
cast --help
anvil --help
