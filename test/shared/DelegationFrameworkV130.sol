// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// TEST-ONLY. ABI copies of the MetaMask Delegation Framework v1.3.0 types
// and entry points the fork tests call, and the framework's deterministic
// v1.3.0 addresses (documents/Deployments.md, the same on every chain it
// lists, Base Sepolia included). Like src/interfaces/ICaveatEnforcer.sol
// these copy the ABI instead of importing sources that pin solc 0.8.23;
// ModeCode is bytes32.
// https://github.com/MetaMask/delegation-framework/blob/v1.3.0/documents/Deployments.md

struct Caveat {
    address enforcer;
    bytes terms;
    bytes args;
}

struct Delegation {
    address delegate;
    address delegator;
    bytes32 authority;
    Caveat[] caveats;
    uint256 salt;
    bytes signature;
}

/// @notice LogicalOrWrapperEnforcer terms: one group per alternative.
struct CaveatGroup {
    Caveat[] caveats;
}

/// @notice LogicalOrWrapperEnforcer args: the group the redeemer picks.
struct SelectedGroup {
    uint256 groupIndex;
    bytes[] caveatArgs;
}

interface IDelegationManagerV130 {
    event RedeemedDelegation(
        address indexed rootDelegator,
        address indexed redeemer,
        Delegation delegation
    );

    error CannotUseADisabledDelegation();

    function redeemDelegations(
        bytes[] calldata permissionContexts,
        bytes32[] calldata modes,
        bytes[] calldata executionCallDatas
    ) external;

    function disableDelegation(Delegation calldata delegation) external;

    function disabledDelegations(bytes32 delegationHash)
        external
        view
        returns (bool);

    function getDelegationHash(Delegation calldata delegation)
        external
        pure
        returns (bytes32);

    function getDomainHash() external view returns (bytes32);

    function VERSION() external view returns (string memory);
}

interface IHybridDeleGatorV130 {
    function initialize(
        address owner,
        string[] calldata keyIds,
        uint256[] calldata xValues,
        uint256[] calldata yValues
    ) external;
}

/// @notice Circle FiatToken (USDC) calls the fork tests need.
interface IUsdc {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    function balanceOf(address account) external view returns (uint256);
    function masterMinter() external view returns (address);
    function configureMinter(address minter, uint256 allowance)
        external
        returns (bool);
    function mint(address to, uint256 amount) external returns (bool);
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;
}

library FrameworkV130 {
    bytes32 internal constant ROOT_AUTHORITY =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    address internal constant ANY_DELEGATE = address(0xa11);
    bytes32 internal constant SINGLE_DEFAULT_MODE = bytes32(0);

    address internal constant DELEGATION_MANAGER =
        0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3;
    address internal constant HYBRID_DELEGATOR_IMPL =
        0x48dBe696A4D990079e039489bA2053B36E8FFEC4;
    address internal constant ALLOWED_CALLDATA_ENFORCER =
        0xc2b0d624c1c4319760C96503BA27C347F3260f55;
    address internal constant ERC20_TRANSFER_AMOUNT_ENFORCER =
        0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc;
    address internal constant EXACT_EXECUTION_ENFORCER =
        0x146713078D39eCC1F5338309c28405ccf85Abfbb;
    address internal constant LIMITED_CALLS_ENFORCER =
        0x04658B29F6b82ed55274221a06Fc97D318E25416;
    address internal constant LOGICAL_OR_WRAPPER_ENFORCER =
        0xE1302607a3251AF54c3a6e69318d6aa07F5eB46c;
    address internal constant REDEEMER_ENFORCER =
        0xE144b0b2618071B4E56f746313528a669c7E65c5;
    address internal constant TIMESTAMP_ENFORCER =
        0x1046bb45C8d673d4ea75321280DB34899413c069;

    /// @notice Circle USDC on Base Sepolia (chain 84532).
    address internal constant BASE_SEPOLIA_USDC =
        0x036CbD53842c5426634e7929541eC2318f3dCF7e;
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
}
