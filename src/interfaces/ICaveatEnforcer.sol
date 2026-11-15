// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title ICaveatEnforcer
/// @notice ABI copy of the MetaMask Delegation Framework v1.3.0
///    ICaveatEnforcer (ERC-7710 caveat hooks), so univocity can implement an
///    enforcer without importing the framework, whose sources pin solc
///    0.8.23. The delegation manager calls hooks only through the ABI.
///    Upstream `ModeCode` is a user-defined value type over bytes32, so
///    `bytes32 mode` gives the same selectors (devdocs ARC-0032 §4.1).
/// @dev The manager calls beforeAllHook (leaf to root), then per delegation
///    beforeHook, the execution, afterHook, then afterAllHook. A revert in
///    any hook reverts the whole redemption.
///    https://github.com/MetaMask/delegation-framework/blob/v1.3.0/src/interfaces/ICaveatEnforcer.sol
interface ICaveatEnforcer {
    /// @notice Runs before any execution in a batch redemption.
    /// @param terms Delegator-signed terms of the caveat.
    /// @param args Redeemer-supplied arguments; unsigned and untrusted.
    /// @param mode ERC-7579 execution mode of executionCallData.
    /// @param executionCallData The execution the redemption performs.
    /// @param delegationHash EIP-712 struct hash of this delegation.
    /// @param delegator The delegation's delegator.
    /// @param redeemer The account that called redeemDelegations.
    function beforeAllHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 mode,
        bytes calldata executionCallData,
        bytes32 delegationHash,
        address delegator,
        address redeemer
    ) external;

    /// @notice Runs before the execution this delegation authorises.
    /// @dev Parameters as beforeAllHook.
    function beforeHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 mode,
        bytes calldata executionCallData,
        bytes32 delegationHash,
        address delegator,
        address redeemer
    ) external;

    /// @notice Runs after the execution this delegation authorises.
    /// @dev Parameters as beforeAllHook.
    function afterHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 mode,
        bytes calldata executionCallData,
        bytes32 delegationHash,
        address delegator,
        address redeemer
    ) external;

    /// @notice Runs after every execution in a batch redemption.
    /// @dev Parameters as beforeAllHook.
    function afterAllHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 mode,
        bytes calldata executionCallData,
        bytes32 delegationHash,
        address delegator,
        address redeemer
    ) external;
}
