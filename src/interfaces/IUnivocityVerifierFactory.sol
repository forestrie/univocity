// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityVerifierFactory
/// @notice Finds the one inclusion verifier of a univocity instance, so the
///    publication enforcer is never told which verifier to trust
///    (devdocs ARC-0032 §4.2).
interface IUnivocityVerifierFactory {
    /// @notice The verifier for `instance`, or an address without code when
    ///    none is deployed yet.
    /// @param instance The univocity instance a hop's terms name.
    /// @return The verifier's address.
    function verifierFor(address instance) external view returns (address);
}
