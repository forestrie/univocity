// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityVerifierFactory
/// @notice Deploys and locates the one inclusion verifier of a univocity
///    instance, at an address derived from the instance alone, so the
///    publication enforcer is never told which verifier to trust
///    (devdocs ARC-0032 section 4.2).
interface IUnivocityVerifierFactory {
    /// @notice Emitted once per instance, when its verifier is deployed.
    /// @param instance The univocity instance.
    /// @param verifier The verifier reading that instance.
    event VerifierDeployed(address indexed instance, address indexed verifier);

    /// @notice A verifier deployed somewhere other than its derived address.
    error VerifierAddressMismatch();

    /// @notice Deploys the verifier of `instance`, or returns the one
    ///    deployed before. Permissionless and idempotent.
    /// @dev Does not check that `instance` has code: a verifier deployed
    ///    before its instance exists is harmless.
    /// @param instance The univocity instance the verifier reads.
    /// @return verifier The instance's verifier.
    function deploy(address instance) external returns (address verifier);

    /// @notice The verifier address of `instance`, computed, not stored.
    /// @param instance The univocity instance.
    /// @return The derived address; it has no code until deploy is called.
    function verifierFor(address instance) external view returns (address);

    /// @notice keccak256 of the verifier creation code the factory deploys.
    /// @return The hash a CREATE2 derivation of verifier addresses needs.
    function verifierInitCodeHash() external view returns (bytes32);

    /// @notice The instance whose verifier is being deployed; zero outside
    ///    deploy. The verifier's constructor reads it.
    /// @return The instance under construction.
    function building() external view returns (address);
}
