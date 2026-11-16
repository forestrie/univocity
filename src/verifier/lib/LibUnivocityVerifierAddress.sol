// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title LibUnivocityVerifierAddress
/// @notice The CREATE2 address of an instance's verifier, derived from the
///    instance alone (devdocs ARC-0032 section 4.2). The factory deploys at
///    it and the publication enforcer computes it, so neither stores or
///    looks it up.
library LibUnivocityVerifierAddress {
    /// @notice The CREATE2 salt for an instance's verifier.
    /// @param instance The univocity instance.
    /// @return The instance address, left-padded to 32 bytes.
    function salt(address instance) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(instance)));
    }

    /// @notice The address `factory` deploys the verifier of `instance` at.
    /// @param factory The UnivocityVerifierFactory.
    /// @param initCodeHash keccak256 of the verifier's creation code, as
    ///    the factory's verifierInitCodeHash reports.
    /// @param instance The univocity instance.
    /// @return The verifier's address; it may not have code yet.
    function verifierAddress(
        address factory,
        bytes32 initCodeHash,
        address instance
    ) internal pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), factory, salt(instance), initCodeHash
                        )
                    )
                )
            )
        );
    }
}
