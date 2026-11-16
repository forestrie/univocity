// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {
    IUnivocityVerifierFactory
} from "@univocity/interfaces/IUnivocityVerifierFactory.sol";
import {UnivocityVerifier} from "@univocity/contracts/UnivocityVerifier.sol";
import {
    LibUnivocityVerifierAddress
} from "@univocity/verifier/lib/LibUnivocityVerifierAddress.sol";

/// @title UnivocityVerifierFactory
/// @notice Permissionless CREATE2 factory of UnivocityVerifier, one per
///    instance, at an address any contract derives from the factory, its
///    init-code hash and the instance (devdocs ARC-0032 section 4.2).
///    Nobody can name a wrong verifier for an instance: the address is a
///    function of the factory, the creation code and the instance.
/// @dev A verifier deployed for an address that is not a univocity instance
///    only weakens delegations that name it.
contract UnivocityVerifierFactory is IUnivocityVerifierFactory {
    /// @inheritdoc IUnivocityVerifierFactory
    bytes32 public immutable verifierInitCodeHash;

    /// @dev Plain storage, set only for the duration of deploy.
    address private _building;

    /// @notice Records the verifier creation code hash.
    constructor() {
        verifierInitCodeHash = keccak256(type(UnivocityVerifier).creationCode);
    }

    /// @inheritdoc IUnivocityVerifierFactory
    function deploy(address instance) external returns (address verifier) {
        if (instance == address(0)) revert ZeroInstance();
        verifier = verifierFor(instance);
        if (verifier.code.length != 0) return verifier;
        _building = instance;
        address deployed = address(
            new UnivocityVerifier{
                salt: LibUnivocityVerifierAddress.salt(instance)
            }()
        );
        delete _building;
        if (deployed != verifier) revert VerifierAddressMismatch();
        emit VerifierDeployed(instance, verifier);
    }

    /// @inheritdoc IUnivocityVerifierFactory
    function verifierFor(address instance) public view returns (address) {
        return LibUnivocityVerifierAddress.verifierAddress(
            address(this), verifierInitCodeHash, instance
        );
    }

    /// @inheritdoc IUnivocityVerifierFactory
    function building() external view returns (address) {
        return _building;
    }
}
