// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ImutableVerifier} from "@univocity/contracts/ImutableVerifier.sol";
import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {
    IUnivocityVerifierFactory
} from "@univocity/interfaces/IUnivocityVerifierFactory.sol";

/// @title ProvisionalVerifierFactory
/// @notice Test-only spike stand-in for the CREATE2 UnivocityVerifierFactory of
///    devdocs ARC-0032 §4.2: one ImutableVerifier per instance, recorded
///    by the factory that built it, so nobody can name a wrong verifier.
///    The production factory derives the address instead of storing it,
///    which saves the enforcer a storage read; the interface is the same.
/// @dev Permissionless and idempotent. A verifier built for an address that
///    is not a univocity instance only weakens delegations that name it.
contract ProvisionalVerifierFactory is IUnivocityVerifierFactory {
    mapping(address instance => address verifier) private _verifiers;

    /// @notice Emitted once per instance, when its verifier is built.
    /// @param instance The univocity instance.
    /// @param verifier The verifier reading that instance's log state.
    event VerifierDeployed(address indexed instance, address verifier);

    /// @notice Builds the verifier for `instance`, or returns the one built
    ///    before.
    /// @param instance The univocity instance whose logState it reads.
    /// @return verifier The instance's verifier.
    function deploy(address instance) external returns (address verifier) {
        verifier = _verifiers[instance];
        if (verifier != address(0)) return verifier;
        verifier = address(new ImutableVerifier(IUnivocal(instance)));
        _verifiers[instance] = verifier;
        emit VerifierDeployed(instance, verifier);
    }

    /// @inheritdoc IUnivocityVerifierFactory
    function verifierFor(address instance) external view returns (address) {
        return _verifiers[instance];
    }
}
