// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    IUnivocityVerifier
} from "@univocity/interfaces/IUnivocityVerifier.sol";
import {
    IUnivocityVerifierFactory
} from "@univocity/interfaces/IUnivocityVerifierFactory.sol";
import {LogState} from "@univocity/interfaces/types.sol";
import {_Verifier} from "@univocity/contracts/_Verifier.sol";
import {verifyInclusionAtPeak} from "@univocity/algorithms/includedRoot.sol";
import {LibLogState} from "@univocity/algorithms/lib/LibLogState.sol";

/// @title UnivocityVerifier
/// @notice The one inclusion verifier of a univocity instance, deployed by
///    UnivocityVerifierFactory at an address derived from the instance
///    (devdocs ARC-0032 section 4.2). Takes no constructor arguments: the
///    instance is read from the deploying factory, so the creation code is
///    the same for every instance.
/// @dev verifyInclusionAtAnchored reads only the leaf's committing peak
///    through the instance's committingPeak getter, and falls back to
///    logState on instances without it. Both feed the same single-peak
///    check (includedRoot.verifyInclusionAtPeak).
contract UnivocityVerifier is _Verifier {
    using LibLogState for LogState;

    /// @notice The factory read no instance to build a verifier for.
    error NoInstance();

    /// @notice The univocity instance this verifier reads.
    address public immutable instance;

    /// @notice Reads the instance from the deploying factory
    ///    (IUnivocityVerifierFactory.building); reverts if there is none.
    constructor() {
        address inst = IUnivocityVerifierFactory(msg.sender).building();
        if (inst == address(0)) revert NoInstance();
        instance = inst;
    }

    /// @inheritdoc _Verifier
    /// @dev Calls committingPeak with a low-level staticcall and uses the
    ///    answer only if the call succeeded and returned exactly two words;
    ///    otherwise (an instance without the getter) it reads logState.
    function verifyInclusionAtAnchored(
        bytes32 logId,
        uint256 index,
        bytes32 leaf,
        bytes32[] calldata path
    ) external view override returns (bool) {
        uint64 size;
        bytes32 peak;
        (bool ok, bytes memory ret) = instance.staticcall(
            abi.encodeCall(IUnivocity.committingPeak, (logId, index))
        );
        if (ok && ret.length == 64) {
            (size, peak) = abi.decode(ret, (uint64, bytes32));
        } else {
            (size, peak) =
                IUnivocal(instance).logState(logId).committingPeak(index);
        }
        if (size == 0) return false;
        return verifyInclusionAtPeak(index, leaf, path, peak, size);
    }

    /// @inheritdoc _Verifier
    function _univocal() internal view override returns (IUnivocal) {
        return IUnivocal(instance);
    }
}
