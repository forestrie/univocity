// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {_Verifier} from "@univocity/contracts/_Verifier.sol";

/// @title ImutableVerifier
/// @notice Concrete verifier that fixes the univocal instance at
///    construction. Uses the constructor initialise pattern; implements
///    _univocal() by returning the immutable reference.
contract ImutableVerifier is _Verifier {
    /// @notice The univocal instance whose log state is used for verification.
    IUnivocal public immutable univocal;

    /// @notice Sets the univocal log state source.
    /// @param univocal_ Contract exposing logState(logId); must return
    ///    accumulator and size for the log identified by logId.
    constructor(IUnivocal univocal_) {
        univocal = univocal_;
    }

    /// @inheritdoc _Verifier
    function _univocal() internal view override returns (IUnivocal) {
        return univocal;
    }
}
