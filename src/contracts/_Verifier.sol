// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {
    IUnivocityVerifier
} from "@univocity/interfaces/IUnivocityVerifier.sol";
import {LogState} from "@univocity/interfaces/types.sol";
import {LibLogState} from "@univocity/algorithms/lib/LibLogState.sol";

/// @title _Verifier
/// @notice Abstract base for read-only MMR inclusion verification against a
///    univocal log state source (plan 0016 / draft-bryce-cose-receipts-
///    mmr-profile). Implementers must override _univocal() to return the
///    IUnivocal instance to use.
/// @dev Fetches LogState via _univocal().logState(logId), then delegates to
///    LibLogState. Returns false for non-inclusion or invalid inputs (e.g.
///    uninitialized log with size 0). Its one entry point is
///    IUnivocityVerifier's verifyInclusionAtAnchored, the leaf check the
///    publication enforcer consumes.
abstract contract _Verifier is IUnivocityVerifier {
    using LibLogState for LogState;

    /// @inheritdoc IUnivocityVerifier
    /// @dev The witness-age rule: a path built at the anchored size or
    ///    later still proves the leaf and needs no re-signing or
    ///    re-fetching (includedRoot.verifyInclusionAtSize). A path built
    ///    before a checkpoint that merged the leaf's peak is refused and
    ///    must be extended from public log data (ARC-0032 section 4.2).
    function verifyInclusionAtAnchored(
        bytes32 logId,
        uint256 index,
        bytes32 leaf,
        bytes32[] calldata path
    ) external view virtual returns (bool) {
        LogState memory log = _univocal().logState(logId);
        return log.verifyInclusionAtAnchored(index, leaf, path);
    }

    /// @notice Returns the univocal instance whose log state is used for
    ///    verification. Must be overridden by the implementation.
    /// @return The IUnivocal contract exposing logState(logId).
    function _univocal() internal view virtual returns (IUnivocal);
}
