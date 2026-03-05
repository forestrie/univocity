// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {
    InclusionProof,
    LogState,
    PublishGrant
} from "@univocity/interfaces/Types.sol";
import {LibLogState} from "@univocity/algorithms/lib/LibLogState.sol";

/// @title _Verifier
/// @notice Abstract base for read-only MMR inclusion verification against a
///    univocal log state source (plan 0016 / draft-bryce-cose-receipts-
///    mmr-profile). Implementers must override _univocal() to return the
///    IUnivocal instance to use.
/// @dev Fetches LogState via _univocal().logState(logId), then delegates to
///    LibLogState. Returns false for non-inclusion or invalid inputs (e.g.
///    uninitialized log with size 0).
abstract contract _Verifier {
    using LibLogState for LogState;

    /// @notice Returns the univocal instance whose log state is used for
    ///    verification. Must be overridden by the implementation.
    /// @return The IUnivocal contract exposing logState(logId).
    function _univocal() internal view virtual returns (IUnivocal);

    /// @notice Verifies that a node is included in the MMR committed to by
    ///    the log identified by logId.
    /// @param logId Identifier of the log whose accumulator and size are
    ///    used (from _univocal().logState(logId)).
    /// @param index Zero-based MMR index of the node.
    /// @param node Hash of the node whose inclusion is proven (e.g. leaf
    ///    commitment or receipt hash).
    /// @param proof Sibling hashes on the path from the node to the
    ///    committing peak (same semantics as includedRoot.verifyInclusion).
    /// @return True if the computed root from (index, node, proof) matches
    ///    the corresponding peak in the log's accumulator; false otherwise
    ///    (e.g. wrong proof, uninitialized log, or index out of range).
    function verifyInclusion(
        bytes32 logId,
        uint256 index,
        bytes32 node,
        bytes32[] calldata proof
    ) external view returns (bool) {
        LogState memory log = _univocal().logState(logId);
        return log.verifyInclusion(index, node, proof);
    }

    /// @notice Verifies that the grant leaf (commitment from publishGrant and
    ///    grantIDTimestampBe) is included in the MMR for the given log.
    /// @param logId Identifier of the log whose accumulator and size are
    ///    used (from _univocal().logState(logId)).
    /// @param publishGrant Grant used to compute the leaf commitment (same
    ///    formula as Univocity: H(grantIDTimestampBe ‖ H(logId, grant, …))).
    /// @param grantIDTimestampBe Big-endian idtimestamp of the grant content.
    /// @param inclusionProof Index and path for the inclusion proof.
    /// @return True if the grant leaf is included in the log's MMR; false
    ///    otherwise.
    function verifyGrantInclusion(
        bytes32 logId,
        PublishGrant calldata publishGrant,
        bytes8 grantIDTimestampBe,
        InclusionProof calldata inclusionProof
    ) external view returns (bool) {
        LogState memory log = _univocal().logState(logId);
        return log.verifyGrantInclusion(
            publishGrant,
            grantIDTimestampBe,
            inclusionProof.index,
            inclusionProof.path
        );
    }
}
