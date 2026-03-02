// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {LogState} from "@univocity/interfaces/Types.sol";
import {
    verifyInclusion as verifyInclusionAlgo
} from "@univocity/algorithms/includedRoot.sol";

/// @title Verifier
/// @notice Read-only contract that verifies MMR inclusion proofs against a
///    single univocal log state source (plan 0016 / draft-bryce-cose-receipts-
///    mmr-profile). Use when you need to check that a node is included in a
///    log's accumulator without calling the full Univocity contract.
/// @dev Fetches LogState (accumulator, size) from the configured IUnivocal,
///    then delegates to the pure verifyInclusion algorithm. Returns false for
///    non-inclusion or invalid inputs (e.g. uninitialized log with size 0).
contract Verifier {
    /// @notice The univocal instance whose log state is used for verification.
    IUnivocal public immutable univocal;

    /// @notice Sets the univocal log state source.
    /// @param _univocal Contract exposing logState(logId); must return
    ///    accumulator and size for the log identified by logId.
    constructor(IUnivocal _univocal) {
        univocal = _univocal;
    }

    /// @notice Verifies that a node is included in the MMR committed to by
    ///    the log identified by logId.
    /// @param logId Identifier of the log whose accumulator and size are
    ///    used (from univocal.logState(logId)).
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
        LogState memory log = univocal.logState(logId);
        return
            verifyInclusionAlgo(index, node, proof, log.accumulator, log.size);
    }
}
