// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ConsistencyProof} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {
    consistentRootsForSizes
} from "@univocity/algorithms/consistentRoots.sol";

/// @notice Run the consistency proof chain from initial accumulator (memory).
///    Caller supplies pre-decoded proof payloads (calldata). Caller must copy
///    storage accumulator to memory before calling.
///
///    Every proof is folded from the accumulator it follows: the initial
///    state for the first, the previous proof's output thereafter. The
///    declared base of each proof must be the size of that accumulator, each
///    proof must grow the tree to a complete MMR size, and the paths must
///    have the lengths the two sizes imply (the draft's SHOULD).
///    The draft's consistent_roots alone checks only peak counts, which
///    many sizes share, and hashes whatever path length it is given;
///    without the size and shape checks a proof could re-home the anchored
///    peaks at heights and positions the log never had, or re-anchor an
///    unchanged accumulator at an inflated size (FOR-567 and follow-ups).
///    consistentRootsForSizes enforces the shape in the same pass as the
///    hashing. An empty log is size 0 with no peaks; a first checkpoint is
///    just the base-0 case of the same fold.
/// @param initialAccumulator Peaks of the log state (tree-size before first
///    proof). Must be memory (copy from storage in caller if needed).
/// @param initialSize Node count committed by initialAccumulator (0 when the
///    log holds nothing yet).
/// @param decodedProofs Pre-decoded consistency proof payloads (order
///    preserved). Passed as calldata; no copy of proof material.
/// @return finalAccumulator Peaks after applying all proofs (memory). The
///    proven tree size is the last proof's treeSize2; caller should use that
///    for grant bounds and state update.
function verifyConsistencyProofChain(
    bytes32[] memory initialAccumulator,
    uint64 initialSize,
    ConsistencyProof[] calldata decodedProofs
) pure returns (bytes32[] memory finalAccumulator) {
    uint256 n = decodedProofs.length;
    if (n == 0) {
        return new bytes32[](0);
    }

    bytes32[] memory accMem = initialAccumulator;
    uint64 sizeFrom = initialSize;

    for (uint256 idx = 0; idx < n; idx++) {
        ConsistencyProof calldata p = decodedProofs[idx];

        if (p.treeSize1 != sizeFrom) {
            revert IUnivocityErrors.ConsistencyBaseMismatch(
                sizeFrom, p.treeSize1
            );
        }
        if (p.treeSize2 <= p.treeSize1) {
            revert IUnivocityErrors.InvalidConsistencyProof();
        }

        (bytes32[] memory roots, uint256 expectedRight) =
            consistentRootsForSizes(p.treeSize1, p.treeSize2, accMem, p.paths);
        if (p.rightPeaks.length != expectedRight) {
            revert IUnivocityErrors.ConsistencyPeakCountMismatch(
                expectedRight, p.rightPeaks.length
            );
        }
        accMem = _concatAccumulator(roots, p.rightPeaks);
        sizeFrom = p.treeSize2;
    }

    return accMem;
}

/// @notice Build the detached payload for consistency receipt signature
///    verification. Draft-bryce (ADR-0046): "use the consistent accumulator
///    as the detached payload" — the raw concatenation of the accumulator
///    peaks, in descending height order, matching the draft's inclusion-
///    receipt raw-value convention. No hashing: the Sig_structure is hashed
///    whole for verification.
/// @param accumulator Peak hashes (MMR accumulator), descending height order.
/// @return detachedPayload Raw concatenation of the peaks (32 bytes each).
function buildDetachedPayloadCommitment(bytes32[] memory accumulator)
    pure
    returns (bytes memory detachedPayload)
{
    detachedPayload = abi.encodePacked(accumulator);
}

/// @notice MMR profile: verify a series of pre-decoded consistency proofs per
///    draft "Verifying the Receipt of consistency". No CBOR decode on-chain.
///    Aligns with algorithms as free functions (consistentRoots, includedRoot).

/// @notice Concat roots then rightPeaks into one accumulator.
function _concatAccumulator(
    bytes32[] memory roots,
    bytes32[] calldata rightPeaks
) pure returns (bytes32[] memory out) {
    out = new bytes32[](roots.length + rightPeaks.length);
    for (uint256 i = 0; i < roots.length; i++) {
        out[i] = roots[i];
    }
    for (uint256 j = 0; j < rightPeaks.length; j++) {
        out[roots.length + j] = rightPeaks[j];
    }
}

