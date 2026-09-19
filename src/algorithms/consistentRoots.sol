// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Consistency between two MMR states, per draft-bryce-cose-receipts-mmr-profile
// "Verifying the Receipt of consistency", with the proof shape the two sizes
// imply enforced in the same pass (the draft's SHOULD on path lengths). For a
// complete MMR the set bits of peaksBitmap(size) are the peak heights in
// accumulator order, so the fold iterates that bitmap directly: no peak index
// list, and no bookkeeping per hop beyond the hash itself.

import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {
    mmrSizeForLeafCount,
    peaksBitmap
} from "@univocity/algorithms/peaks.sol";
import {bitLength, popcount64} from "@univocity/algorithms/binUtils.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

/// @notice Fold the peaks of MMR(sizeFrom) into the peaks of MMR(sizeTo) that
///    commit them, requiring the proof to have exactly the shape the two
///    sizes imply.
///
///    Let `split` be the highest bit on which the two peaks bitmaps differ.
///    As sizeTo > sizeFrom the target has it and the origin does not. An
///    origin peak above `split` is still a peak of the target: its path is
///    empty and it is carried unchanged. Every origin peak below `split` is
///    committed by the single target peak of height `split`: its path has
///    length split - h, and all of them must fold to the same value. The
///    target's remaining peaks lie below every origin peak, so they are new
///    material the prover supplies as rightPeaks; their count is returned.
///
///    Only the target size must be complete: the origin is anchored state,
///    and every anchored size was itself a checked target.
/// @param sizeFrom Node count of the origin state (0 for an empty log).
/// @param sizeTo Node count of the target state; caller ensures > sizeFrom.
/// @param accumulatorFrom Peaks of MMR(sizeFrom), descending height.
/// @param proofs One path per origin peak, in the same order (calldata).
/// @return roots Peaks of MMR(sizeTo) that commit origin peaks, descending
///    height: the unchanged peaks, then the one merged root if any.
/// @return expectedRight Number of MMR(sizeTo) peaks the prover must supply
///    as rightPeaks.
function consistentRootsForSizes(
    uint64 sizeFrom,
    uint64 sizeTo,
    bytes32[] memory accumulatorFrom,
    bytes32[][] calldata proofs
) pure returns (bytes32[] memory roots, uint256 expectedRight) {
    uint256 to = peaksBitmap(sizeTo);
    // peaksBitmap rounds an incomplete size down to the largest MMR below
    // it, so `to` describes MMR(sizeTo) only if sizeTo is complete. Without
    // this a target such as 6 anchors an accumulator that is no MMR's, and a
    // verifier later reads its entries at the wrong heights.
    if (mmrSizeForLeafCount(to) != sizeTo) {
        revert IUnivocityErrors.IncompleteTreeSize(sizeTo);
    }
    uint256 from = peaksBitmap(sizeFrom);
    uint256 n = popcount64(from);
    if (accumulatorFrom.length != n) {
        revert IUnivocityErrors.ConsistencyPeakCountMismatch(
            n, accumulatorFrom.length
        );
    }
    if (proofs.length != n) {
        revert IUnivocityErrors.ConsistencyPeakCountMismatch(n, proofs.length);
    }
    if (n == 0) {
        return (new bytes32[](0), popcount64(to));
    }

    uint256 split = bitLength(from ^ to) - 1;
    roots = new bytes32[](n);
    uint256 count;
    bool merged;
    // Nodes preceding the current origin peak's subtree; a peak of height h
    // sits at offset + 2^(h+1) - 2 and its subtree has 2^(h+1) - 1 nodes.
    uint256 offset;
    uint256 i;
    for (uint256 h = bitLength(from); h > 0;) {
        h--;
        if ((from >> h) & 1 == 0) continue;
        uint256 subtree = (uint256(1) << (h + 1)) - 1;
        uint256 expected = h > split ? 0 : split - h;
        if (proofs[i].length != expected) {
            revert IUnivocityErrors.ConsistencyPathLengthMismatch(
                i, expected, proofs[i].length
            );
        }
        if (h > split) {
            // Still a peak of the target; the empty path is the identity.
            roots[count++] = accumulatorFrom[i];
        } else {
            bytes32 root = includedRoot(
                offset + subtree - 1, accumulatorFrom[i], proofs[i]
            );
            if (!merged) {
                roots[count++] = root;
                merged = true;
            } else if (roots[count - 1] != root) {
                revert IUnivocityErrors.ConsistencyRootMismatch(i);
            }
        }
        offset += subtree;
        i++;
    }
    assembly {
        mstore(roots, count)
    }
    expectedRight = popcount64(to) - count;
}
