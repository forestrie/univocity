// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Consistency between two MMR states, per draft-bryce-cose-receipts-mmr-profile
// "Verifying the Receipt of consistency", with the proof shape the two sizes
// imply enforced in the same pass (the draft's SHOULD on path lengths). For a
// complete MMR the set bits of peaksBitmap(size) are the peak heights in
// accumulator order, so verification iterates that bitmap directly: no peak
// index list, and no bookkeeping per hop beyond the hash itself.

import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {
    mmrSizeForLeafCount,
    peaksBitmap
} from "@univocity/algorithms/peaks.sol";
import {bitLength, popcount64} from "@univocity/algorithms/binUtils.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

/// @notice Produce the peaks of MMR(sizeTo) that the proofs prove from the
///    peaks of MMR(sizeFrom), requiring the proofs to have exactly the shape
///    the two sizes imply.
///
///    Let `split` be the highest bit on which the two peaks bitmaps differ.
///    As sizeTo > sizeFrom the target has it and the origin does not. An
///    origin peak above `split` is also a peak of the target: its path is
///    empty and it is returned unchanged. Every origin peak below `split`
///    is committed by the target peak of height `split`: its path has
///    length split - h, and every such path must prove the same root. The
///    target's remaining peaks lie below every origin peak, so no proof
///    reaches them; the prover supplies them as rightPeaks, and their count
///    is returned.
///
///    Only the target size must be complete: the origin is anchored state,
///    and every anchored size was itself a checked target.
/// @param sizeFrom Node count of the origin state (0 for an empty log).
/// @param sizeTo Node count of the target state; caller ensures > sizeFrom.
/// @param accumulatorFrom Peaks of MMR(sizeFrom), descending height.
/// @param proofs One path per origin peak, in the same order (calldata).
/// @return roots The peaks of MMR(sizeTo) proven from the origin peaks, in
///    descending height: the unchanged peaks, then the one proven root if
///    any.
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
    // Nodes preceding the current origin peak's subtree; a peak of height h
    // sits at offset + 2^(h+1) - 2 and its subtree has 2^(h+1) - 1 nodes.
    uint256 offset;
    uint256 i;

    // Origin peaks above the split are also peaks of the target. The path
    // is not read; requiring it to be empty rejects unused material (shape,
    // not safety).
    uint256 h = bitLength(from);
    for (; h > split + 1;) {
        h--;
        if ((from >> h) & 1 == 0) continue;
        if (proofs[i].length != 0) {
            revert IUnivocityErrors.ConsistencyPathLengthMismatch(
                i, 0, proofs[i].length
            );
        }
        roots[count++] = accumulatorFrom[i];
        offset += (uint256(1) << (h + 1)) - 1;
        i++;
    }

    // Origin peaks below the split are all committed by the target peak of
    // height `split` (bit `split` itself is clear in `from`), so each path
    // must have length split - h and every path must prove the same root.
    // `above` peaks were carried and i == above at the first peak below.
    uint256 above = count;
    bytes32 root;
    for (h = split; h > 0;) {
        h--;
        if ((from >> h) & 1 == 0) continue;
        uint256 expected = split - h;
        if (proofs[i].length != expected) {
            revert IUnivocityErrors.ConsistencyPathLengthMismatch(
                i, expected, proofs[i].length
            );
        }
        uint256 subtree = (uint256(1) << (h + 1)) - 1;
        bytes32 proven =
            includedRoot(offset + subtree - 1, accumulatorFrom[i], proofs[i]);
        if (i == above) {
            root = proven;
        } else if (proven != root) {
            revert IUnivocityErrors.ConsistencyRootMismatch(i);
        }
        offset += subtree;
        i++;
    }
    if (n > above) {
        roots[count++] = root;
    }

    assembly {
        mstore(roots, count)
    }
    expectedRight = popcount64(to) - count;
}
