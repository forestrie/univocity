// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Consistency between two MMR states, per draft-bryce-cose-receipts-mmr-profile
// "Verifying the Receipt of consistency", with the proof shape the two sizes
// imply enforced in the same pass. The draft's next revision states the
// path-length check as a MUST for receipts of consistency (ADR-0066 D5.2);
// this implementation already requires it. For a complete MMR the set bits
// of peaksBitmap(size) are the peak heights in accumulator order, so
// verification iterates that bitmap directly: no peak index list, and no
// bookkeeping per hop beyond the hash itself. Exposition with diagrams and
// worked examples: docs/consistent-roots.md.

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
///    Let `splitHeight` be the highest bit on which the two peaks bitmaps
///    differ. As sizeTo > sizeFrom the target has it and the origin does
///    not. Bitmaps big-endian, so they read left to right like the
///    accumulator; the origin 7 leaves (size 11) to the target 12 leaves
///    (size 22):
///
///        from  0 1 1 1     peaks h2 h1 h0
///        to    1 1 0 0     peaks h3 h2
///        xor   1 0 1 1
///              ^ splitHeight = 3
///
///    An origin peak above `splitHeight` is also a peak of the target: its
///    path is empty and it is returned unchanged. Every origin peak below
///    `splitHeight` is buried under the target peak of that height: its
///    path has length splitHeight - h, and every such path must prove the
///    same root (here all three, with paths of 1, 2 and 3). The target's
///    remaining peaks lie below every origin peak, so no proof reaches
///    them; the prover supplies them as rightPeaks, and their count is
///    returned (here one, h2).
///
///    Only the target size must be complete: the origin is anchored state,
///    and every anchored size was itself a checked target.
///    See docs/consistent-roots.md for the exposition and the case with an
///    unchanged origin peak.
/// @param sizeFrom Node count of the origin state (0 for an empty log).
/// @param sizeTo Node count of the target state; must exceed sizeFrom.
/// @param accumulatorFrom Peaks of MMR(sizeFrom), descending height.
/// @param proofs One path per origin peak, in the same order (calldata).
/// @return roots The peaks of MMR(sizeTo) proven from the origin peaks, in
///    descending height: the unchanged peaks, then the one proven root if
///    any.
/// @return expectedRight Number of MMR(sizeTo) peaks the prover must supply
///    as rightPeaks: the target peaks below the split other than the split
///    peak itself (docs/consistent-roots.md, "The split").
function consistentRootsForSizes(
    uint64 sizeFrom,
    uint64 sizeTo,
    bytes32[] memory accumulatorFrom,
    bytes32[][] calldata proofs
) pure returns (bytes32[] memory roots, uint256 expectedRight) {
    // The split is the highest bit on which the two peak bitmaps differ,
    // and it is read as `bitLength(from ^ to) - 1` below. Equal sizes give
    // equal bitmaps, so that subtraction underflows to Panic(0x11) rather
    // than a named reason, and a target below the origin has the split on
    // the wrong side. The one caller in src/ checks growth first, but this
    // is an exported pure function with no such guarantee, so the check
    // belongs here too (FOR-568 C3, C7).
    if (sizeTo <= sizeFrom) {
        revert IUnivocityErrors.SizeMustIncrease(sizeFrom, sizeTo);
    }
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

    // splitHeight is a height: that of the lowest target peak taller than
    // every origin peak it buries. Origin peaks are compared with it by
    // their own height h, and a buried peak's path climbs splitHeight - h
    // levels to reach it.
    uint256 splitHeight = bitLength(from ^ to) - 1;
    roots = new bytes32[](n);
    uint256 count;
    // Node count of every subtree to the left of the current origin peak.
    // A peak of height h roots a subtree of 2^(h+1) - 1 nodes, so its node
    // index is offset + 2^(h+1) - 2; after it, offset grows by its subtree
    // so the next peak's index is right.
    uint256 offset;
    uint256 i;

    // Origin peaks above the split are also peaks of the target. The path
    // is not read; requiring it to be empty rejects unused material (a shape
    // check: the result does not depend on it).
    uint256 h = bitLength(from);
    for (; h > splitHeight + 1;) {
        h--;
        // No origin peak of height h.
        if ((from >> h) & 1 == 0) continue;
        if (proofs[i].length != 0) {
            revert IUnivocityErrors.ConsistencyPathLengthMismatch(
                i, 0, proofs[i].length
            );
        }
        roots[count++] = accumulatorFrom[i];
        // Step over this peak's whole subtree: it is unchanged in the
        // target, so the next origin peak's subtree starts right after it.
        offset += (uint256(1) << (h + 1)) - 1;
        i++;
    }

    // Origin peaks below the split are all buried under the target peak of
    // height splitHeight (that bit is clear in `from`), so each path must
    // have length splitHeight - h and every path must prove the same root.
    // The first `above` peaks were returned unchanged, so i == above at the
    // first peak below the split.
    uint256 above = count;
    bytes32 root;
    for (h = splitHeight; h > 0;) {
        h--;
        // No origin peak of height h.
        if ((from >> h) & 1 == 0) continue;
        // The path length is the height climbed from this origin peak to
        // the target peak that buries it: one sibling per level.
        uint256 expected = splitHeight - h;
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
