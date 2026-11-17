// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Functions for computing MMR (Merkle Mountain Range) peaks.
// Peaks are the roots of the complete binary trees that make up an MMR.
// They are listed in descending order of height.
// LeafCount and PeakIndex match go-merklelog/mmr semantics for verifyInclusion.

import {
    bitLength,
    popcount64,
    log2floor
} from "@univocity/algorithms/binUtils.sol";
import {MAX_HEIGHT} from "@univocity/algorithms/constants.sol";

/// @notice Returns the peak bitmap for the largest valid MMR with size <= mmrSize.
/// @dev A set bit indicates a peak; the numeric value equals the leaf count.
///    Matches go-merklelog/mmr PeaksBitmap. Used by leafCount and PeakIndex.
///    The one-value form of peaksBitmapComplete.
/// @param mmrSize Number of nodes in the MMR (last index + 1). Zero returns 0.
/// @return bitmap Bitmask whose popcount is the number of peaks; its value
///    is the number of leaves.
function peaksBitmap(uint256 mmrSize) pure returns (uint256 bitmap) {
    (bitmap,) = peaksBitmapComplete(mmrSize);
}

/// @notice Node count of the complete MMR with `leaves` leaves:
///    2 * leaves - popcount(leaves). Every leaf adds itself plus one
///    interior node per binary carry, and each peak is a carry that has not
///    happened. Because peaksBitmap rounds an incomplete size down to the
///    largest complete MMR below it, `mmrSizeForLeafCount(peaksBitmap(size))
///    == size` holds exactly for complete sizes (go-merklelog's
///    FirstMMRSize / the draft's complete_mmr, in closed form).
function mmrSizeForLeafCount(uint256 leaves) pure returns (uint256) {
    return 2 * leaves - popcount64(leaves);
}

/// @notice Returns the number of leaves in the largest valid MMR with size <= mmrSize.
/// @dev Matches go-merklelog/mmr LeafCount(size) = PeaksBitmap(size).
/// @param mmrSize Number of nodes in the MMR (last index + 1).
/// @return Leaf count (same numeric value as peaksBitmap(mmrSize)).
function leafCount(uint256 mmrSize) pure returns (uint256) {
    return peaksBitmap(mmrSize);
}

/// @notice Peak bitmap of MMR(mmrSize), as peaksBitmap, and whether
///    mmrSize is complete.
/// @dev Takes the largest peak that fits, highest first, and keeps what is
///    left over: a size is complete exactly when its peaks use every node.
///    The bitmap's value is the leaf count, so for a leaf's MMR index, which
///    is the size of the complete MMR before it, the bitmap is the leaf's
///    zero-based index among the leaves, and `complete` is false for the
///    MMR index of any interior node. At most 64 steps for a uint64 size.
/// @param mmrSize Number of nodes, or the MMR index of a node.
/// @return bitmap Same value as peaksBitmap(mmrSize): the leaf count.
/// @return complete True if mmrSize is the size of a complete MMR.
function peaksBitmapComplete(uint256 mmrSize)
    pure
    returns (uint256 bitmap, bool complete)
{
    uint256 rest = mmrSize;
    uint256 n = bitLength(mmrSize);
    uint256 peakSize = n >= 256 ? type(uint256).max : (1 << n) - 1;
    // Unchecked: rest only drops by a peakSize it is at least.
    unchecked {
        while (peakSize > 0) {
            bitmap <<= 1;
            if (rest >= peakSize) {
                rest -= peakSize;
                bitmap |= 1;
            }
            peakSize >>= 1;
        }
    }
    complete = rest == 0;
}

/// @notice Accumulator index of the peak whose tree holds node `index` in
///    the complete MMR(mmrSize), for any node, leaf or not.
/// @dev One pass over the peaks, highest first as the accumulator orders
///    them, stopping at the first peak whose index range reaches `index`.
///    At most 64 steps for a uint64 size. Equal to
///    peakIndex(leafCount(mmrSize), indexHeight(index) +
///    committingPathLength(index, mmrSize)).
/// @param index Zero-based MMR index of the node.
/// @param mmrSize Number of nodes in the complete MMR.
/// @return slot Index into the accumulator; the peak count, which names no
///    slot, when index >= mmrSize.
function committingPeakIndex(uint256 index, uint256 mmrSize)
    pure
    returns (uint256 slot)
{
    uint256 rest = mmrSize;
    uint256 end = 0;
    uint256 n = bitLength(mmrSize);
    uint256 peakSize = n >= 256 ? type(uint256).max : (1 << n) - 1;
    // Unchecked: rest only drops by a peakSize it is at least, end never
    // passes mmrSize, and there are at most 256 peaks.
    unchecked {
        while (peakSize > 0) {
            if (rest >= peakSize) {
                rest -= peakSize;
                end += peakSize;
                if (index < end) return slot;
                slot++;
            }
            peakSize >>= 1;
        }
    }
}

/// @notice Returns the accumulator index for the peak that commits a proof of length d.
/// @dev Matches go-merklelog/mmr PeakIndex(leafCount, d). By construction no two
///    peaks have the same height, so (leafCount, d) uniquely identifies the peak.
/// @param leafCountResult Leaf count from leafCount(mmrSize) (or peaksBitmap value).
/// @param d Proof length (number of sibling hashes).
/// @return Index into the accumulator (peaks array) for the committing peak.
function peakIndex(uint256 leafCountResult, uint256 d) pure returns (uint256) {
    uint256 peaksMask = (d + 1) >= 256 ? type(uint256).max : (1 << (d + 1)) - 1;
    uint256 n = popcount64(leafCountResult & peaksMask);
    return popcount64(leafCountResult) - n;
}

/// @notice Returns the peak indices for MMR(i) in highest to lowest order.
/// @dev Assumes MMR(i) is complete. Callers can verify completeness by
///    checking that indexHeight(i+1) == 0.
///    The peaks are the roots of the perfect binary trees that compose
///    the MMR. Each peak index corresponds to an accumulator entry.
/// @param i The index of the last node in the MMR (MMR size - 1).
/// @return result Array of peak indices in descending height order.
function peaks(uint256 i) pure returns (uint256[] memory result) {
    // Pre-allocate maximum size, then trim. This avoids iterating twice
    // (once to count, once to fill).
    result = new uint256[](MAX_HEIGHT);

    uint256 peak = 0;
    uint256 s = i + 1;
    uint256 count = 0;

    while (s != 0) {
        // Find the highest peak size in the current MMR(s)
        // A complete binary tree of height h has 2^(h+1) - 1 nodes
        // forge-lint: disable-next-line(incorrect-shift)
        uint256 highestSize = (1 << log2floor(s + 1)) - 1;
        peak = peak + highestSize;
        result[count] = peak - 1;
        s -= highestSize;
        count++;
    }

    // Trim array to actual size
    assembly {
        mstore(result, count)
    }
}
