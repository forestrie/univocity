// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Functions for computing MMR (Merkle Mountain Range) peaks.
// Peaks are the roots of the complete binary trees that make up an MMR.
// They are listed in descending order of height.
// LeafCount and PeakIndex match go-merklelog/mmr semantics for verifyInclusion.

import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
import {MAX_HEIGHT} from "@univocity/algorithms/constants.sol";

/// @notice Returns the peak bitmap for the largest valid MMR with size <= mmrSize.
/// @dev A set bit indicates a peak; the numeric value equals the leaf count.
///    Matches go-merklelog/mmr PeaksBitmap. Used by leafCount and PeakIndex.
/// @param mmrSize Number of nodes in the MMR (last index + 1). Zero returns 0.
/// @return Bitmask whose popcount is the number of leaves (and of peaks).
function peaksBitmap(uint256 mmrSize) pure returns (uint256) {
    if (mmrSize == 0) return 0;
    uint256 pos = mmrSize;
    uint256 n = LibBinUtils.bitLength(mmrSize);
    uint256 peakSize = n >= 256 ? type(uint256).max : (1 << n) - 1;
    uint256 peakMap = 0;
    while (peakSize > 0) {
        peakMap <<= 1;
        if (pos >= peakSize) {
            pos -= peakSize;
            peakMap |= 1;
        }
        peakSize >>= 1;
    }
    return peakMap;
}

/// @notice Returns the number of leaves in the largest valid MMR with size <= mmrSize.
/// @dev Matches go-merklelog/mmr LeafCount(size) = PeaksBitmap(size).
/// @param mmrSize Number of nodes in the MMR (last index + 1).
/// @return Leaf count (same numeric value as peaksBitmap(mmrSize)).
function leafCount(uint256 mmrSize) pure returns (uint256) {
    return peaksBitmap(mmrSize);
}

/// @notice Returns the accumulator index for the peak that commits a proof of length d.
/// @dev Matches go-merklelog/mmr PeakIndex(leafCount, d). By construction no two
///    peaks have the same height, so (leafCount, d) uniquely identifies the peak.
/// @param leafCountResult Leaf count from leafCount(mmrSize) (or peaksBitmap value).
/// @param d Proof length (number of sibling hashes).
/// @return Index into the accumulator (peaks array) for the committing peak.
function peakIndex(uint256 leafCountResult, uint256 d) pure returns (uint256) {
    uint256 peaksMask = (d + 1) >= 256 ? type(uint256).max : (1 << (d + 1)) - 1;
    uint256 n = LibBinUtils.popcount64(leafCountResult & peaksMask);
    return LibBinUtils.popcount64(leafCountResult) - n;
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
        uint256 highestSize = (1 << LibBinUtils.log2floor(s + 1)) - 1;
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
