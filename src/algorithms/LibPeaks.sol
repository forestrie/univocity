// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";

/// @title LibPeaks
/// @notice Provides functions for computing MMR (Merkle Mountain Range) peaks.
/// @dev Peaks are the roots of the complete binary trees that make up an MMR.
///      They are listed in descending order of height.
library LibPeaks {
    /// @notice Returns the peak indices for MMR(i) in highest to lowest order.
    /// @dev Assumes MMR(i) is complete. Callers can verify completeness by
    ///      checking that indexHeight(i+1) == 0.
    ///      The peaks are the roots of the perfect binary trees that compose
    ///      the MMR. Each peak index corresponds to an accumulator entry.
    /// @param i The index of the last node in the MMR (MMR size - 1).
    /// @return result Array of peak indices in descending height order.
    function peaks(uint256 i) internal pure returns (uint256[] memory result) {
        // Count peaks first to allocate exact array size
        uint256 peakCount = countPeaks(i);
        result = new uint256[](peakCount);

        uint256 peak = 0;
        uint256 s = i + 1;
        uint256 idx = 0;

        while (s != 0) {
            // Find the highest peak size in the current MMR(s)
            // A complete binary tree of height h has 2^(h+1) - 1 nodes
            uint256 highestSize = (1 << LibBinUtils.log2floor(s + 1)) - 1;
            peak = peak + highestSize;
            result[idx] = peak - 1;
            s -= highestSize;
            idx++;
        }
    }

    /// @notice Counts the number of peaks in MMR(i).
    /// @dev The number of peaks equals the number of 1-bits in the leaf count.
    ///      This is equivalent to popcount(leafCount(i)).
    /// @param i The index of the last node in the MMR.
    /// @return count The number of peaks.
    function countPeaks(uint256 i) internal pure returns (uint256 count) {
        uint256 s = i + 1;
        while (s != 0) {
            uint256 highestSize = (1 << LibBinUtils.log2floor(s + 1)) - 1;
            s -= highestSize;
            count++;
        }
    }
}
