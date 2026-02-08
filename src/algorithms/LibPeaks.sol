// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
import {MAX_HEIGHT} from "@univocity/algorithms/constants.sol";

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
        // Pre-allocate maximum size, then trim. This avoids iterating twice
        // (once to count, once to fill).
        result = new uint256[](MAX_HEIGHT);

        uint256 peak = 0;
        uint256 s = i + 1;
        uint256 count = 0;

        while (s != 0) {
            // Find the highest peak size in the current MMR(s)
            // A complete binary tree of height h has 2^(h+1) - 1 nodes
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
}
