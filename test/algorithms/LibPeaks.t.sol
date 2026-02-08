// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibPeaks} from "@univocity/algorithms/LibPeaks.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";

/// @title PeaksHarness
/// @notice Harness contract to expose LibPeaks for testing.
contract PeaksHarness {
    function peaks(uint256 i) external pure returns (uint256[] memory) {
        return LibPeaks.peaks(i);
    }
}

/// @title LibPeaksTest
/// @notice Unit tests for LibPeaks MMR peak computation.
/// @dev Test vectors from reference Python implementation.
///      Complete MMR indices: [0, 2, 3, 6, 7, 9, 10, 14, 15, 17, 18, 21, 22, 24, 25, 30, 31, 33, 34, 37, 38]
///
///      MMR structure for reference (showing first 15 nodes):
///
///                    14
///                 /      \
///               6          13
///             /   \       /   \
///           2      5     9     12
///          / \    / \   / \   /  \
///         0   1  3   4 7   8 10  11
contract LibPeaksTest is Test {
    PeaksHarness harness;

    function setUp() public {
        harness = new PeaksHarness();
    }

    // =========================================================================
    // Test vectors for complete MMR sizes
    // =========================================================================

    function test_peaks_singleNode() public view {
        // MMR with 1 node (index 0)
        uint256[] memory result = harness.peaks(0);
        assertEq(result.length, 1);
        assertEq(result[0], 0);
    }

    function test_peaks_threeNodes() public view {
        // MMR with 3 nodes (indices 0, 1, 2)
        // Structure: peak at 2
        uint256[] memory result = harness.peaks(2);
        assertEq(result.length, 1);
        assertEq(result[0], 2);
    }

    function test_peaks_fourNodes() public view {
        // MMR with 4 nodes (indices 0, 1, 2, 3)
        // Structure: peaks at 2, 3
        uint256[] memory result = harness.peaks(3);
        assertEq(result.length, 2);
        assertEq(result[0], 2);
        assertEq(result[1], 3);
    }

    function test_peaks_sevenNodes() public view {
        // MMR with 7 nodes (indices 0-6)
        // Structure: single peak at 6
        uint256[] memory result = harness.peaks(6);
        assertEq(result.length, 1);
        assertEq(result[0], 6);
    }

    function test_peaks_eightNodes() public view {
        // MMR with 8 nodes (indices 0-7)
        // Structure: peaks at 6, 7
        uint256[] memory result = harness.peaks(7);
        assertEq(result.length, 2);
        assertEq(result[0], 6);
        assertEq(result[1], 7);
    }

    function test_peaks_tenNodes() public view {
        // MMR with 10 nodes (indices 0-9)
        // Structure: peaks at 6, 9
        uint256[] memory result = harness.peaks(9);
        assertEq(result.length, 2);
        assertEq(result[0], 6);
        assertEq(result[1], 9);
    }

    function test_peaks_elevenNodes() public view {
        // MMR with 11 nodes (indices 0-10)
        // Structure: peaks at 6, 9, 10
        uint256[] memory result = harness.peaks(10);
        assertEq(result.length, 3);
        assertEq(result[0], 6);
        assertEq(result[1], 9);
        assertEq(result[2], 10);
    }

    function test_peaks_fifteenNodes() public view {
        // MMR with 15 nodes (indices 0-14)
        // Structure: single peak at 14
        uint256[] memory result = harness.peaks(14);
        assertEq(result.length, 1);
        assertEq(result[0], 14);
    }

    function test_peaks_sixteenNodes() public view {
        // MMR with 16 nodes (indices 0-15)
        // Structure: peaks at 14, 15
        uint256[] memory result = harness.peaks(15);
        assertEq(result.length, 2);
        assertEq(result[0], 14);
        assertEq(result[1], 15);
    }

    function test_peaks_eighteenNodes() public view {
        // MMR with 18 nodes (indices 0-17)
        // Structure: peaks at 14, 17
        uint256[] memory result = harness.peaks(17);
        assertEq(result.length, 2);
        assertEq(result[0], 14);
        assertEq(result[1], 17);
    }

    function test_peaks_nineteenNodes() public view {
        // MMR with 19 nodes (indices 0-18)
        // Structure: peaks at 14, 17, 18
        uint256[] memory result = harness.peaks(18);
        assertEq(result.length, 3);
        assertEq(result[0], 14);
        assertEq(result[1], 17);
        assertEq(result[2], 18);
    }

    function test_peaks_twentyTwoNodes() public view {
        // MMR with 22 nodes (indices 0-21)
        // Structure: peaks at 14, 21
        uint256[] memory result = harness.peaks(21);
        assertEq(result.length, 2);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
    }

    function test_peaks_twentyThreeNodes() public view {
        // MMR with 23 nodes (indices 0-22)
        // Structure: peaks at 14, 21, 22
        uint256[] memory result = harness.peaks(22);
        assertEq(result.length, 3);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
        assertEq(result[2], 22);
    }

    function test_peaks_twentyFiveNodes() public view {
        // MMR with 25 nodes (indices 0-24)
        // Structure: peaks at 14, 21, 24
        uint256[] memory result = harness.peaks(24);
        assertEq(result.length, 3);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
        assertEq(result[2], 24);
    }

    function test_peaks_twentySixNodes() public view {
        // MMR with 26 nodes (indices 0-25)
        // Structure: peaks at 14, 21, 24, 25
        uint256[] memory result = harness.peaks(25);
        assertEq(result.length, 4);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
        assertEq(result[2], 24);
        assertEq(result[3], 25);
    }

    function test_peaks_thirtyOneNodes() public view {
        // MMR with 31 nodes (indices 0-30)
        // Structure: single peak at 30
        uint256[] memory result = harness.peaks(30);
        assertEq(result.length, 1);
        assertEq(result[0], 30);
    }

    function test_peaks_thirtyTwoNodes() public view {
        // MMR with 32 nodes (indices 0-31)
        // Structure: peaks at 30, 31
        uint256[] memory result = harness.peaks(31);
        assertEq(result.length, 2);
        assertEq(result[0], 30);
        assertEq(result[1], 31);
    }

    function test_peaks_thirtyFourNodes() public view {
        // MMR with 34 nodes (indices 0-33)
        // Structure: peaks at 30, 33
        uint256[] memory result = harness.peaks(33);
        assertEq(result.length, 2);
        assertEq(result[0], 30);
        assertEq(result[1], 33);
    }

    function test_peaks_thirtyFiveNodes() public view {
        // MMR with 35 nodes (indices 0-34)
        // Structure: peaks at 30, 33, 34
        uint256[] memory result = harness.peaks(34);
        assertEq(result.length, 3);
        assertEq(result[0], 30);
        assertEq(result[1], 33);
        assertEq(result[2], 34);
    }

    function test_peaks_thirtyEightNodes() public view {
        // MMR with 38 nodes (indices 0-37)
        // Structure: peaks at 30, 37
        uint256[] memory result = harness.peaks(37);
        assertEq(result.length, 2);
        assertEq(result[0], 30);
        assertEq(result[1], 37);
    }

    function test_peaks_thirtyNineNodes() public view {
        // MMR with 39 nodes (indices 0-38)
        // Structure: peaks at 30, 37, 38
        uint256[] memory result = harness.peaks(38);
        assertEq(result.length, 3);
        assertEq(result[0], 30);
        assertEq(result[1], 37);
        assertEq(result[2], 38);
    }

    // =========================================================================
    // Property tests
    // =========================================================================

    /// @dev Peak heights should be strictly decreasing
    function test_peaks_heightsDecreasing() public view {
        uint256[] memory result = harness.peaks(38);

        for (uint256 j = 1; j < result.length; j++) {
            uint256 prevHeight = LibBinUtils.indexHeight(result[j - 1]);
            uint256 currHeight = LibBinUtils.indexHeight(result[j]);
            assertTrue(prevHeight > currHeight, "Peak heights should decrease");
        }
    }

    /// @dev First peak should be the highest node in the MMR
    function test_peaks_firstPeakIsHighest() public view {
        uint256[] memory p;

        // Test various MMR sizes
        uint256[10] memory testIndices = [uint256(0), 2, 6, 14, 30, 7, 10, 25, 38, 62];

        for (uint256 j = 0; j < testIndices.length; j++) {
            p = harness.peaks(testIndices[j]);
            // First peak should have the maximum height
            uint256 maxHeight = 0;
            for (uint256 k = 0; k < p.length; k++) {
                uint256 h = LibBinUtils.indexHeight(p[k]);
                if (h > maxHeight) maxHeight = h;
            }
            assertEq(LibBinUtils.indexHeight(p[0]), maxHeight);
        }
    }

    /// @dev All peak indices should be valid (within MMR bounds)
    function test_peaks_allIndicesValid() public view {
        uint256 i = 38;
        uint256[] memory result = harness.peaks(i);

        for (uint256 j = 0; j < result.length; j++) {
            assertTrue(result[j] <= i, "Peak index should be within MMR bounds");
        }
    }

    /// @dev Perfect binary tree sizes should have exactly one peak
    function test_peaks_perfectTreesHaveOnePeak() public view {
        // Perfect binary tree sizes: 2^n - 1 for n >= 1
        // MMR indices: 0 (1 node), 2 (3 nodes), 6 (7 nodes), 14 (15 nodes), etc.
        for (uint256 n = 1; n <= 8; n++) {
            uint256 treeSize = (1 << n) - 1;
            uint256[] memory p = harness.peaks(treeSize - 1);
            assertEq(p.length, 1, "Perfect tree should have exactly one peak");
        }
    }
}
