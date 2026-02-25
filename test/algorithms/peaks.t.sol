// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    leafCount,
    peakIndex,
    peaks,
    peaksBitmap
} from "@univocity/algorithms/peaks.sol";
import {indexHeight} from "@univocity/algorithms/binUtils.sol";

/// @title PeaksHarness
/// @notice Harness contract to expose peaks for testing.
contract PeaksHarness {
    function callPeaks(uint256 i) external pure returns (uint256[] memory) {
        return peaks(i);
    }

    function callPeaksBitmap(uint256 mmrSize) external pure returns (uint256) {
        return peaksBitmap(mmrSize);
    }

    function callLeafCount(uint256 mmrSize) external pure returns (uint256) {
        return leafCount(mmrSize);
    }

    function callPeakIndex(uint256 leafCountVal, uint256 d)
        external
        pure
        returns (uint256)
    {
        return peakIndex(leafCountVal, d);
    }
}

/// @title PeaksTest
/// @notice Unit tests for peaks MMR peak computation.
/// @dev Test vectors from reference Python implementation.
///    Complete MMR indices: [0, 2, 3, 6, 7, 9, 10, 14, 15, 17, 18, 21, 22,
///    24, 25, 30, 31, 33,
///    34, 37, 38]
///
///      MMR structure for reference (showing first 15 nodes):
///
///                    14
///    /      \
///    6          13
///    /   \       /   \
///    2      5     9     12
///    / \    / \   / \   /  \
///    0   1  3   4 7   8 10  11
contract PeaksTest is Test {
    PeaksHarness harness;

    function setUp() public {
        harness = new PeaksHarness();
    }

    // ========================================================================
    // =
    // Test vectors for complete MMR sizes
    // ========================================================================
    // =

    function test_peaks_singleNode() public view {
        // MMR with 1 node (index 0)
        uint256[] memory result = harness.callPeaks(0);
        assertEq(result.length, 1);
        assertEq(result[0], 0);
    }

    function test_peaks_threeNodes() public view {
        // MMR with 3 nodes (indices 0, 1, 2)
        // Structure: peak at 2
        uint256[] memory result = harness.callPeaks(2);
        assertEq(result.length, 1);
        assertEq(result[0], 2);
    }

    function test_peaks_fourNodes() public view {
        // MMR with 4 nodes (indices 0, 1, 2, 3)
        // Structure: peaks at 2, 3
        uint256[] memory result = harness.callPeaks(3);
        assertEq(result.length, 2);
        assertEq(result[0], 2);
        assertEq(result[1], 3);
    }

    function test_peaks_sevenNodes() public view {
        // MMR with 7 nodes (indices 0-6)
        // Structure: single peak at 6
        uint256[] memory result = harness.callPeaks(6);
        assertEq(result.length, 1);
        assertEq(result[0], 6);
    }

    function test_peaks_eightNodes() public view {
        // MMR with 8 nodes (indices 0-7)
        // Structure: peaks at 6, 7
        uint256[] memory result = harness.callPeaks(7);
        assertEq(result.length, 2);
        assertEq(result[0], 6);
        assertEq(result[1], 7);
    }

    function test_peaks_tenNodes() public view {
        // MMR with 10 nodes (indices 0-9)
        // Structure: peaks at 6, 9
        uint256[] memory result = harness.callPeaks(9);
        assertEq(result.length, 2);
        assertEq(result[0], 6);
        assertEq(result[1], 9);
    }

    function test_peaks_elevenNodes() public view {
        // MMR with 11 nodes (indices 0-10)
        // Structure: peaks at 6, 9, 10
        uint256[] memory result = harness.callPeaks(10);
        assertEq(result.length, 3);
        assertEq(result[0], 6);
        assertEq(result[1], 9);
        assertEq(result[2], 10);
    }

    function test_peaks_fifteenNodes() public view {
        // MMR with 15 nodes (indices 0-14)
        // Structure: single peak at 14
        uint256[] memory result = harness.callPeaks(14);
        assertEq(result.length, 1);
        assertEq(result[0], 14);
    }

    function test_peaks_sixteenNodes() public view {
        // MMR with 16 nodes (indices 0-15)
        // Structure: peaks at 14, 15
        uint256[] memory result = harness.callPeaks(15);
        assertEq(result.length, 2);
        assertEq(result[0], 14);
        assertEq(result[1], 15);
    }

    function test_peaks_eighteenNodes() public view {
        // MMR with 18 nodes (indices 0-17)
        // Structure: peaks at 14, 17
        uint256[] memory result = harness.callPeaks(17);
        assertEq(result.length, 2);
        assertEq(result[0], 14);
        assertEq(result[1], 17);
    }

    function test_peaks_nineteenNodes() public view {
        // MMR with 19 nodes (indices 0-18)
        // Structure: peaks at 14, 17, 18
        uint256[] memory result = harness.callPeaks(18);
        assertEq(result.length, 3);
        assertEq(result[0], 14);
        assertEq(result[1], 17);
        assertEq(result[2], 18);
    }

    function test_peaks_twentyTwoNodes() public view {
        // MMR with 22 nodes (indices 0-21)
        // Structure: peaks at 14, 21
        uint256[] memory result = harness.callPeaks(21);
        assertEq(result.length, 2);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
    }

    function test_peaks_twentyThreeNodes() public view {
        // MMR with 23 nodes (indices 0-22)
        // Structure: peaks at 14, 21, 22
        uint256[] memory result = harness.callPeaks(22);
        assertEq(result.length, 3);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
        assertEq(result[2], 22);
    }

    function test_peaks_twentyFiveNodes() public view {
        // MMR with 25 nodes (indices 0-24)
        // Structure: peaks at 14, 21, 24
        uint256[] memory result = harness.callPeaks(24);
        assertEq(result.length, 3);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
        assertEq(result[2], 24);
    }

    function test_peaks_twentySixNodes() public view {
        // MMR with 26 nodes (indices 0-25)
        // Structure: peaks at 14, 21, 24, 25
        uint256[] memory result = harness.callPeaks(25);
        assertEq(result.length, 4);
        assertEq(result[0], 14);
        assertEq(result[1], 21);
        assertEq(result[2], 24);
        assertEq(result[3], 25);
    }

    function test_peaks_thirtyOneNodes() public view {
        // MMR with 31 nodes (indices 0-30)
        // Structure: single peak at 30
        uint256[] memory result = harness.callPeaks(30);
        assertEq(result.length, 1);
        assertEq(result[0], 30);
    }

    function test_peaks_thirtyTwoNodes() public view {
        // MMR with 32 nodes (indices 0-31)
        // Structure: peaks at 30, 31
        uint256[] memory result = harness.callPeaks(31);
        assertEq(result.length, 2);
        assertEq(result[0], 30);
        assertEq(result[1], 31);
    }

    function test_peaks_thirtyFourNodes() public view {
        // MMR with 34 nodes (indices 0-33)
        // Structure: peaks at 30, 33
        uint256[] memory result = harness.callPeaks(33);
        assertEq(result.length, 2);
        assertEq(result[0], 30);
        assertEq(result[1], 33);
    }

    function test_peaks_thirtyFiveNodes() public view {
        // MMR with 35 nodes (indices 0-34)
        // Structure: peaks at 30, 33, 34
        uint256[] memory result = harness.callPeaks(34);
        assertEq(result.length, 3);
        assertEq(result[0], 30);
        assertEq(result[1], 33);
        assertEq(result[2], 34);
    }

    function test_peaks_thirtyEightNodes() public view {
        // MMR with 38 nodes (indices 0-37)
        // Structure: peaks at 30, 37
        uint256[] memory result = harness.callPeaks(37);
        assertEq(result.length, 2);
        assertEq(result[0], 30);
        assertEq(result[1], 37);
    }

    function test_peaks_thirtyNineNodes() public view {
        // MMR with 39 nodes (indices 0-38)
        // Structure: peaks at 30, 37, 38
        uint256[] memory result = harness.callPeaks(38);
        assertEq(result.length, 3);
        assertEq(result[0], 30);
        assertEq(result[1], 37);
        assertEq(result[2], 38);
    }

    // ========================================================================
    // =
    // Property tests
    // ========================================================================
    // =

    /// @dev Peak heights should be strictly decreasing
    function test_peaks_heightsDecreasing() public view {
        uint256[] memory result = harness.callPeaks(38);

        for (uint256 j = 1; j < result.length; j++) {
            uint256 prevHeight = indexHeight(result[j - 1]);
            uint256 currHeight = indexHeight(result[j]);
            assertTrue(prevHeight > currHeight, "Peak heights should decrease");
        }
    }

    /// @dev First peak should be the highest node in the MMR
    function test_peaks_firstPeakIsHighest() public view {
        uint256[] memory p;

        // Test various MMR sizes
        uint256[10] memory testIndices =
            [uint256(0), 2, 6, 14, 30, 7, 10, 25, 38, 62];

        for (uint256 j = 0; j < testIndices.length; j++) {
            p = harness.callPeaks(testIndices[j]);
            // First peak should have the maximum height
            uint256 maxHeight = 0;
            for (uint256 k = 0; k < p.length; k++) {
                uint256 h = indexHeight(p[k]);
                if (h > maxHeight) maxHeight = h;
            }
            assertEq(indexHeight(p[0]), maxHeight);
        }
    }

    /// @dev All peak indices should be valid (within MMR bounds)
    function test_peaks_allIndicesValid() public view {
        uint256 i = 38;
        uint256[] memory result = harness.callPeaks(i);

        for (uint256 j = 0; j < result.length; j++) {
            assertTrue(
                result[j] <= i, "Peak index should be within MMR bounds"
            );
        }
    }

    /// @dev Perfect binary tree sizes should have exactly one peak
    function test_peaks_perfectTreesHaveOnePeak() public view {
        // Perfect binary tree sizes: 2^n - 1 for n >= 1
        // MMR indices: 0 (1 node), 2 (3 nodes), 6 (7 nodes), 14 (15 nodes),
        // etc.
        for (uint256 n = 1; n <= 8; n++) {
            // forge-lint: disable-next-line(incorrect-shift)
            uint256 treeSize = (1 << n) - 1;
            uint256[] memory p = harness.callPeaks(treeSize - 1);
            assertEq(p.length, 1, "Perfect tree should have exactly one peak");
        }
    }

    // ========================================================================
    // =
    // peaksBitmap / leafCount / peakIndex (go-merklelog/mmr parity)
    // ========================================================================
    // =

    /// @dev PeaksBitmap vectors from go-merklelog/mmr/peaks_test.go TestPeaksBitmap
    function test_peaksBitmap_goVectors() public view {
        assertEq(harness.callPeaksBitmap(10), 6);
        assertEq(harness.callPeaksBitmap(1), 1);
        assertEq(harness.callPeaksBitmap(3), 2);
        assertEq(harness.callPeaksBitmap(4), 3);
        assertEq(harness.callPeaksBitmap(7), 4);
        assertEq(harness.callPeaksBitmap(8), 5);
        assertEq(harness.callPeaksBitmap(11), 7);
        assertEq(harness.callPeaksBitmap(15), 8);
        assertEq(harness.callPeaksBitmap(16), 9);
        assertEq(harness.callPeaksBitmap(18), 10);
    }

    /// @dev leafCount(mmrSize) == peaksBitmap(mmrSize)
    function test_leafCount_equalsPeaksBitmap() public view {
        for (uint256 mmrSize = 1; mmrSize <= 25; mmrSize++) {
            assertEq(
                harness.callLeafCount(mmrSize),
                harness.callPeaksBitmap(mmrSize)
            );
        }
    }

    /// @dev PeakIndex vectors from go-merklelog/mmr/peaks_test.go TestPeakIndex
    ///     (subset; see test_peakIndex_goTableFull for full 43-case KAT).
    ///     Go: peakBits := LeafCount(tt.mmrIndex + 1); PeakIndex(peakBits, d).
    function test_peakIndex_goVectors() public view {
        uint256 lc;
        assertEq(harness.callPeakIndex(harness.callLeafCount(1), 0), 0);
        lc = harness.callLeafCount(3);
        assertEq(harness.callPeakIndex(lc, 1), 0);
        lc = harness.callLeafCount(4);
        assertEq(harness.callPeakIndex(lc, 1), 0);
        assertEq(harness.callPeakIndex(lc, 0), 1);
        assertEq(harness.callPeakIndex(harness.callLeafCount(7), 2), 0);
        lc = harness.callLeafCount(8);
        assertEq(harness.callPeakIndex(lc, 2), 0);
        assertEq(harness.callPeakIndex(lc, 0), 1);
        lc = harness.callLeafCount(10);
        assertEq(harness.callPeakIndex(lc, 2), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        lc = harness.callLeafCount(11);
        assertEq(harness.callPeakIndex(lc, 2), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2);
        assertEq(harness.callPeakIndex(harness.callLeafCount(15), 3), 0);
        lc = harness.callLeafCount(19);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2);
        lc = harness.callLeafCount(26);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1);
        assertEq(harness.callPeakIndex(lc, 1), 2);
        assertEq(harness.callPeakIndex(lc, 0), 3);
    }

    /// @dev Full KAT from go-merklelog/mmr/peaks_test.go TestPeakIndex: all 43
    ///     (mmrIndex, proofLength, expected) rows. Expected values match Python
    ///     peak_index(leaf_count(mmrSize), d) and Go PeakIndex(LeafCount(size), d)
    ///     (same formula; Go PeaksBitmap(19)=11 so leaf counts align). Regenerate
    ///     oracle: python3 -m algorithms.gen_all_kat --peak-index
    function test_peakIndex_goTableFull() public view {
        uint256 mmrSize;
        uint256 lc;
        // (mmrIndex, proofLength, expected) -> peakIndex(leafCount(mmrIndex+1), d) == expected
        assertEq(harness.callPeakIndex(harness.callLeafCount(1), 0), 0); // 0,0,0
        mmrSize = 3;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 1), 0); // 2,1,0
        mmrSize = 4;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 1), 0);
        assertEq(harness.callPeakIndex(lc, 0), 1); // 3,1,0 and 3,0,1
        mmrSize = 7;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 2), 0); // 6,2,0
        mmrSize = 8;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 2), 0);
        assertEq(harness.callPeakIndex(lc, 0), 1); // 7,2,0 and 7,0,1
        mmrSize = 10;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 2), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1); // 9,2,0 and 9,1,1
        mmrSize = 11;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 2), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2); // 10,2,0 10,1,1 10,0,2
        mmrSize = 15;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0); // 14,3,0
        mmrSize = 16;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 0), 1); // 15,3,0 and 15,0,1
        mmrSize = 18;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1); // 17,3,0 and 17,1,1
        mmrSize = 19;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2); // 18,3,0 18,1,1 18,0,2
        mmrSize = 22;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1); // 21,3,0 and 21,2,1
        mmrSize = 23;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2); // 22,3,0 22,2,1 22,0,2
        mmrSize = 25;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1);
        assertEq(harness.callPeakIndex(lc, 1), 2); // 24,3,0 24,2,1 24,1,2
        mmrSize = 26;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1);
        assertEq(harness.callPeakIndex(lc, 1), 2);
        assertEq(harness.callPeakIndex(lc, 0), 3); // 25,3,0 25,2,1 25,1,2 25,0,3
        mmrSize = 31;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 4), 0); // 30,4,0
        mmrSize = 32;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 4), 0);
        assertEq(harness.callPeakIndex(lc, 0), 1); // 31,4,0 and 31,0,1
        mmrSize = 34;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 4), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1); // 33,4,0 and 33,1,1
        mmrSize = 35;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 4), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2); // 34,4,0 34,1,1 34,0,2
        mmrSize = 38;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 4), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1); // 37,4,0 and 37,2,1
        mmrSize = 39;
        lc = harness.callLeafCount(mmrSize);
        assertEq(harness.callPeakIndex(lc, 4), 0);
        assertEq(harness.callPeakIndex(lc, 2), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2); // 38,4,0 38,2,1 38,0,2
    }

    /// @dev For 39-node MMR (lc=21), peakIndex(lc, d) gives accumulator index for
    ///    each proof length d=4,2,0 (three peaks).
    function test_peakIndex_kat39_threePeaks() public view {
        uint256 lc = harness.callLeafCount(39);
        assertEq(lc, 21, "leafCount(39)");
        assertEq(harness.callPeakIndex(21, 4), 0, "d=4");
        assertEq(harness.callPeakIndex(21, 2), 1, "d=2");
        assertEq(harness.callPeakIndex(21, 0), 2, "d=0");
    }

    /// @dev peakIndex(leafCount(mmrSize), proofLen) matches accumulator slot of peak
    function test_peakIndex_accumulatorSlotMatchesPeaksOrder() public view {
        uint256 mmrSize = 19;
        uint256[] memory peakIndices = harness.callPeaks(mmrSize - 1);
        uint256 lc = harness.callLeafCount(mmrSize);
        // For each proof length that appears in this MMR, peakIndex should
        // point into peakIndices. We only check a few (proof len 0,1,3).
        assertEq(harness.callPeakIndex(lc, 3), 0);
        assertEq(harness.callPeakIndex(lc, 1), 1);
        assertEq(harness.callPeakIndex(lc, 0), 2);
        assertEq(peakIndices.length, 3);
    }

    // ========================================================================
    // =
    // Go parity: TestLeafCount, TestLeafCountFirst26, TestPeakIndex full,
    // TestPeaks
    // ========================================================================
    // =

    /// @dev Go TestLeafCount: size 15 -> 8 leaves, size 11 -> 7, invalid 12 -> 7
    function test_leafCount_goTestLeafCount() public view {
        assertEq(harness.callLeafCount(15), 8, "size 15 has 8 leaves");
        assertEq(harness.callLeafCount(11), 7, "size 11 has 7 leaves");
        assertEq(harness.callLeafCount(12), 7, "invalid size 12 has 7 leaves");
    }

    /// @notice KAT from Python tests.py TestIndexOperations.test_index_leaf_counts
    ///     (index_values_table mmrsize=39)[1]; leafCount(mmrSize) for mmrSize 1..39.
    function test_leafCount_pythonTable() public view {
        uint8[39] memory expect = [
            uint8(1),
            1,
            2,
            3,
            3,
            3,
            4,
            5,
            5,
            6,
            7,
            7,
            7,
            7,
            8,
            9,
            9,
            10,
            11,
            11,
            11,
            12,
            13,
            13,
            14,
            15,
            15,
            15,
            15,
            15,
            16,
            17,
            17,
            18,
            19,
            19,
            19,
            20,
            21
        ];
        for (uint256 mmrSize = 1; mmrSize <= 39; mmrSize++) {
            assertEq(
                harness.callLeafCount(mmrSize),
                uint256(expect[mmrSize - 1]),
                "leafCount(mmrSize)"
            );
        }
    }

    /// @dev Go TestLeafCountFirst26: expectLeafCounts for mmrIndex 0..25
    ///     (mmrSize = mmrIndex+1). LeafCount returns bitmap for largest valid
    ///     MMR with size <= mmrSize.
    function test_leafCount_goFirst26() public view {
        uint256[26] memory expect = [
            uint256(1), // 0b1
            1,
            2, // 0b10
            3,
            3,
            3,
            4, // 0b100
            5,
            5,
            6,
            7,
            7,
            7,
            7,
            8, // 0b1000
            9, // mmrIndex 15, mmrSize 16 -> 9
            9,
            10, // 0b1010
            11,
            11,
            11,
            12, // 0b1100
            13,
            13,
            14,
            15
        ];
        for (uint256 mmrIndex = 0; mmrIndex < 26; mmrIndex++) {
            uint256 mmrSize = mmrIndex + 1;
            assertEq(
                harness.callLeafCount(mmrSize),
                expect[mmrIndex],
                "LeafCount(mmrSize) at mmrIndex"
            );
        }
    }

    /// @dev Go TestPeaks: (mmrIndex, want peaks). We use 0-based indices;
    ///     Go Peaks returns same. Nil/invalid -> we skip (no nil in Solidity).
    function test_peaks_goTestPeaks() public view {
        // complete index 10 gives three peaks [6, 9, 10]
        _assertPeaks(10, _arr(6, 9, 10));
        // complete index 25 gives 4 peaks [14, 21, 24, 25]
        _assertPeaks(25, _arr(14, 21, 24, 25));
        // complete index 9 gives two peaks [6, 9]
        _assertPeaks(9, _arr(6, 9));
        // complete index 14 (perfect) gives single peak [14]
        _assertPeaks(14, _arr(14));
        // complete index 17 gives two peaks [14, 17]
        _assertPeaks(17, _arr(14, 17));
        // complete index 21 gives two peaks [14, 21]
        _assertPeaks(21, _arr(14, 21));
    }

    function _assertPeaks(uint256 mmrIndex, uint256[] memory want)
        internal
        view
    {
        uint256[] memory got = harness.callPeaks(mmrIndex);
        assertEq(got.length, want.length, "peaks length");
        for (uint256 j = 0; j < want.length; j++) {
            assertEq(got[j], want[j], "peaks[j]");
        }
    }

    function _arr(uint256 a) internal pure returns (uint256[] memory) {
        uint256[] memory r = new uint256[](1);
        r[0] = a;
        return r;
    }

    function _arr(uint256 a, uint256 b)
        internal
        pure
        returns (uint256[] memory)
    {
        uint256[] memory r = new uint256[](2);
        r[0] = a;
        r[1] = b;
        return r;
    }

    function _arr(uint256 a, uint256 b, uint256 c)
        internal
        pure
        returns (uint256[] memory)
    {
        uint256[] memory r = new uint256[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
        return r;
    }

    function _arr(uint256 a, uint256 b, uint256 c, uint256 d)
        internal
        pure
        returns (uint256[] memory)
    {
        uint256[] memory r = new uint256[](4);
        r[0] = a;
        r[1] = b;
        r[2] = c;
        r[3] = d;
        return r;
    }
}
