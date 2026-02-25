// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {indexHeight} from "@univocity/algorithms/binUtils.sol";

/// @title BinUtils_indexHeight_Test
/// @notice Unit tests for indexHeight function.
/// @dev MMR structure for reference (heights in parentheses):
///
///         6(2)
///    /    \
///    2(1)    5(1)
///    /   \   /   \
///    0(0) 1(0) 3(0) 4(0)   7(0)
///
/// Indices: 0  1  2  3  4  5  6  7  8  9  10 ...
/// Heights: 0  0  1  0  0  1  2  0  0  1  0  ...
contract BinUtils_indexHeight_Test is Test {
    function test_indexHeight_leaves() public pure {
        // Leaves have height 0
        assertEq(indexHeight(0), 0);
        assertEq(indexHeight(1), 0);
        assertEq(indexHeight(3), 0);
        assertEq(indexHeight(4), 0);
        assertEq(indexHeight(7), 0);
        assertEq(indexHeight(8), 0);
        assertEq(indexHeight(10), 0);
        assertEq(indexHeight(11), 0);
    }

    function test_indexHeight_heightOne() public pure {
        // Interior nodes at height 1
        assertEq(indexHeight(2), 1);
        assertEq(indexHeight(5), 1);
        assertEq(indexHeight(9), 1);
        assertEq(indexHeight(12), 1);
    }

    function test_indexHeight_heightTwo() public pure {
        // Interior nodes at height 2
        assertEq(indexHeight(6), 2);
        assertEq(indexHeight(13), 2);
    }

    function test_indexHeight_heightThree() public pure {
        // Interior nodes at height 3
        assertEq(indexHeight(14), 3);
    }

    function test_indexHeight_largerIndices() public pure {
        // Test pattern continues:
        // Height 0: 15, 16, 18, 19, 21, 22, 24, 25, ...
        // Height 1: 17, 20, 23, 26, ...
        // Height 2: 27, ...
        // Height 3: 28, ...
        // Height 4: 30

        assertEq(indexHeight(15), 0);
        assertEq(indexHeight(16), 0);
        assertEq(indexHeight(17), 1);
        assertEq(indexHeight(18), 0);
        assertEq(indexHeight(19), 0);
        assertEq(indexHeight(20), 1);
        assertEq(indexHeight(21), 2);
        assertEq(indexHeight(22), 0);
        assertEq(indexHeight(29), 3);
        assertEq(indexHeight(30), 4);
    }

    function test_indexHeight_peakIndices() public pure {
        // Peak indices (roots of complete binary trees) have heights:
        // 2^(h+1) - 2 is a peak at height h
        assertEq(indexHeight(0), 0); // 2^1 - 2 = 0
        assertEq(indexHeight(2), 1); // 2^2 - 2 = 2
        assertEq(indexHeight(6), 2); // 2^3 - 2 = 6
        assertEq(indexHeight(14), 3); // 2^4 - 2 = 14
        assertEq(indexHeight(30), 4); // 2^5 - 2 = 30
        assertEq(indexHeight(62), 5); // 2^6 - 2 = 62
        assertEq(indexHeight(126), 6); // 2^7 - 2 = 126
    }

    /// @notice KAT from Python tests.py TestIndexOperations.test_index_heights
    ///    (mmr indices 0..38 for canonical 39-node MMR).
    function test_indexHeight_pythonTable() public pure {
        uint8[39] memory expect = [
            uint8(0),
            0,
            1,
            0,
            0,
            1,
            2,
            0,
            0,
            1,
            0,
            0,
            1,
            2,
            3,
            0,
            0,
            1,
            0,
            0,
            1,
            2,
            0,
            0,
            1,
            0,
            0,
            1,
            2,
            3,
            4,
            0,
            0,
            1,
            0,
            0,
            1,
            2,
            0
        ];
        for (uint256 i = 0; i < 39; i++) {
            assertEq(
                indexHeight(i), uint256(expect[i]), "indexHeight(i) mismatch"
            );
        }
    }
}
