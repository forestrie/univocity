// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";

/// @title LibBinUtils_indexHeight_Test
/// @notice Unit tests for LibBinUtils.indexHeight function.
/// @dev MMR structure for reference (heights in parentheses):
///
///         6(2)
///        /    \
///      2(1)    5(1)
///     /   \   /   \
///    0(0) 1(0) 3(0) 4(0)   7(0)
///
/// Indices: 0  1  2  3  4  5  6  7  8  9  10 ...
/// Heights: 0  0  1  0  0  1  2  0  0  1  0  ...
contract LibBinUtils_indexHeight_Test is Test {
    function test_indexHeight_leaves() public pure {
        // Leaves have height 0
        assertEq(LibBinUtils.indexHeight(0), 0);
        assertEq(LibBinUtils.indexHeight(1), 0);
        assertEq(LibBinUtils.indexHeight(3), 0);
        assertEq(LibBinUtils.indexHeight(4), 0);
        assertEq(LibBinUtils.indexHeight(7), 0);
        assertEq(LibBinUtils.indexHeight(8), 0);
        assertEq(LibBinUtils.indexHeight(10), 0);
        assertEq(LibBinUtils.indexHeight(11), 0);
    }

    function test_indexHeight_heightOne() public pure {
        // Interior nodes at height 1
        assertEq(LibBinUtils.indexHeight(2), 1);
        assertEq(LibBinUtils.indexHeight(5), 1);
        assertEq(LibBinUtils.indexHeight(9), 1);
        assertEq(LibBinUtils.indexHeight(12), 1);
    }

    function test_indexHeight_heightTwo() public pure {
        // Interior nodes at height 2
        assertEq(LibBinUtils.indexHeight(6), 2);
        assertEq(LibBinUtils.indexHeight(13), 2);
    }

    function test_indexHeight_heightThree() public pure {
        // Interior nodes at height 3
        assertEq(LibBinUtils.indexHeight(14), 3);
    }

    function test_indexHeight_largerIndices() public pure {
        // Test pattern continues:
        // Height 0: 15, 16, 18, 19, 21, 22, 24, 25, ...
        // Height 1: 17, 20, 23, 26, ...
        // Height 2: 27, ...
        // Height 3: 28, ...
        // Height 4: 30

        assertEq(LibBinUtils.indexHeight(15), 0);
        assertEq(LibBinUtils.indexHeight(16), 0);
        assertEq(LibBinUtils.indexHeight(17), 1);
        assertEq(LibBinUtils.indexHeight(18), 0);
        assertEq(LibBinUtils.indexHeight(19), 0);
        assertEq(LibBinUtils.indexHeight(20), 1);
        assertEq(LibBinUtils.indexHeight(21), 2);
        assertEq(LibBinUtils.indexHeight(22), 0);
        assertEq(LibBinUtils.indexHeight(29), 3);
        assertEq(LibBinUtils.indexHeight(30), 4);
    }

    function test_indexHeight_peakIndices() public pure {
        // Peak indices (roots of complete binary trees) have heights:
        // 2^(h+1) - 2 is a peak at height h
        assertEq(LibBinUtils.indexHeight(0), 0); // 2^1 - 2 = 0
        assertEq(LibBinUtils.indexHeight(2), 1); // 2^2 - 2 = 2
        assertEq(LibBinUtils.indexHeight(6), 2); // 2^3 - 2 = 6
        assertEq(LibBinUtils.indexHeight(14), 3); // 2^4 - 2 = 14
        assertEq(LibBinUtils.indexHeight(30), 4); // 2^5 - 2 = 30
        assertEq(LibBinUtils.indexHeight(62), 5); // 2^6 - 2 = 62
        assertEq(LibBinUtils.indexHeight(126), 6); // 2^7 - 2 = 126
    }
}
