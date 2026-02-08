// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "../../src/algorithms/LibBinUtils.sol";

/// @title LibBinUtils_log2floor_Test
/// @notice Unit tests for LibBinUtils.log2floor function.
contract LibBinUtils_log2floor_Test is Test {
    function test_log2floor_zero() public pure {
        assertEq(LibBinUtils.log2floor(0), 0);
    }

    function test_log2floor_one() public pure {
        assertEq(LibBinUtils.log2floor(1), 0);
    }

    function test_log2floor_powersOfTwo() public pure {
        // log2(2^n) = n
        assertEq(LibBinUtils.log2floor(2), 1);
        assertEq(LibBinUtils.log2floor(4), 2);
        assertEq(LibBinUtils.log2floor(8), 3);
        assertEq(LibBinUtils.log2floor(16), 4);
        assertEq(LibBinUtils.log2floor(32), 5);
        assertEq(LibBinUtils.log2floor(64), 6);
        assertEq(LibBinUtils.log2floor(128), 7);
        assertEq(LibBinUtils.log2floor(256), 8);
        assertEq(LibBinUtils.log2floor(1 << 16), 16);
        assertEq(LibBinUtils.log2floor(1 << 32), 32);
        assertEq(LibBinUtils.log2floor(1 << 64), 64);
        assertEq(LibBinUtils.log2floor(1 << 128), 128);
        assertEq(LibBinUtils.log2floor(1 << 255), 255);
    }

    function test_log2floor_nonPowersOfTwo() public pure {
        // log2floor rounds down
        assertEq(LibBinUtils.log2floor(3), 1); // between 2 and 4
        assertEq(LibBinUtils.log2floor(5), 2); // between 4 and 8
        assertEq(LibBinUtils.log2floor(6), 2);
        assertEq(LibBinUtils.log2floor(7), 2);
        assertEq(LibBinUtils.log2floor(9), 3); // between 8 and 16
        assertEq(LibBinUtils.log2floor(15), 3);
        assertEq(LibBinUtils.log2floor(17), 4); // between 16 and 32
        assertEq(LibBinUtils.log2floor(100), 6); // between 64 and 128
    }

    function test_log2floor_maxUint256() public pure {
        assertEq(LibBinUtils.log2floor(type(uint256).max), 255);
    }

    function testFuzz_log2floor_consistentWithBitLength(uint256 x) public pure {
        vm.assume(x > 0);
        assertEq(LibBinUtils.log2floor(x), LibBinUtils.bitLength(x) - 1);
    }

    function testFuzz_log2floor_boundsCheck(uint256 x) public pure {
        vm.assume(x > 0);
        uint256 result = LibBinUtils.log2floor(x);
        // 2^result <= x < 2^(result+1)
        assertTrue((1 << result) <= x);
        if (result < 255) {
            assertTrue(x < (uint256(1) << (result + 1)));
        }
    }
}
