// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "../../src/algorithms/LibBinUtils.sol";

/// @title LibBinUtils_mostSigBit_Test
/// @notice Unit tests for LibBinUtils.mostSigBit function.
contract LibBinUtils_mostSigBit_Test is Test {
    function test_mostSigBit_zero() public pure {
        assertEq(LibBinUtils.mostSigBit(0), 0);
    }

    function test_mostSigBit_one() public pure {
        assertEq(LibBinUtils.mostSigBit(1), 1);
    }

    function test_mostSigBit_powersOfTwo() public pure {
        // For powers of 2, MSB is the number itself
        assertEq(LibBinUtils.mostSigBit(2), 2);
        assertEq(LibBinUtils.mostSigBit(4), 4);
        assertEq(LibBinUtils.mostSigBit(8), 8);
        assertEq(LibBinUtils.mostSigBit(16), 16);
        assertEq(LibBinUtils.mostSigBit(1 << 64), 1 << 64);
        assertEq(LibBinUtils.mostSigBit(1 << 128), 1 << 128);
        assertEq(LibBinUtils.mostSigBit(1 << 255), 1 << 255);
    }

    function test_mostSigBit_nonPowersOfTwo() public pure {
        assertEq(LibBinUtils.mostSigBit(3), 2); // 11 -> MSB is 10
        assertEq(LibBinUtils.mostSigBit(5), 4); // 101 -> MSB is 100
        assertEq(LibBinUtils.mostSigBit(7), 4); // 111 -> MSB is 100
        assertEq(LibBinUtils.mostSigBit(9), 8); // 1001 -> MSB is 1000
        assertEq(LibBinUtils.mostSigBit(15), 8); // 1111 -> MSB is 1000
        assertEq(LibBinUtils.mostSigBit(100), 64); // 1100100 -> MSB is 1000000
    }

    function test_mostSigBit_maxUint256() public pure {
        assertEq(LibBinUtils.mostSigBit(type(uint256).max), 1 << 255);
    }

    function testFuzz_mostSigBit_isPowerOfTwo(uint256 x) public pure {
        vm.assume(x > 0);
        uint256 msb = LibBinUtils.mostSigBit(x);
        // MSB should be a power of 2
        assertTrue(msb > 0 && (msb & (msb - 1)) == 0);
        // MSB should be <= x
        assertTrue(msb <= x);
        // 2 * MSB should be > x (unless MSB is 2^255)
        if (msb < (1 << 255)) {
            assertTrue(msb * 2 > x);
        }
    }
}
