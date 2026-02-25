// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {mostSigBit} from "@univocity/algorithms/binUtils.sol";

/// @title BinUtils_mostSigBit_Test
/// @notice Unit tests for mostSigBit function.
contract BinUtils_mostSigBit_Test is Test {
    function test_mostSigBit_zero() public pure {
        assertEq(mostSigBit(0), 0);
    }

    function test_mostSigBit_one() public pure {
        assertEq(mostSigBit(1), 1);
    }

    function test_mostSigBit_powersOfTwo() public pure {
        // For powers of 2, MSB is the number itself
        assertEq(mostSigBit(2), 2);
        assertEq(mostSigBit(4), 4);
        assertEq(mostSigBit(8), 8);
        assertEq(mostSigBit(16), 16);
        assertEq(mostSigBit(1 << 64), 1 << 64);
        assertEq(mostSigBit(1 << 128), 1 << 128);
        assertEq(mostSigBit(1 << 255), 1 << 255);
    }

    function test_mostSigBit_nonPowersOfTwo() public pure {
        assertEq(mostSigBit(3), 2); // 11 -> MSB is 10
        assertEq(mostSigBit(5), 4); // 101 -> MSB is 100
        assertEq(mostSigBit(7), 4); // 111 -> MSB is 100
        assertEq(mostSigBit(9), 8); // 1001 -> MSB is 1000
        assertEq(mostSigBit(15), 8); // 1111 -> MSB is 1000
        assertEq(mostSigBit(100), 64); // 1100100 -> MSB is 1000000
    }

    function test_mostSigBit_maxUint256() public pure {
        assertEq(mostSigBit(type(uint256).max), 1 << 255);
    }

    function testFuzz_mostSigBit_isPowerOfTwo(uint256 x) public pure {
        vm.assume(x > 0);
        uint256 msb = mostSigBit(x);
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
