// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {bitLength} from "@univocity/algorithms/binUtils.sol";

/// @title BinUtils_bitLength_Test
/// @notice Unit tests for bitLength function.
contract BinUtils_bitLength_Test is Test {
    function test_bitLength_zero() public pure {
        assertEq(bitLength(0), 0);
    }

    function test_bitLength_one() public pure {
        assertEq(bitLength(1), 1);
    }

    function test_bitLength_powersOfTwo() public pure {
        // 2^0 = 1 needs 1 bit
        assertEq(bitLength(1), 1);
        // 2^1 = 2 needs 2 bits
        assertEq(bitLength(2), 2);
        // 2^2 = 4 needs 3 bits
        assertEq(bitLength(4), 3);
        // 2^3 = 8 needs 4 bits
        assertEq(bitLength(8), 4);
        // 2^7 = 128 needs 8 bits
        assertEq(bitLength(128), 8);
        // 2^8 = 256 needs 9 bits
        assertEq(bitLength(256), 9);
        // 2^16 needs 17 bits
        assertEq(bitLength(1 << 16), 17);
        // 2^32 needs 33 bits
        assertEq(bitLength(1 << 32), 33);
        // 2^64 needs 65 bits
        assertEq(bitLength(1 << 64), 65);
        // 2^128 needs 129 bits
        assertEq(bitLength(1 << 128), 129);
        // 2^255 needs 256 bits
        assertEq(bitLength(1 << 255), 256);
    }

    function test_bitLength_powerOfTwoMinusOne() public pure {
        // 2^n - 1 needs n bits
        assertEq(bitLength(3), 2); // 11
        assertEq(bitLength(7), 3); // 111
        assertEq(bitLength(15), 4); // 1111
        assertEq(bitLength(255), 8); // 8 ones
        assertEq(bitLength((1 << 64) - 1), 64);
    }

    function test_bitLength_miscValues() public pure {
        assertEq(bitLength(5), 3); // 101
        assertEq(bitLength(6), 3); // 110
        assertEq(bitLength(9), 4); // 1001
        assertEq(bitLength(100), 7); // 1100100
    }

    function test_bitLength_maxUint256() public pure {
        assertEq(bitLength(type(uint256).max), 256);
    }

    function testFuzz_bitLength_consistentWithLoop(uint256 x) public pure {
        // Compare against naive loop implementation
        uint256 expected = 0;
        uint256 temp = x;
        while (temp > 0) {
            expected++;
            temp >>= 1;
        }
        assertEq(bitLength(x), expected);
    }
}
