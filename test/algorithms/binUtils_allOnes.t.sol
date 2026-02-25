// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {allOnes} from "@univocity/algorithms/binUtils.sol";

/// @title BinUtils_allOnes_Test
/// @notice Unit tests for allOnes function.
contract BinUtils_allOnes_Test is Test {
    function test_allOnes_zero_isFalse() public pure {
        assertFalse(allOnes(0));
    }

    function test_allOnes_trueValues() public pure {
        assertTrue(allOnes(1)); // 1
        assertTrue(allOnes(3)); // 11
        assertTrue(allOnes(7)); // 111
        assertTrue(allOnes(15)); // 1111
        assertTrue(allOnes(31)); // 11111
        assertTrue(allOnes(63)); // 111111
        assertTrue(allOnes(127)); // 1111111
        assertTrue(allOnes(255)); // 11111111
        assertTrue(allOnes((1 << 64) - 1));
        assertTrue(allOnes((1 << 128) - 1));
        assertTrue(allOnes(type(uint256).max));
    }

    function test_allOnes_falseValues() public pure {
        assertFalse(allOnes(2)); // 10
        assertFalse(allOnes(4)); // 100
        assertFalse(allOnes(5)); // 101
        assertFalse(allOnes(6)); // 110
        assertFalse(allOnes(8)); // 1000
        assertFalse(allOnes(9)); // 1001
        assertFalse(allOnes(10)); // 1010
        assertFalse(allOnes(100));
        assertFalse(allOnes(1 << 64));
    }

    function testFuzz_allOnes_powerOfTwoMinusOne(uint8 n) public pure {
        vm.assume(n > 0);
        uint256 value = (uint256(1) << n) - 1;
        assertTrue(allOnes(value));
    }

    function testFuzz_allOnes_powerOfTwo_isFalse(uint8 n) public pure {
        vm.assume(n > 0);
        uint256 value = uint256(1) << n;
        assertFalse(allOnes(value));
    }
}
