// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "../../src/algorithms/LibBinUtils.sol";

/// @title LibBinUtils_allOnes_Test
/// @notice Unit tests for LibBinUtils.allOnes function.
contract LibBinUtils_allOnes_Test is Test {
    function test_allOnes_zero_isFalse() public pure {
        assertFalse(LibBinUtils.allOnes(0));
    }

    function test_allOnes_trueValues() public pure {
        assertTrue(LibBinUtils.allOnes(1)); // 1
        assertTrue(LibBinUtils.allOnes(3)); // 11
        assertTrue(LibBinUtils.allOnes(7)); // 111
        assertTrue(LibBinUtils.allOnes(15)); // 1111
        assertTrue(LibBinUtils.allOnes(31)); // 11111
        assertTrue(LibBinUtils.allOnes(63)); // 111111
        assertTrue(LibBinUtils.allOnes(127)); // 1111111
        assertTrue(LibBinUtils.allOnes(255)); // 11111111
        assertTrue(LibBinUtils.allOnes((1 << 64) - 1));
        assertTrue(LibBinUtils.allOnes((1 << 128) - 1));
        assertTrue(LibBinUtils.allOnes(type(uint256).max));
    }

    function test_allOnes_falseValues() public pure {
        assertFalse(LibBinUtils.allOnes(2)); // 10
        assertFalse(LibBinUtils.allOnes(4)); // 100
        assertFalse(LibBinUtils.allOnes(5)); // 101
        assertFalse(LibBinUtils.allOnes(6)); // 110
        assertFalse(LibBinUtils.allOnes(8)); // 1000
        assertFalse(LibBinUtils.allOnes(9)); // 1001
        assertFalse(LibBinUtils.allOnes(10)); // 1010
        assertFalse(LibBinUtils.allOnes(100));
        assertFalse(LibBinUtils.allOnes(1 << 64));
    }

    function testFuzz_allOnes_powerOfTwoMinusOne(uint8 n) public pure {
        vm.assume(n > 0);
        uint256 value = (uint256(1) << n) - 1;
        assertTrue(LibBinUtils.allOnes(value));
    }

    function testFuzz_allOnes_powerOfTwo_isFalse(uint8 n) public pure {
        vm.assume(n > 0);
        uint256 value = uint256(1) << n;
        assertFalse(LibBinUtils.allOnes(value));
    }
}
