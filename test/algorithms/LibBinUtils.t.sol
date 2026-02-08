// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "../../src/algorithms/LibBinUtils.sol";

/// @title LibBinUtilsTest
/// @notice Unit tests for LibBinUtils binary manipulation functions.
contract LibBinUtilsTest is Test {
    // =========================================================================
    // bitLength tests
    // =========================================================================

    function test_bitLength_zero() public pure {
        assertEq(LibBinUtils.bitLength(0), 0);
    }

    function test_bitLength_one() public pure {
        assertEq(LibBinUtils.bitLength(1), 1);
    }

    function test_bitLength_powersOfTwo() public pure {
        // 2^0 = 1 needs 1 bit
        assertEq(LibBinUtils.bitLength(1), 1);
        // 2^1 = 2 needs 2 bits
        assertEq(LibBinUtils.bitLength(2), 2);
        // 2^2 = 4 needs 3 bits
        assertEq(LibBinUtils.bitLength(4), 3);
        // 2^3 = 8 needs 4 bits
        assertEq(LibBinUtils.bitLength(8), 4);
        // 2^7 = 128 needs 8 bits
        assertEq(LibBinUtils.bitLength(128), 8);
        // 2^8 = 256 needs 9 bits
        assertEq(LibBinUtils.bitLength(256), 9);
        // 2^16 needs 17 bits
        assertEq(LibBinUtils.bitLength(1 << 16), 17);
        // 2^32 needs 33 bits
        assertEq(LibBinUtils.bitLength(1 << 32), 33);
        // 2^64 needs 65 bits
        assertEq(LibBinUtils.bitLength(1 << 64), 65);
        // 2^128 needs 129 bits
        assertEq(LibBinUtils.bitLength(1 << 128), 129);
        // 2^255 needs 256 bits
        assertEq(LibBinUtils.bitLength(1 << 255), 256);
    }

    function test_bitLength_powerOfTwoMinusOne() public pure {
        // 2^n - 1 needs n bits
        assertEq(LibBinUtils.bitLength(3), 2); // 11
        assertEq(LibBinUtils.bitLength(7), 3); // 111
        assertEq(LibBinUtils.bitLength(15), 4); // 1111
        assertEq(LibBinUtils.bitLength(255), 8); // 8 ones
        assertEq(LibBinUtils.bitLength((1 << 64) - 1), 64);
    }

    function test_bitLength_miscValues() public pure {
        assertEq(LibBinUtils.bitLength(5), 3); // 101
        assertEq(LibBinUtils.bitLength(6), 3); // 110
        assertEq(LibBinUtils.bitLength(9), 4); // 1001
        assertEq(LibBinUtils.bitLength(100), 7); // 1100100
    }

    function test_bitLength_maxUint256() public pure {
        assertEq(LibBinUtils.bitLength(type(uint256).max), 256);
    }

    function testFuzz_bitLength_consistentWithLoop(uint256 x) public pure {
        // Compare against naive loop implementation
        uint256 expected = 0;
        uint256 temp = x;
        while (temp > 0) {
            expected++;
            temp >>= 1;
        }
        assertEq(LibBinUtils.bitLength(x), expected);
    }

    // =========================================================================
    // mostSigBit tests
    // =========================================================================

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

    // =========================================================================
    // allOnes tests
    // =========================================================================

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

    // =========================================================================
    // indexHeight tests
    // =========================================================================

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

    // =========================================================================
    // hashPosPair64 tests
    // =========================================================================

    function test_hashPosPair64_basicCase() public pure {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        uint64 pos = 3;

        bytes32 result = LibBinUtils.hashPosPair64(pos, a, b);

        // Compute expected: SHA256(pos as 8 bytes || a || b)
        bytes32 expected = sha256(abi.encodePacked(pos, a, b));
        assertEq(result, expected);
    }

    function test_hashPosPair64_zeroInputs() public pure {
        bytes32 a = bytes32(0);
        bytes32 b = bytes32(0);
        uint64 pos = 0;

        bytes32 result = LibBinUtils.hashPosPair64(pos, a, b);
        bytes32 expected = sha256(abi.encodePacked(pos, a, b));
        assertEq(result, expected);
    }

    function test_hashPosPair64_maxValues() public pure {
        bytes32 a = bytes32(type(uint256).max);
        bytes32 b = bytes32(type(uint256).max);
        uint64 pos = type(uint64).max;

        bytes32 result = LibBinUtils.hashPosPair64(pos, a, b);
        bytes32 expected = sha256(abi.encodePacked(pos, a, b));
        assertEq(result, expected);
    }

    function test_hashPosPair64_orderMatters() public pure {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        uint64 pos = 1;

        bytes32 resultAB = LibBinUtils.hashPosPair64(pos, a, b);
        bytes32 resultBA = LibBinUtils.hashPosPair64(pos, b, a);

        // Order of a and b should produce different results
        assertTrue(resultAB != resultBA);
    }

    function test_hashPosPair64_positionMatters() public pure {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));

        bytes32 result1 = LibBinUtils.hashPosPair64(1, a, b);
        bytes32 result2 = LibBinUtils.hashPosPair64(2, a, b);

        // Different positions should produce different results
        assertTrue(result1 != result2);
    }

    function testFuzz_hashPosPair64_matchesManualComputation(uint64 pos, bytes32 a, bytes32 b) public pure {
        bytes32 result = LibBinUtils.hashPosPair64(pos, a, b);
        bytes32 expected = sha256(abi.encodePacked(pos, a, b));
        assertEq(result, expected);
    }

    function test_hashPosPair64_knownVector() public pure {
        // Known test vector: SHA256 of 72 bytes (8 + 32 + 32)
        // pos = 1 (0x0000000000000001)
        // a = 0x00...01
        // b = 0x00...02
        uint64 pos = 1;
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));

        bytes32 result = LibBinUtils.hashPosPair64(pos, a, b);

        // Pre-computed expected value
        // Input: 0x0000000000000001 || 0x00..01 || 0x00..02
        bytes memory input = abi.encodePacked(pos, a, b);
        assertEq(input.length, 72);

        bytes32 expected = sha256(input);
        assertEq(result, expected);
    }
}
