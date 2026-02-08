// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";

/// @title LibBinUtils_hashPosPair64_Test
/// @notice Unit tests for LibBinUtils.hashPosPair64 function.
contract LibBinUtils_hashPosPair64_Test is Test {
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
