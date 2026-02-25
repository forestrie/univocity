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

    function testFuzz_hashPosPair64_matchesManualComputation(
        uint64 pos,
        bytes32 a,
        bytes32 b
    ) public pure {
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

    /// @notice KAT from canonical 39-node MMR (Python db.KatDB / Go KAT39).
    ///    Parent at MMR index 2 = hash_pospair64(3, H0, H1); index 5 = pos 6,
    ///    H3, H4; index 6 = pos 7, H2, H5.
    function test_hashPosPair64_canonicalMMRParents() public pure {
        bytes32 h0 = sha256(abi.encodePacked(uint64(0)));
        bytes32 h1 = sha256(abi.encodePacked(uint64(1)));
        bytes32 h3 = sha256(abi.encodePacked(uint64(3)));
        bytes32 h4 = sha256(abi.encodePacked(uint64(4)));

        bytes32 h2 = LibBinUtils.hashPosPair64(3, h0, h1);
        bytes32 h5 = LibBinUtils.hashPosPair64(6, h3, h4);
        bytes32 h6 = LibBinUtils.hashPosPair64(7, h2, h5);

        assertEq(
            h2,
            0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8
        );
        assertEq(
            h5,
            0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0
        );
        assertEq(
            h6,
            0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88
        );
    }
}
