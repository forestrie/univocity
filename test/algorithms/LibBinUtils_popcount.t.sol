// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";

/// @title LibBinUtils_popcount_Test
/// @notice Tests for popcount and popcount64 (match go bits.OnesCount64 for
///    use in PeakIndex).
contract LibBinUtils_popcount_Test is Test {
    /// @dev popcount64 matches popcount for all 64-bit values (fuzz)
    function testFuzz_popcount64_matchesPopcount_uint64(uint64 x) public pure {
        assertEq(LibBinUtils.popcount64(x), LibBinUtils.popcount(x));
    }

    /// @dev popcount64 ignores high bits (only low 64 bits counted)
    function testFuzz_popcount64_ignoresHighBits(uint64 lo, uint256 hi)
        public
        pure
    {
        uint256 x = (uint256(hi) << 64) | lo;
        assertEq(LibBinUtils.popcount64(x), LibBinUtils.popcount64(lo));
    }

    /// @dev Known values: 0 -> 0, 1 -> 1, 3 -> 2, 0xFF -> 8
    function test_popcount64_knownValues() public pure {
        assertEq(LibBinUtils.popcount64(0), 0);
        assertEq(LibBinUtils.popcount64(1), 1);
        assertEq(LibBinUtils.popcount64(3), 2);
        assertEq(LibBinUtils.popcount64(0xFF), 8);
        assertEq(LibBinUtils.popcount64(0xFFFFFFFFFFFFFFFF), 64);
    }

    /// @dev Peak bitmap values from Go (leaf counts): popcount = number of peaks
    function test_popcount64_peakBitmapValues() public pure {
        assertEq(LibBinUtils.popcount64(1), 1); // 0b1
        assertEq(LibBinUtils.popcount64(5), 2); // 0b101
        assertEq(LibBinUtils.popcount64(7), 3); // 0b111
        assertEq(LibBinUtils.popcount64(11), 3); // 0b1011
        assertEq(LibBinUtils.popcount64(15), 4); // 0b1111
    }

    /// @dev popcount general: known values
    function test_popcount_knownValues() public pure {
        assertEq(LibBinUtils.popcount(0), 0);
        assertEq(LibBinUtils.popcount(1), 1);
        assertEq(LibBinUtils.popcount(0xAA), 4);
        assertEq(LibBinUtils.popcount(type(uint256).max), 256);
    }
}
