// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    committingPathLength,
    includedRoot,
    includedRootByLeafIndex
} from "@univocity/algorithms/includedRoot.sol";
import {
    committingPeakIndex,
    peaksBitmapComplete,
    leafCount,
    mmrSizeForLeafCount,
    peakIndex,
    peaksBitmap
} from "@univocity/algorithms/peaks.sol";
import {indexHeight, popcount64} from "@univocity/algorithms/binUtils.sol";

contract WalkHarness {
    function walk(
        uint256 mmrIndex,
        uint256 g,
        uint256 leafIndex,
        bytes32 node,
        bytes32[] calldata path
    ) external pure returns (bytes32) {
        return includedRootByLeafIndex(mmrIndex, g, leafIndex, node, path);
    }

    function root(uint256 i, bytes32 leaf, bytes32[] calldata path)
        external
        pure
        returns (bytes32)
    {
        return includedRoot(i, leaf, path);
    }

    function slot(uint256 index, uint256 size)
        external
        pure
        returns (uint256)
    {
        return committingPeakIndex(index, size);
    }

    function referenceSlot(uint256 index, uint256 size)
        external
        pure
        returns (uint256)
    {
        return peakIndex(
            leafCount(size),
            indexHeight(index) + committingPathLength(index, size)
        );
    }
}

/// @notice The linear leaf walk's helpers agree with the reference
///    algorithms they replace on the verifier's path: the committing-peak
///    slot through committingPathLength, and includedRoot. The peak
///    bitmap is checked against its definition.
contract LeafWalkTest is Test {
    WalkHarness internal h = new WalkHarness();

    /// @dev 2^63 leaves: one peak, at the maximum height 63.
    uint256 internal constant MAX_SIZE = type(uint64).max;

    /// @dev The getter's slot at the largest sizes: measured plus ~15%.
    uint256 internal constant CEILING_SLOT_MAX = 16_400;

    function _referenceSlot(uint256 index, uint256 size)
        internal
        pure
        returns (uint256)
    {
        return peakIndex(
            leafCount(size),
            indexHeight(index) + committingPathLength(index, size)
        );
    }

    function _path(bytes32 seed, uint256 len)
        internal
        pure
        returns (bytes32[] memory path)
    {
        path = new bytes32[](len);
        for (uint256 j = 0; j < len; j++) {
            path[j] = keccak256(abi.encode(seed, j));
        }
    }

    function _largeSizes() internal pure returns (uint256[6] memory) {
        return [
            MAX_SIZE,
            MAX_SIZE - 1,
            mmrSizeForLeafCount(type(uint64).max >> 1),
            mmrSizeForLeafCount(1 << 62),
            mmrSizeForLeafCount((1 << 62) + 1),
            (1 << 63) - 1
        ];
    }

    /// @dev The bitmap's value is the leaf count of the largest complete
    ///    MMR that fits in `s`, and `s` is complete when that MMR fills it.
    function _assertPeaksBitmapComplete(uint256 s) internal pure {
        (uint256 bitmap, bool complete) = peaksBitmapComplete(s);
        assertLe(mmrSizeForLeafCount(bitmap), s);
        assertGt(mmrSizeForLeafCount(bitmap + 1), s);
        assertEq(complete, mmrSizeForLeafCount(bitmap) == s);
    }

    function test_peaksBitmapComplete_everySmallSize_largestMMRThatFits()
        public
        pure
    {
        for (uint256 s = 0; s <= 300; s++) {
            _assertPeaksBitmapComplete(s);
        }
    }

    function test_peaksBitmapComplete_largestSizes_largestMMRThatFits()
        public
        pure
    {
        uint256[6] memory sizes = _largeSizes();
        for (uint256 k = 0; k < sizes.length; k++) {
            _assertPeaksBitmapComplete(sizes[k]);
        }
    }

    function test_committingPeakIndex_everyNodeTo64Leaves_matchesReference()
        public
        pure
    {
        for (uint256 a = 1; a <= 64; a++) {
            uint256 size = mmrSizeForLeafCount(a);
            for (uint256 i = 0; i < size; i++) {
                assertEq(committingPeakIndex(i, size), _referenceSlot(i, size));
            }
            // Past the last peak there is no slot.
            assertGe(committingPeakIndex(size, size), popcount64(a));
        }
    }

    function test_committingPeakIndex_largestSizes_matchReference()
        public
        pure
    {
        uint256[6] memory sizes = _largeSizes();
        for (uint256 k = 0; k < sizes.length; k++) {
            uint256 size = sizes[k];
            (, bool complete) = peaksBitmapComplete(size);
            if (!complete) continue;
            uint256 last = mmrSizeForLeafCount(peaksBitmap(size) - 1);
            uint256[4] memory ix = [0, size / 2, last, size - 1];
            for (uint256 j = 0; j < ix.length; j++) {
                assertEq(
                    committingPeakIndex(ix[j], size),
                    _referenceSlot(ix[j], size)
                );
            }
        }
    }

    function testFuzz_includedRootByLeafIndex_matchesIncludedRoot(
        uint64 index,
        uint64 beneath,
        uint8 len,
        bytes32 seed
    ) public view {
        // Any node, leaf or interior, steered by any leaf beneath it.
        uint256 i = bound(index, 0, (1 << 41) - 1);
        uint256 g = indexHeight(i);
        // A node's leftmost leaf is the first of its 2^(g+1) - 1 nodes.
        (uint256 leftmost,) = peaksBitmapComplete(i + 2 - (2 << g));
        uint256 e = leftmost + bound(beneath, 0, (1 << g) - 1);
        bytes32[] memory path = _path(seed, bound(len, 0, 24));
        bytes32 node = keccak256(abi.encode(seed));
        assertEq(h.walk(i, g, e, node, path), h.root(i, node, path));
    }

    function test_includedRootByLeafIndex_maxHeight_matchesIncludedRoot()
        public
        view
    {
        // All left children, all right children, and alternating.
        uint256[3] memory es =
            [uint256(0), (1 << 63) - 1, uint256(0x2aaaaaaaaaaaaaaa)];
        bytes32[] memory path = _path(keccak256("max"), 63);
        for (uint256 k = 0; k < es.length; k++) {
            uint256 i = mmrSizeForLeafCount(es[k]);
            bytes32 leaf = keccak256(abi.encode(k));
            assertEq(h.walk(i, 0, es[k], leaf, path), h.root(i, leaf, path));
        }
    }

    function test_gas_committingPeakIndex_largestSizes() public {
        // 63 peaks (heights 62 to 0): the last node is in the last peak.
        uint256 manyPeaks = mmrSizeForLeafCount(type(uint64).max >> 1);
        uint256 g0 = gasleft();
        h.slot(manyPeaks - 1, manyPeaks);
        uint256 lastOfMany = g0 - gasleft();
        uint256 lastLeaf = mmrSizeForLeafCount((1 << 63) - 1);
        g0 = gasleft();
        h.slot(lastLeaf, MAX_SIZE);
        uint256 lastOfOne = g0 - gasleft();
        g0 = gasleft();
        h.referenceSlot(lastLeaf, MAX_SIZE);
        uint256 referenceLastOfOne = g0 - gasleft();
        emit log_named_uint("slot, last node of 63 peaks", lastOfMany);
        emit log_named_uint("slot, last leaf at height 63", lastOfOne);
        emit log_named_uint(
            "reference slot, last leaf at height 63", referenceLastOfOne
        );
        assertLt(lastOfMany, CEILING_SLOT_MAX);
        assertLt(lastOfOne, CEILING_SLOT_MAX);
    }
}
