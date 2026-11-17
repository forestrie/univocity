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
import {
    committingPathLengthReference,
    includedRootReference
} from "./IncludedRootOracle.sol";

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

    function referenceRoot(uint256 i, bytes32 node, bytes32[] calldata path)
        external
        pure
        returns (bytes32)
    {
        return includedRootReference(i, node, path);
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
            indexHeight(index) + committingPathLengthReference(index, size)
        );
    }
}

/// @dev Only the entry the gas test times, so helpers added to WalkHarness
///    cannot move the measured figure.
contract RootGasHarness {
    function root(uint256 i, bytes32 leaf, bytes32[] calldata path)
        external
        pure
        returns (bytes32)
    {
        return includedRoot(i, leaf, path);
    }
}

/// @notice The linear forms built on the leaf walk agree with the reference
///    algorithms they replace (IncludedRootOracle.sol): includedRoot and
///    committingPathLength for any node, the walk itself, and the
///    committing-peak slot. The peak bitmap is checked against its
///    definition.
contract LeafWalkTest is Test {
    WalkHarness internal h = new WalkHarness();
    RootGasHarness internal gasH = new RootGasHarness();

    /// @dev 2^63 leaves: one peak, at the maximum height 63.
    uint256 internal constant MAX_SIZE = type(uint64).max;

    /// @dev The getter's slot at the largest sizes: measured plus ~15%.
    uint256 internal constant CEILING_SLOT_MAX = 16_400;

    /// @dev includedRoot for the last of 2^20 leaves, 20 siblings, timed
    ///    through RootGasHarness: measured 38,360 plus 15%.
    uint256 internal constant CEILING_ROOT_2POW20 = 44_100;

    function _referenceSlot(uint256 index, uint256 size)
        internal
        pure
        returns (uint256)
    {
        return peakIndex(
            leafCount(size),
            indexHeight(index) + committingPathLengthReference(index, size)
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

    function testFuzz_includedRootByLeafIndex_matchesReference(
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
        assertEq(h.walk(i, g, e, node, path), h.referenceRoot(i, node, path));
    }

    function test_includedRootByLeafIndex_maxHeight_matchesReference()
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
            assertEq(
                h.walk(i, 0, es[k], leaf, path), h.referenceRoot(i, leaf, path)
            );
        }
    }

    /// @dev Nodes of the complete MMR(size) worth checking at the largest
    ///    sizes: the first and last node, one in the middle, the last leaf,
    ///    and the leftmost leaf of every peak.
    function _largeSizeNodes(uint256 size)
        internal
        pure
        returns (uint256[] memory ix)
    {
        uint256 leaves = peaksBitmap(size);
        uint256 n = popcount64(leaves);
        ix = new uint256[](n + 4);
        ix[0] = 0;
        ix[1] = size / 2;
        ix[2] = mmrSizeForLeafCount(leaves - 1);
        ix[3] = size - 1;
        uint256 k = 4;
        for (uint256 b = 64; b > 0;) {
            b--;
            if ((leaves >> b) & 1 == 0) continue;
            // The leaves of the taller peaks come first.
            ix[k++] = mmrSizeForLeafCount((leaves >> (b + 1)) << (b + 1));
        }
    }

    function test_includedRoot_everyNodeTo64Leaves_matchesReference()
        public
        view
    {
        for (uint256 a = 1; a <= 64; a++) {
            uint256 size = mmrSizeForLeafCount(a);
            for (uint256 i = 0; i < size; i++) {
                // The path to the node's committing peak at this size. Over
                // every size a node climbs every height it can reach in
                // MMR(127), the 64-leaf MMR.
                bytes32[] memory path = _path(
                    keccak256(abi.encode(a, i)),
                    committingPathLengthReference(i, size)
                );
                bytes32 node = keccak256(abi.encode(i));
                assertEq(h.root(i, node, path), h.referenceRoot(i, node, path));
            }
        }
    }

    function testFuzz_includedRoot_matchesReference(
        uint64 index,
        uint8 len,
        bytes32 seed
    ) public view {
        // Any node, leaf or interior, climbing any number of levels.
        uint256 i = bound(index, 0, (1 << 41) - 1);
        bytes32[] memory path = _path(seed, bound(len, 0, 63));
        bytes32 node = keccak256(abi.encode(seed));
        assertEq(h.root(i, node, path), h.referenceRoot(i, node, path));
    }

    function test_includedRoot_largestSizes_matchesReference() public view {
        uint256[6] memory sizes = _largeSizes();
        for (uint256 k = 0; k < sizes.length; k++) {
            uint256 size = sizes[k];
            (, bool complete) = peaksBitmapComplete(size);
            if (!complete) continue;
            uint256[] memory ix = _largeSizeNodes(size);
            for (uint256 j = 0; j < ix.length; j++) {
                bytes32[] memory path = _path(
                    keccak256(abi.encode(k, j)),
                    committingPathLengthReference(ix[j], size)
                );
                bytes32 node = keccak256(abi.encode(ix[j]));
                assertEq(
                    h.root(ix[j], node, path),
                    h.referenceRoot(ix[j], node, path)
                );
            }
        }
    }

    function test_committingPathLength_everyNodeTo64Leaves_matchesReference()
        public
        pure
    {
        for (uint256 a = 1; a <= 64; a++) {
            uint256 size = mmrSizeForLeafCount(a);
            for (uint256 i = 0; i < size; i++) {
                assertEq(
                    committingPathLength(i, size),
                    committingPathLengthReference(i, size)
                );
            }
        }
    }

    function test_committingPathLength_largestSizes_matchReference()
        public
        pure
    {
        uint256[6] memory sizes = _largeSizes();
        for (uint256 k = 0; k < sizes.length; k++) {
            uint256 size = sizes[k];
            (, bool complete) = peaksBitmapComplete(size);
            if (!complete) continue;
            uint256[] memory ix = _largeSizeNodes(size);
            for (uint256 j = 0; j < ix.length; j++) {
                assertEq(
                    committingPathLength(ix[j], size),
                    committingPathLengthReference(ix[j], size)
                );
            }
        }
    }

    function test_gas_includedRoot_lastOf2pow20Leaves() public {
        // The grant inclusion a checkpoint pays for the last leaf of a log
        // of 2^20 leaves: one peak, 20 siblings.
        uint256 i = mmrSizeForLeafCount((1 << 20) - 1);
        bytes32[] memory path = _path(keccak256("grant"), 20);
        bytes32 leaf = keccak256("leaf");
        uint256 g0 = gasleft();
        gasH.root(i, leaf, path);
        uint256 used = g0 - gasleft();
        emit log_named_uint("includedRoot, last of 2^20 leaves", used);
        assertLt(used, CEILING_ROOT_2POW20);
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
