// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    includedLeafRoot,
    includedRoot,
    verifyInclusionAtPeak,
    verifyInclusionAtSize
} from "@univocity/algorithms/includedRoot.sol";
import {mmrSizeForLeafCount} from "@univocity/algorithms/peaks.sol";
import {LibLogState} from "@univocity/algorithms/lib/LibLogState.sol";
import {LogState} from "@univocity/interfaces/types.sol";
import {Mmr, MmrBuilder} from "../shared/MmrBuilder.sol";

contract AtPeakHarness {
    function atPeak(
        uint256 i,
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 peak,
        uint256 size
    ) external pure returns (bool) {
        return verifyInclusionAtPeak(i, leaf, proof, peak, size);
    }

    function atSize(
        uint256 i,
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32[] memory acc,
        uint256 size
    ) external pure returns (bool) {
        return verifyInclusionAtSize(i, leaf, proof, acc, size);
    }

    function leafRoot(
        uint256 i,
        uint256 leafNumber,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external pure returns (bytes32) {
        return includedLeafRoot(i, leafNumber, leaf, proof);
    }

    function root(uint256 i, bytes32 leaf, bytes32[] calldata proof)
        external
        pure
        returns (bytes32)
    {
        return includedRoot(i, leaf, proof);
    }
}

/// @notice verifyInclusionAtPeak is verifyInclusionAtSize with the
///    committing peak supplied by the caller.
contract VerifyInclusionAtPeakTest is Test {
    using MmrBuilder for Mmr;

    AtPeakHarness internal h = new AtPeakHarness();

    /// @dev The single-peak check at the maximum height, with 63 siblings:
    ///    measured plus ~15%.
    uint256 internal constant CEILING_MAX_HEIGHT = 79_700;

    function _build(uint256 leaves)
        internal
        pure
        returns (Mmr memory m, uint256[] memory ix)
    {
        m = MmrBuilder.create(2 * leaves + 64);
        ix = new uint256[](leaves);
        for (uint256 i = 0; i < leaves; i++) {
            ix[i] = m.append(sha256(abi.encodePacked(i)));
        }
    }

    function _peak(Mmr memory m, uint256 index, uint256 size)
        internal
        pure
        returns (bytes32 p)
    {
        LogState memory s = LogState({
            accumulator: m.accumulatorAt(size), size: uint64(size)
        });
        (, p) = LibLogState.committingPeak(s, index);
    }

    function test_everyLeafAtEverySize_agreesWithAccumulatorVariant()
        public
        view
    {
        (Mmr memory m, uint256[] memory ix) = _build(13);
        for (uint256 a = 1; a <= 13; a++) {
            uint256 size = mmrSizeForLeafCount(a);
            for (uint256 k = 0; k < a; k++) {
                bytes32 leaf = m.nodes[ix[k]];
                bytes32 peak = _peak(m, ix[k], size);
                for (uint256 t = a; t <= 13; t++) {
                    bytes32[] memory path =
                        m.pathAt(ix[k], mmrSizeForLeafCount(t));
                    assertTrue(h.atPeak(ix[k], leaf, path, peak, size));
                    assertEq(
                        h.atPeak(ix[k], leaf, path, peak, size),
                        h.atSize(
                            ix[k], leaf, path, m.accumulatorAt(size), size
                        )
                    );
                }
            }
        }
    }

    function test_wrongPeak_refused() public view {
        (Mmr memory m, uint256[] memory ix) = _build(7);
        uint256 size = mmrSizeForLeafCount(7);
        bytes32[] memory path = m.pathAt(ix[5], size);
        assertFalse(
            h.atPeak(ix[5], m.nodes[ix[5]], path, bytes32(uint256(1)), size)
        );
    }

    function test_leafBeyondSize_refused() public view {
        (Mmr memory m, uint256[] memory ix) = _build(11);
        uint256 size = mmrSizeForLeafCount(7);
        bytes32[] memory path = m.pathAt(ix[9], mmrSizeForLeafCount(11));
        assertFalse(
            h.atPeak(ix[9], m.nodes[ix[9]], path, _peak(m, ix[6], size), size)
        );
    }

    function test_zeroLeafAgainstZeroPeak_refused() public view {
        // One-leaf MMR: empty committing path, so the leaf is the peak.
        assertFalse(h.atPeak(0, bytes32(0), new bytes32[](0), bytes32(0), 1));
    }

    function test_leafAtOrPastSize_peakEqualsLeaf_refused() public view {
        // Indices 3 and 4 lie at or past the 3-node MMR. With an empty path
        // and the leaf as the peak, only the size check can refuse.
        bytes32 leaf = bytes32(uint256(7));
        assertFalse(h.atPeak(3, leaf, new bytes32[](0), leaf, 3));
        assertFalse(h.atPeak(4, leaf, new bytes32[](0), leaf, 3));
    }

    function test_nonLeaf_refused() public view {
        (Mmr memory m,) = _build(4);
        uint256 size = mmrSizeForLeafCount(4);
        // Node 2 with its real path and the real root as the peak.
        assertFalse(
            h.atPeak(2, m.nodes[2], m.pathAt(2, size), m.nodes[size - 1], size)
        );
    }

    function test_nonLeaf_onlyLeafCheckRefuses() public view {
        (Mmr memory m,) = _build(4);
        // Node 2 at size 7 with a 2-sibling path, which is as long as the
        // walk requires, and the root that walk reaches as the peak. Only
        // the leaf-only rule can refuse.
        bytes32[] memory path = new bytes32[](2);
        path[0] = m.nodes[0];
        path[1] = m.nodes[5];
        bytes32 peak = h.leafRoot(2, 1, m.nodes[2], path);
        assertFalse(h.atPeak(2, m.nodes[2], path, peak, 7));
    }

    /// @dev The largest anchored size, 2^64 - 1, is one peak of height 63.
    ///    Its last leaf has the longest committing path and the longest
    ///    pass over its index's bits.
    function _maxHeight()
        internal
        view
        returns (
            uint256 i,
            bytes32 leaf,
            bytes32[] memory path,
            bytes32 peak,
            uint256 size
        )
    {
        size = type(uint64).max;
        i = mmrSizeForLeafCount((1 << 63) - 1);
        leaf = sha256("last leaf");
        path = new bytes32[](64);
        for (uint256 j = 0; j < path.length; j++) {
            path[j] = sha256(abi.encodePacked(j));
        }
        bytes32[] memory committing = new bytes32[](63);
        for (uint256 j = 0; j < committing.length; j++) {
            committing[j] = path[j];
        }
        peak = h.root(i, leaf, committing);
    }

    function test_maxHeight_verifies_oneShortRefused() public view {
        (
            uint256 i,
            bytes32 leaf,
            bytes32[] memory path,
            bytes32 peak,
            uint256 size
        ) = _maxHeight();
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = peak;
        // A 64-sibling path is trimmed to the 63 that reach the peak.
        assertTrue(h.atPeak(i, leaf, path, peak, size));
        assertTrue(h.atSize(i, leaf, path, acc, size));
        assembly {
            mstore(path, 62)
        }
        assertFalse(h.atPeak(i, leaf, path, peak, size));
        assertFalse(h.atSize(i, leaf, path, acc, size));
    }

    function test_incompleteSize_refused() public view {
        // Size 2 is leaves 0 and 1 without their parent: no anchored size.
        bytes32 leaf = bytes32(uint256(7));
        assertFalse(h.atPeak(0, leaf, new bytes32[](0), leaf, 2));
    }

    function test_gas_maxHeight() public {
        (
            uint256 i,
            bytes32 leaf,
            bytes32[] memory path,
            bytes32 peak,
            uint256 size
        ) = _maxHeight();
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = peak;
        uint256 g0 = gasleft();
        h.atPeak(i, leaf, path, peak, size);
        uint256 atPeak = g0 - gasleft();
        g0 = gasleft();
        h.atSize(i, leaf, path, acc, size);
        uint256 atSize = g0 - gasleft();
        emit log_named_uint("verifyInclusionAtPeak, 63 siblings", atPeak);
        emit log_named_uint("verifyInclusionAtSize, 63 siblings", atSize);
        assertLt(atPeak, CEILING_MAX_HEIGHT);
    }

    function test_pathShorterThanCommittingPath_refused() public view {
        (Mmr memory m, uint256[] memory ix) = _build(8);
        uint256 size = mmrSizeForLeafCount(8);
        bytes32[] memory stale = m.pathAt(ix[4], mmrSizeForLeafCount(6));
        assertFalse(
            h.atPeak(ix[4], m.nodes[ix[4]], stale, _peak(m, ix[4], size), size)
        );
    }
}
