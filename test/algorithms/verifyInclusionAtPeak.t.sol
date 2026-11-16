// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
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
}

/// @notice verifyInclusionAtPeak is verifyInclusionAtSize with the
///    committing peak supplied by the caller.
contract VerifyInclusionAtPeakTest is Test {
    using MmrBuilder for Mmr;

    AtPeakHarness internal h = new AtPeakHarness();

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

    function test_nonLeaf_refused() public view {
        (Mmr memory m,) = _build(4);
        uint256 size = mmrSizeForLeafCount(4);
        // Node 2 with its real path and the real root as the peak.
        assertFalse(
            h.atPeak(2, m.nodes[2], m.pathAt(2, size), m.nodes[size - 1], size)
        );
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
