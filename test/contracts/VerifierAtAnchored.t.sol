// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ImutableVerifier} from "@univocity/contracts/ImutableVerifier.sol";
import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {mmrSizeForLeafCount} from "@univocity/algorithms/peaks.sol";
import {Mmr, MmrBuilder} from "../shared/MmrBuilder.sol";
import {StubUnivocal} from "../shared/StubUnivocal.sol";

/// @notice The witness-age rule (devdocs ARC-0032 §4.2): a path built at a
///    later log size than the one anchored on chain still proves the leaf,
///    because only its prefix up to the leaf's committing peak at the
///    anchored size is used, and MMR nodes never change once written.
contract VerifierAtAnchoredTest is Test {
    using MmrBuilder for Mmr;

    bytes32 internal constant LOG = keccak256("log");

    StubUnivocal internal univocal;
    ImutableVerifier internal verifier;

    function setUp() public {
        univocal = new StubUnivocal();
        verifier = new ImutableVerifier(IUnivocal(address(univocal)));
    }

    function _build(uint256 leaves)
        internal
        pure
        returns (Mmr memory m, uint256[] memory leafMMRIndex)
    {
        m = MmrBuilder.create(2 * leaves + 64);
        leafMMRIndex = new uint256[](leaves);
        for (uint256 i = 0; i < leaves; i++) {
            leafMMRIndex[i] = m.append(_leaf(i));
        }
    }

    function _leaf(uint256 i) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes8(uint64(i)), bytes32(i)));
    }

    function _anchor(Mmr memory m, uint256 leaves) internal {
        uint256 size = mmrSizeForLeafCount(leaves);
        // forge-lint: disable-next-line(unsafe-typecast)
        univocal.setLogState(LOG, m.accumulatorAt(size), uint64(size));
    }

    function test_pathAtAnchoredSize_verifies() public {
        (Mmr memory m, uint256[] memory ix) = _build(7);
        _anchor(m, 7);
        uint256 size = mmrSizeForLeafCount(7);
        assertTrue(
            verifier.verifyInclusionAtAnchored(
                LOG, ix[5], _leaf(5), m.pathAt(ix[5], size)
            )
        );
    }

    function test_pathBuiltAtLaterSize_verifiesAfterTrim() public {
        (Mmr memory m, uint256[] memory ix) = _build(11);
        _anchor(m, 7);
        // Leaf 5 is under a height-1 peak at 7 leaves and under the
        // height-3 peak at 11 leaves, so the later path is two longer.
        bytes32[] memory later = m.pathAt(ix[5], mmrSizeForLeafCount(11));
        bytes32[] memory atAnchor = m.pathAt(ix[5], mmrSizeForLeafCount(7));
        assertGt(later.length, atAnchor.length);
        assertTrue(
            verifier.verifyInclusionAtAnchored(LOG, ix[5], _leaf(5), later)
        );
    }

    function test_pathShorterThanCommittingPeak_refused() public {
        (Mmr memory m, uint256[] memory ix) = _build(8);
        _anchor(m, 8);
        // Built when the log had 6 leaves: it stops at a peak that MMR(8)
        // has merged away, so it cannot reach the anchored peak.
        bytes32[] memory stale = m.pathAt(ix[4], mmrSizeForLeafCount(6));
        assertFalse(
            verifier.verifyInclusionAtAnchored(LOG, ix[4], _leaf(4), stale)
        );
    }

    function test_leafBeyondAnchoredSize_refused() public {
        (Mmr memory m, uint256[] memory ix) = _build(11);
        _anchor(m, 7);
        bytes32[] memory path = m.pathAt(ix[9], mmrSizeForLeafCount(11));
        assertFalse(
            verifier.verifyInclusionAtAnchored(LOG, ix[9], _leaf(9), path)
        );
        // The anchored last leaf claimed at a later index: it verifies
        // only if the beyond-size check is missing.
        assertFalse(
            verifier.verifyInclusionAtAnchored(
                LOG, 16, _leaf(6), new bytes32[](0)
            )
        );
    }

    function test_wrongLeaf_refused() public {
        (Mmr memory m, uint256[] memory ix) = _build(11);
        _anchor(m, 7);
        bytes32[] memory path = m.pathAt(ix[5], mmrSizeForLeafCount(11));
        assertFalse(
            verifier.verifyInclusionAtAnchored(LOG, ix[5], _leaf(4), path)
        );
    }

    function test_uninitialisedLog_refused() public view {
        bytes32[] memory path = new bytes32[](0);
        assertFalse(verifier.verifyInclusionAtAnchored(LOG, 0, _leaf(0), path));
    }

    function test_interiorNode_refused() public {
        (Mmr memory m,) = _build(4);
        uint256 size = mmrSizeForLeafCount(4);
        // Node 2 is the parent of leaves 0 and 1: a real node, but not a
        // leaf. Its path has length 1, so peakIndex(4, 1) picks slot 1;
        // fill that slot with the real root so that, were the leaf-only
        // rule missing, the node would verify.
        bytes32[] memory acc = new bytes32[](2);
        acc[0] = m.nodes[size - 1];
        acc[1] = m.nodes[size - 1];
        // forge-lint: disable-next-line(unsafe-typecast)
        univocal.setLogState(LOG, acc, uint64(size));
        bytes32[] memory path = m.pathAt(2, size);
        assertFalse(
            verifier.verifyInclusionAtAnchored(LOG, 2, m.nodes[2], path)
        );
    }

    /// @notice Any leaf anchored at any complete size verifies with a path
    ///    built at any later size.
    function testFuzz_laterPath_verifiesAtAnchoredSize(
        uint8 totalSeed,
        uint8 anchoredSeed,
        uint8 leafSeed
    ) public {
        uint256 total = bound(totalSeed, 1, 64);
        uint256 anchored = bound(anchoredSeed, 1, total);
        uint256 k = bound(leafSeed, 0, anchored - 1);
        (Mmr memory m, uint256[] memory ix) = _build(total);
        _anchor(m, anchored);
        bytes32[] memory path = m.pathAt(ix[k], mmrSizeForLeafCount(total));
        assertTrue(
            verifier.verifyInclusionAtAnchored(LOG, ix[k], _leaf(k), path)
        );
    }
}
