// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice consistentRootsForSizes derives the proof shape from the two peaks
///   bitmaps and enforces it in the same pass as the hashing. These fuzz
///   tests build proofs with sibling values that are consistent by
///   construction — from the draft's inclusion_proof_path walk and
///   indexHeight only, never from the bitmap arithmetic under test — and
///   check: well-formed proofs are accepted with the number of proven roots
///   the walk predicts; a single perturbed path length is rejected naming the peak;
///   a single perturbed sibling under a shared target peak is rejected; the
///   completeness identity mmrSizeForLeafCount(peaksBitmap(size)) == size
///   agrees with indexHeight.

import {Test} from "forge-std/Test.sol";
import {
    consistentRootsForSizes
} from "@univocity/algorithms/consistentRoots.sol";
import {
    mmrSizeForLeafCount,
    peaks,
    peaksBitmap
} from "@univocity/algorithms/peaks.sol";
import {indexHeight} from "@univocity/algorithms/binUtils.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {inclusionProofPathLength} from "./InclusionProofPathOracle.sol";

/// @notice consistentRootsForSizes and includedRoot take calldata paths;
///    tests hold memory.
contract ConsistencyShapeHarness {
    function prove(
        uint64 sizeFrom,
        uint64 sizeTo,
        bytes32[] memory acc,
        bytes32[][] calldata proofs
    ) external pure returns (bytes32[] memory roots, uint256 expectedRight) {
        return consistentRootsForSizes(sizeFrom, sizeTo, acc, proofs);
    }

    /// @notice Value of node `i` climbed along the first `len` siblings of
    ///    `path` — the chain's value `len` heights above `i`.
    function climb(
        uint256 i,
        bytes32 node,
        bytes32[] calldata path,
        uint256 len
    ) external pure returns (bytes32) {
        return includedRoot(i, node, path[:len]);
    }
}

contract ConsistencyShapeTest is Test {
    /// @dev Leaf counts up to 2^62 keep sizes inside uint64.
    uint256 internal constant MAX_LEAVES = uint256(1) << 62;

    ConsistencyShapeHarness internal harness;

    function setUp() public {
        harness = new ConsistencyShapeHarness();
    }

    /// @notice Node count of the complete MMR with `leaves` leaves.
    function _mmrSize(uint256 leaves) internal pure returns (uint64) {
        return uint64(mmrSizeForLeafCount(leaves));
    }

    /// @notice The completeness test the verifier applies to the target size.
    function _isComplete(uint256 size) internal pure returns (bool) {
        return mmrSizeForLeafCount(peaksBitmap(size)) == size;
    }

    /// @notice A well-formed proof for sizeFrom -> sizeTo built from the draft
    ///    walk and indexHeight only. Path lengths come from the walk. The
    ///    origin peaks that share a target peak form one chain, built bottom
    ///    up: the lowest peak climbs through new material r(g) until it
    ///    reaches the height of the next origin peak j, where the chain is
    ///    j's right sibling and j is the chain's left sibling; above that the
    ///    merged chain continues and every peak in it shares each further
    ///    sibling. Chain values are computed with includedRoot on the path
    ///    prefix, so the construction is exactly what a real tree yields.
    ///    Also returns the number of proven roots the walk predicts.
    function _wellFormedProof(uint64 sizeFrom, uint64 sizeTo)
        internal
        view
        returns (
            bytes32[] memory acc,
            bytes32[][] memory proofs,
            uint256 carried
        )
    {
        uint256[] memory fromPeaks = sizeFrom == 0
            ? new uint256[](0)
            : peaks(uint256(sizeFrom) - 1);
        uint256 n = fromPeaks.length;
        acc = new bytes32[](n);
        proofs = new bytes32[][](n);
        if (n == 0) return (acc, proofs, 0);

        uint256[] memory heights = new uint256[](n);
        uint256 last = type(uint256).max;
        for (uint256 k = 0; k < n; k++) {
            acc[k] = keccak256(abi.encode("peak", k));
            heights[k] = indexHeight(fromPeaks[k]);
            (uint256 len, uint256 peak) =
                inclusionProofPathLength(fromPeaks[k], uint256(sizeTo) - 1);
            proofs[k] = new bytes32[](len);
            if (peak != last) {
                carried++;
                last = peak;
            }
        }

        // Peaks with an empty path are unchanged; the rest share one chain
        // rooted at the lowest peak m and ending at height `split`.
        uint256 m = n - 1;
        if (proofs[m].length == 0) return (acc, proofs, carried);
        uint256 split = heights[m] + proofs[m].length;
        for (uint256 g = heights[m]; g < split; g++) {
            uint256 j = type(uint256).max;
            for (uint256 k = 0; k < m; k++) {
                if (heights[k] == g) j = k;
            }
            if (j != type(uint256).max) {
                // The chain arrives at peak j's height as its right sibling.
                bytes32 chain = harness.climb(
                    fromPeaks[m], acc[m], proofs[m], g - heights[m]
                );
                proofs[j][0] = chain;
                for (uint256 k = j + 1; k <= m; k++) {
                    proofs[k][g - heights[k]] = acc[j];
                }
            } else {
                bytes32 fresh = keccak256(abi.encode("new", g));
                for (uint256 k = 0; k <= m; k++) {
                    if (proofs[k].length > 0 && heights[k] <= g) {
                        proofs[k][g - heights[k]] = fresh;
                    }
                }
            }
        }
    }

    function testFuzz_wellFormedProofAccepted(
        uint64 leavesFrom,
        uint64 leavesTo
    ) public view {
        leavesFrom = uint64(bound(leavesFrom, 0, MAX_LEAVES));
        leavesTo = uint64(bound(leavesTo, 1, MAX_LEAVES));
        vm.assume(leavesFrom < leavesTo);
        uint64 sizeFrom = _mmrSize(leavesFrom);
        uint64 sizeTo = _mmrSize(leavesTo);

        (
            bytes32[] memory acc,
            bytes32[][] memory proofs,
            uint256 wantCarried
        ) = _wellFormedProof(sizeFrom, sizeTo);
        (bytes32[] memory roots, uint256 expectedRight) =
            harness.prove(sizeFrom, sizeTo, acc, proofs);

        assertEq(roots.length, wantCarried, "proven roots");
        assertEq(
            roots.length + expectedRight,
            peaks(uint256(sizeTo) - 1).length,
            "roots + right must cover every target peak"
        );
        // Peaks with an empty path are returned unchanged, in order.
        for (uint256 k = 0; k < acc.length && proofs[k].length == 0; k++) {
            assertEq(roots[k], acc[k], "unchanged peak returned");
        }
    }

    /// @notice Lengthening any one path by one is rejected, naming
    ///    the peak and the length the sizes imply.
    function testFuzz_perturbedPathLengthRejected(
        uint64 leavesFrom,
        uint64 leavesTo,
        uint256 which
    ) public {
        leavesFrom = uint64(bound(leavesFrom, 1, MAX_LEAVES - 1));
        leavesTo = uint64(bound(leavesTo, 2, MAX_LEAVES));
        vm.assume(leavesFrom < leavesTo);
        uint64 sizeFrom = _mmrSize(leavesFrom);
        uint64 sizeTo = _mmrSize(leavesTo);

        (bytes32[] memory acc, bytes32[][] memory proofs,) =
            _wellFormedProof(sizeFrom, sizeTo);
        which = bound(which, 0, proofs.length - 1);
        uint256 expected = proofs[which].length;
        proofs[which] = new bytes32[](expected + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyPathLengthMismatch.selector,
                which,
                expected,
                expected + 1
            )
        );
        harness.prove(sizeFrom, sizeTo, acc, proofs);
    }

    /// @notice When the two lowest origin peaks share a target peak, altering
    ///    one sibling in the lowest peak's path breaks the agreement and is
    ///    rejected at that peak.
    function testFuzz_inconsistentSiblingRejected(
        uint64 leavesFrom,
        uint64 leavesTo,
        uint256 slot
    ) public {
        leavesFrom = uint64(bound(leavesFrom, 3, MAX_LEAVES - 1));
        leavesTo = uint64(bound(leavesTo, 4, MAX_LEAVES));
        vm.assume(leavesFrom < leavesTo);
        uint64 sizeFrom = _mmrSize(leavesFrom);
        uint64 sizeTo = _mmrSize(leavesTo);

        (bytes32[] memory acc, bytes32[][] memory proofs,) =
            _wellFormedProof(sizeFrom, sizeTo);
        uint256 n = proofs.length;
        vm.assume(n >= 2);
        // The two lowest peaks share a target peak iff the second-lowest has
        // a non-empty path (it is below the split).
        vm.assume(proofs[n - 2].length > 0);
        slot = bound(slot, 0, proofs[n - 1].length - 1);
        proofs[n - 1][slot] = keccak256(abi.encode("altered", slot));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyRootMismatch.selector, n - 1
            )
        );
        harness.prove(sizeFrom, sizeTo, acc, proofs);
    }

    function testFuzz_completenessIdentityMatchesIndexHeight(uint64 size)
        public
        pure
    {
        assertEq(_isComplete(size), indexHeight(size) == 0);
    }

    function testFuzz_everyLeafCountGivesACompleteSize(uint64 leaves)
        public
        pure
    {
        leaves = uint64(bound(leaves, 0, MAX_LEAVES));
        assertTrue(_isComplete(_mmrSize(leaves)));
    }

    function test_incompleteTargetRejected() public {
        bytes32[] memory none = new bytes32[](0);
        bytes32[][] memory noProofs = new bytes32[][](0);
        uint64[3] memory bad = [uint64(2), 5, 6];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IUnivocityErrors.IncompleteTreeSize.selector, bad[i]
                )
            );
            harness.prove(0, bad[i], none, noProofs);
        }
    }
}
