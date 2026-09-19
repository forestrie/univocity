// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice checkConsistencyProofShape derives consistency-proof path lengths
///   and peak counts from the two peaks bitmaps. These fuzz tests show that
///   arithmetic agrees with the draft's inclusion_proof_path walk (kept in
///   the test tree as an oracle) on random pairs of complete MMR sizes, that
///   a single perturbed path length is rejected, and that isCompleteMMR's
///   closed form agrees with indexHeight.

import {Test} from "forge-std/Test.sol";
import {
    checkConsistencyProofShape
} from "@univocity/algorithms/consistentRoots.sol";
import {isCompleteMMR, peaks} from "@univocity/algorithms/peaks.sol";
import {indexHeight, popcount64} from "@univocity/algorithms/binUtils.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {inclusionProofPathLength} from "./InclusionProofPathOracle.sol";

/// @notice checkConsistencyProofShape takes calldata paths; tests hold memory.
contract ConsistencyShapeHarness {
    function check(uint64 sizeFrom, uint64 sizeTo, bytes32[][] calldata proofs)
        external
        pure
        returns (uint256 carried, uint256 expectedRight)
    {
        return checkConsistencyProofShape(sizeFrom, sizeTo, proofs);
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
        return uint64(2 * leaves - popcount64(leaves));
    }

    /// @notice Honest proof shape for sizeFrom -> sizeTo per the draft walk:
    ///    one zero-filled path per origin peak with the walked length, plus
    ///    the number of distinct committing peaks.
    function _oracleShape(uint64 sizeFrom, uint64 sizeTo)
        internal
        pure
        returns (bytes32[][] memory proofs, uint256 carried)
    {
        uint256[] memory fromPeaks = sizeFrom == 0
            ? new uint256[](0)
            : peaks(uint256(sizeFrom) - 1);
        proofs = new bytes32[][](fromPeaks.length);
        uint256 last = type(uint256).max;
        for (uint256 i = 0; i < fromPeaks.length; i++) {
            (uint256 len, uint256 peak) =
                inclusionProofPathLength(fromPeaks[i], uint256(sizeTo) - 1);
            proofs[i] = new bytes32[](len);
            if (peak != last) {
                carried++;
                last = peak;
            }
        }
    }

    function testFuzz_shapeMatchesDraftWalk(uint64 leavesFrom, uint64 leavesTo)
        public
        view
    {
        leavesFrom = uint64(bound(leavesFrom, 0, MAX_LEAVES));
        leavesTo = uint64(bound(leavesTo, 1, MAX_LEAVES));
        vm.assume(leavesFrom < leavesTo);
        uint64 sizeFrom = _mmrSize(leavesFrom);
        uint64 sizeTo = _mmrSize(leavesTo);

        (bytes32[][] memory proofs, uint256 wantCarried) =
            _oracleShape(sizeFrom, sizeTo);
        (uint256 carried, uint256 expectedRight) =
            harness.check(sizeFrom, sizeTo, proofs);

        assertEq(carried, wantCarried, "carried peaks");
        assertEq(
            carried + expectedRight,
            peaks(uint256(sizeTo) - 1).length,
            "carried + right must cover every target peak"
        );
    }

    /// @notice Lengthening any one honest path by one is rejected, naming
    ///    the peak and the length the sizes imply.
    function testFuzz_shapeRejectsPerturbedPathLength(
        uint64 leavesFrom,
        uint64 leavesTo,
        uint256 which
    ) public {
        leavesFrom = uint64(bound(leavesFrom, 1, MAX_LEAVES - 1));
        leavesTo = uint64(bound(leavesTo, 2, MAX_LEAVES));
        vm.assume(leavesFrom < leavesTo);
        uint64 sizeFrom = _mmrSize(leavesFrom);
        uint64 sizeTo = _mmrSize(leavesTo);

        (bytes32[][] memory proofs,) = _oracleShape(sizeFrom, sizeTo);
        which = bound(which, 0, proofs.length - 1);
        uint256 honest = proofs[which].length;
        proofs[which] = new bytes32[](honest + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyPathLengthMismatch.selector,
                which,
                honest,
                honest + 1
            )
        );
        harness.check(sizeFrom, sizeTo, proofs);
    }

    function testFuzz_isCompleteMMRMatchesIndexHeight(uint64 size)
        public
        pure
    {
        assertEq(isCompleteMMR(size), indexHeight(size) == 0);
    }

    function testFuzz_everyLeafCountGivesACompleteSize(uint64 leaves)
        public
        pure
    {
        leaves = uint64(bound(leaves, 0, MAX_LEAVES));
        assertTrue(isCompleteMMR(_mmrSize(leaves)));
    }

    function test_incompleteSizesRejected() public {
        bytes32[][] memory none = new bytes32[][](0);
        uint64[3] memory bad = [uint64(2), 5, 6];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IUnivocityErrors.IncompleteTreeSize.selector, bad[i]
                )
            );
            harness.check(0, bad[i], none);
        }
    }
}
