// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Consistency proof chain tests: the declared base of every proof
///   must be the size the contract actually holds (FOR-567). Split per
///   test/checkpoints/README.md.
///
///   `consistentRoots` only checks that the stored accumulator has as many
///   peaks as `peaks(treeSize1 - 1)`. Many sizes share a peak count, so
///   before the fix a proof could declare a base other than the anchored
///   size and still fold. Four routes are exercised, each against a log
///   that already holds an accumulator, and each must now revert:
///   - base 0: the fold adopted `rightPeaks` verbatim (stored state ignored)
///   - aliased base: size 1 held, base 3 declared (both one peak)
///   - chain break: proof i declares a base other than proof i-1's treeSize2
///   - shrinking chain: contiguous bases, but one step goes 3 -> 2
///   Each route was run green against 8143868 before the fix.

import "./UnivocityTestHelper.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {hashPosPair64} from "@univocity/algorithms/binUtils.sol";
import {
    inclusionProofPathLength
} from "@univocity/algorithms/inclusionProofPath.sol";

/// @notice Harness so tests compute expected path lengths from the same
///    arithmetic the contract uses, rather than hardcoding them.
contract InclusionProofPathLengthHarness {
    function length(uint256 i, uint256 c)
        external
        pure
        returns (uint256 len, uint256 peak)
    {
        return inclusionProofPathLength(i, c);
    }
}

contract UnivocityConsistencyProofTest is UnivocityTestHelper {
    bytes32 internal constant PEAK1 = keccak256("peak1");

    InclusionProofPathLengthHarness internal pathLengthHarness;

    function setUp() public override {
        super.setUp();
        pathLengthHarness = new InclusionProofPathLengthHarness();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
        // TEST_LOG: size 1, accumulator [PEAK1]; owner is the authority log.
        _publishFirstToTestLog(univocity, PEAK1, authorityLeaf0, grantTestLog);
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    // --- honest baseline ---------------------------------------------------

    /// @notice Honest extension of TEST_LOG from size 1 to 3: the stored peak
    ///    is folded with the supplied sibling. Same shape as the aliased-base
    ///    case below, differing only in the declared base.
    function test_extend_declaredBaseMatchesStoredSize_succeeds() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths[0]);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, new bytes32[](0));

        _publishTestLog(_signReceipt(proofs, _toAcc(root3)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 3);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], root3);
    }

    // --- FOR-567 -----------------------------------------------------------

    /// @notice Route 1: base-0 proof against the authority log (size 3). The
    ///    fold used to ignore the stored accumulator and adopt `rightPeaks`
    ///    as-is, letting the root key holder replace the anchored history
    ///    with a peak of their choosing. The root grant is replayed with the
    ///    same inclusion proof the honest extension tests use. Declared
    ///    target (4) is above the current size so the base check is reached
    ///    (rather than SizeMustIncrease firing first).
    function test_publishCheckpoint_base0OnInitialisedLog_reverts() public {
        bytes32 forged = keccak256("forged-root");
        bytes32 before = univocity.logState(AUTHORITY_LOG_ID).accumulator[0];
        assertTrue(before != forged);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(0, 4, new bytes32[][](0), _toAcc(forged));
        ConsistencyReceipt memory receipt =
            _signReceipt(proofs, _toAcc(forged));

        vm.prank(BOOTSTRAP);
        vm.expectRevert(_baseMismatch(3, 0));
        univocity.publishCheckpoint(
            receipt,
            _buildPaymentInclusionProof(0, _path1(authorityLeaf1)),
            IDTIMESTAMP_AUTH,
            grant1
        );

        assertEq(univocity.logState(AUTHORITY_LOG_ID).size, 3);
        assertEq(univocity.logState(AUTHORITY_LOG_ID).accumulator[0], before);
    }

    /// @notice Route 2: TEST_LOG holds size 1 (one peak). A proof declaring
    ///    base 3 (also one peak) passes the peak-count check; before the fix
    ///    the stored peak was hashed as though it sat at MMR index 2 with a
    ///    sibling the caller chose.
    function test_publishCheckpoint_aliasedBaseOnInitialisedLog_reverts()
        public
    {
        bytes32[][] memory paths = _paths1(_path1(keccak256("chosen")));
        // What the fold computes when it believes PEAK1 is the peak of MMR(2).
        bytes32 bogus =
            includedRootHarness.callIncludedRoot(2, PEAK1, paths[0]);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(3, 7, paths, new bytes32[](0));

        vm.expectRevert(_baseMismatch(1, 3));
        _publishTestLog(_signReceipt(proofs, _toAcc(bogus)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], PEAK1);
    }

    /// @notice Route 3: an honest 1 -> 3 proof followed by a proof that
    ///    declares base 1 rather than 3. Before the fix the chain was never
    ///    checked for contiguity, so the second proof folded the
    ///    intermediate root as a leaf.
    function test_publishCheckpoint_chainBaseMismatch_reverts() public {
        bytes32[][] memory paths0 = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths0[0]);
        bytes32[][] memory paths1 = _paths1(_path1(keccak256("chosen")));
        bytes32 bogus =
            includedRootHarness.callIncludedRoot(0, root3, paths1[0]);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](2);
        proofs[0] = _proof(1, 3, paths0, new bytes32[](0));
        proofs[1] = _proof(1, 7, paths1, new bytes32[](0));

        vm.expectRevert(_baseMismatch(3, 1));
        _publishTestLog(_signReceipt(proofs, _toAcc(bogus)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice Route 4: a contiguous chain that shrinks mid-way (1 -> 3 ->
    ///    2 -> 7). Each base matches the previous treeSize2, but the 3 -> 2
    ///    step re-homes the size-3 root as one of two size-2 peaks, after
    ///    which it is hashed at a position no honest MMR gives it.
    function test_publishCheckpoint_chainShrinks_reverts() public {
        bytes32 chosen = keccak256("chosen");
        bytes32[][] memory paths0 = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths0[0]);
        // 3 -> 2: fold root3 (as peak of MMR(2)) with `chosen`, then pad to
        // the two peaks size 2 requires.
        bytes32[][] memory paths1 = _paths1(_path1(chosen));
        bytes32 node =
            includedRootHarness.callIncludedRoot(2, root3, paths1[0]);
        // 2 -> 7: both size-2 "peaks" prove to the same root at index 0/1.
        bytes32[][] memory paths2 = new bytes32[][](2);
        paths2[0] = _path1(chosen);
        paths2[1] = _path1(node);
        bytes32 bogus =
            includedRootHarness.callIncludedRoot(0, node, paths2[0]);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](3);
        proofs[0] = _proof(1, 3, paths0, new bytes32[](0));
        proofs[1] = _proof(3, 2, paths1, _toAcc(chosen));
        proofs[2] = _proof(2, 7, paths2, new bytes32[](0));

        vm.expectRevert(IUnivocityErrors.InvalidConsistencyProof.selector);
        _publishTestLog(_signReceipt(proofs, _toAcc(bogus)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    // --- checkConsistencyProofShape errors -----------------------------------

    /// @notice A declared target size that is not a complete MMR reverts
    ///    IncompleteTreeSize(5), before any path/peak-count check runs.
    function test_publishCheckpoint_incompleteTreeSizeTarget_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 5, paths, new bytes32[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.IncompleteTreeSize.selector, uint64(5)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(keccak256("whatever"))));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice The keyless "replay the old signature at an inflated size"
    ///    attack: an empty path at 1 -> 3 (the path length peak index 0
    ///    needs there is 1) reverts ConsistencyPathLengthMismatch(0, 1, 0).
    function test_publishCheckpoint_emptyPathAt1To3_reverts() public {
        bytes32[][] memory paths = _paths1(new bytes32[](0));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, new bytes32[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyPathLengthMismatch.selector,
                uint256(0),
                uint256(1),
                uint256(0)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(PEAK1)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice Same attack shape at 1 -> 7: the expected length (what the
    ///    error carries) comes from inclusionProofPathLength, not a guess.
    function test_publishCheckpoint_emptyPathAt1To7_reverts() public {
        (uint256 expectedLen,) = pathLengthHarness.length(0, 6);
        assertEq(expectedLen, 2);

        bytes32[][] memory paths = _paths1(new bytes32[](0));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 7, paths, new bytes32[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyPathLengthMismatch.selector,
                uint256(0),
                expectedLen,
                uint256(0)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(PEAK1)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice 1 -> 4 with an honest origin path but no rightPeaks: MMR(4)
    ///    has two peaks, and the second (the new leaf) must arrive as a
    ///    rightPeak. Omitting it reverts ConsistencyPeakCountMismatch(1, 0).
    function test_publishCheckpoint_missingRightPeakAt1To4_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 4, paths, new bytes32[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyPeakCountMismatch.selector,
                uint256(1),
                uint256(0)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(keccak256("whatever"))));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice 1 -> 3 with an honest origin path plus a junk rightPeak:
    ///    MMR(3) has one peak, fully carried from the origin, so any
    ///    rightPeak reverts ConsistencyPeakCountMismatch(0, 1).
    function test_publishCheckpoint_surplusRightPeakAt1To3_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, _toAcc(keccak256("junk")));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyPeakCountMismatch.selector,
                uint256(0),
                uint256(1)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(keccak256("whatever"))));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    // --- honest chained growth -----------------------------------------------

    /// @notice 1 -> 3 -> 4 -> 7 all succeed in sequence on TEST_LOG, and the
    ///    on-chain accumulator matches the canonical MMR node values
    ///    (hashPosPair64) at each step.
    function test_extend_chainedGrowth_1To3_3To4_4To7_succeeds() public {
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 node2 = hashPosPair64(3, PEAK1, leaf1);

        ConsistencyProof[] memory proofs1 = new ConsistencyProof[](1);
        proofs1[0] = _proof(1, 3, _paths1(_path1(leaf1)), new bytes32[](0));
        _publishTestLog(_signReceipt(proofs1, _toAcc(node2)));
        assertEq(univocity.logState(TEST_LOG_ID).size, 3);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], node2);

        bytes32 leaf3 = keccak256("leaf3");
        ConsistencyProof[] memory proofs2 = new ConsistencyProof[](1);
        proofs2[0] = _proof(3, 4, _paths1(new bytes32[](0)), _toAcc(leaf3));
        bytes32[] memory acc4 = new bytes32[](2);
        acc4[0] = node2;
        acc4[1] = leaf3;
        _publishTestLog(_signReceipt(proofs2, acc4));
        assertEq(univocity.logState(TEST_LOG_ID).size, 4);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], node2);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[1], leaf3);

        bytes32 leaf4 = keccak256("leaf4");
        bytes32 node5 = hashPosPair64(6, leaf3, leaf4);
        bytes32 node6 = hashPosPair64(7, node2, node5);
        bytes32[][] memory paths3 = new bytes32[][](2);
        paths3[0] = _path1(node5);
        paths3[1] = _path2(leaf4, node2);
        ConsistencyProof[] memory proofs3 = new ConsistencyProof[](1);
        proofs3[0] = _proof(4, 7, paths3, new bytes32[](0));
        _publishTestLog(_signReceipt(proofs3, _toAcc(node6)));
        assertEq(univocity.logState(TEST_LOG_ID).size, 7);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], node6);
    }

    // --- fixtures ----------------------------------------------------------

    function _baseMismatch(uint64 expected, uint64 declared)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            IUnivocityErrors.ConsistencyBaseMismatch.selector,
            expected,
            declared
        );
    }

    function _proof(
        uint64 treeSize1,
        uint64 treeSize2,
        bytes32[][] memory paths,
        bytes32[] memory rightPeaks
    ) internal pure returns (ConsistencyProof memory) {
        return ConsistencyProof({
            treeSize1: treeSize1,
            treeSize2: treeSize2,
            paths: paths,
            rightPeaks: rightPeaks
        });
    }

    function _paths1(bytes32[] memory path)
        internal
        pure
        returns (bytes32[][] memory paths)
    {
        paths = new bytes32[][](1);
        paths[0] = path;
    }

    /// @notice Sign `finalAcc` as the detached payload with the KS256 root
    ///    key shared by both logs. The caller states the accumulator the
    ///    fold will produce; a mismatch surfaces as a signature failure.
    function _signReceipt(
        ConsistencyProof[] memory proofs,
        bytes32[] memory finalAcc
    ) internal pure returns (ConsistencyReceipt memory) {
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(finalAcc));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Extend TEST_LOG, replaying the data-log grant with its
    ///    inclusion proof in the (unchanged) authority log.
    function _publishTestLog(ConsistencyReceipt memory receipt) internal {
        univocity.publishCheckpoint(
            receipt,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            grantTestLog
        );
    }
}
