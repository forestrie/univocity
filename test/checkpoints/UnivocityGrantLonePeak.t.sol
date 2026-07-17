// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Grant inclusion where the grant leaf is itself an accumulator peak,
///   so its inclusion path is legitimately EMPTY.
///
///   An owner log with N leaves has a lone height-0 peak — its last leaf — when
///   N is odd. A child log's create grant is by construction the owner's most
///   recent leaf, so roughly half of all child-log creations present an empty
///   grant inclusion path. That must be accepted: an empty path asserts the
///   leaf IS a peak, and it verifies as an exact peak match (see
///   _Univocity._applyInclusionGrant).
///
///   Regression: _applyInclusionGrant previously accepted an empty path only
///   when `ownerLog.size == 1`, so a lone-peak grant against a GROWN owner
///   reverted InvalidPaymentReceipt. The arbor publisher terminally acks a
///   mined revert, which permanently stranded the child log.
///
///   These tests use canonical MMR sizes only. The owner is a 3-leaf MMR
///   (size 4, leafCount 3 — odd), whose accumulator is
///   [parent(leaf0, leaf1), leaf2]; leaf2 is the lone height-0 peak that
///   peakIndex(3, 0) = 1 selects for an empty path.
import "./UnivocityTestHelper.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    InclusionProof,
    LogState,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

contract UnivocityGrantLonePeakTest is UnivocityTestHelper {
    bytes32 internal constant CHILD_LOG_ID = keccak256("child-data-log");
    bytes8 internal constant IDTIMESTAMP_CHILD = bytes8(uint64(2));

    /// @notice Second leaf of the owner log; filler, never a grant.
    bytes32 internal constant OWNER_LEAF1 = keccak256("owner-filler-leaf");

    function setUp() public override {
        super.setUp();
    }

    /// @notice Root's first checkpoint publishing a chosen accumulator at a
    ///    chosen canonical size. treeSize1 == 0 means the new accumulator IS
    ///    rightPeaks (no paths to walk), so the test controls the owner's peaks
    ///    exactly.
    function _rootFirstCheckpointWithAcc(bytes32[] memory acc, uint64 size)
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: size,
            paths: new bytes32[][](0),
            rightPeaks: acc
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(acc));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _rootGrant() internal view returns (PublishGrant memory) {
        return _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
    }

    function _childGrant() internal view returns (PublishGrant memory) {
        return _publishGrant(
            CHILD_LOG_ID,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
    }

    /// @notice Seed the owner (root) as a canonical 3-leaf MMR (size 4) whose
    ///    leaves are [rootGrantLeaf, OWNER_LEAF1, lastLeaf]. Accumulator is
    ///    [parent(rootGrantLeaf, OWNER_LEAF1), lastLeaf] — lastLeaf is the lone
    ///    height-0 peak. The root's own grant proves at index 0 with a
    ///    one-element path, so this is a normal, fully verified checkpoint.
    function _seedOwnerThreeLeaves(bytes32 lastLeaf) internal {
        univocity = _deployUnivocityKS256();
        PublishGrant memory root = _rootGrant();
        bytes32 rootLeaf = _leafCommitment(IDTIMESTAMP_AUTH, root);

        bytes32[] memory acc = new bytes32[](2);
        acc[0] = hashPosPair64(3, rootLeaf, OWNER_LEAF1);
        acc[1] = lastLeaf;

        univocity.publishCheckpoint(
            _rootFirstCheckpointWithAcc(acc, 4),
            _buildPaymentInclusionProof(0, _path1(OWNER_LEAF1)),
            IDTIMESTAMP_AUTH,
            root
        );
    }

    /// @notice Seed the owner as a canonical 2-leaf MMR (size 3): accumulator
    ///    is a single height-1 peak, so there is NO height-0 peak at all.
    function _seedOwnerTwoLeaves() internal {
        univocity = _deployUnivocityKS256();
        PublishGrant memory root = _rootGrant();
        bytes32 rootLeaf = _leafCommitment(IDTIMESTAMP_AUTH, root);

        bytes32[] memory acc = new bytes32[](1);
        acc[0] = hashPosPair64(3, rootLeaf, OWNER_LEAF1);

        univocity.publishCheckpoint(
            _rootFirstCheckpointWithAcc(acc, 3),
            _buildPaymentInclusionProof(0, _path1(OWNER_LEAF1)),
            IDTIMESTAMP_AUTH,
            root
        );
    }

    function _childFirstCheckpoint()
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        return _buildConsistencyReceipt(_toAcc(keccak256("child-first-peak")));
    }

    /// @notice Precondition: the grant leaf really is the owner's lone height-0
    ///    peak — exactly what an empty path asserts.
    function test_ownerAccumulator_lastPeakIsTheGrantLeaf() public {
        bytes32 childLeaf = _leafCommitment(IDTIMESTAMP_CHILD, _childGrant());
        _seedOwnerThreeLeaves(childLeaf);

        LogState memory st = univocity.logState(AUTHORITY_LOG_ID);
        assertEq(st.size, 4, "canonical 3-leaf mmr");
        assertEq(st.accumulator.length, 2, "odd leaf count -> two peaks");
        assertEq(
            st.accumulator[1], childLeaf, "lone height-0 peak is the grant"
        );
    }

    /// @notice THE REGRESSION: a lone-peak grant against a GROWN owner presents
    ///    an empty path and must publish. Previously reverted
    ///    InvalidPaymentReceipt solely because ownerLog.size != 1.
    function test_lonePeakGrant_emptyPath_againstGrownOwner_succeeds() public {
        PublishGrant memory child = _childGrant();
        bytes32 childLeaf = _leafCommitment(IDTIMESTAMP_CHILD, child);
        _seedOwnerThreeLeaves(childLeaf);
        assertGt(
            univocity.logState(AUTHORITY_LOG_ID).size,
            1,
            "owner must be grown or the old guard would have allowed it"
        );

        bytes32[] memory emptyPath;
        univocity.publishCheckpoint(
            _childFirstCheckpoint(),
            _buildPaymentInclusionProof(0, emptyPath),
            IDTIMESTAMP_CHILD,
            child
        );

        assertTrue(
            univocity.isLogInitialized(CHILD_LOG_ID),
            "child log created from a lone-peak grant"
        );
        assertEq(univocity.logConfig(CHILD_LOG_ID).authLogId, AUTHORITY_LOG_ID);
    }

    /// @notice Fails closed: empty path whose leaf is NOT the owner's height-0
    ///    peak. The owner's last leaf is some other log's grant.
    function test_emptyPath_leafNotThePeak_reverts() public {
        _seedOwnerThreeLeaves(keccak256("someone-elses-grant-leaf"));

        bytes32[] memory emptyPath;
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            _childFirstCheckpoint(),
            _buildPaymentInclusionProof(0, emptyPath),
            IDTIMESTAMP_CHILD,
            _childGrant()
        );
        assertFalse(univocity.isLogInitialized(CHILD_LOG_ID));
    }

    /// @notice Fails closed: an owner with an EVEN leaf count has no height-0
    ///    peak, so peakIndex selects an out-of-range peak and
    ///    proofLengthRootStorage returns bytes32(0). An empty path can never
    ///    verify against such an owner.
    function test_emptyPath_ownerHasNoHeight0Peak_reverts() public {
        _seedOwnerTwoLeaves();
        assertEq(
            univocity.logState(AUTHORITY_LOG_ID).accumulator.length,
            1,
            "even leaf count -> single height-1 peak"
        );

        bytes32[] memory emptyPath;
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            _childFirstCheckpoint(),
            _buildPaymentInclusionProof(0, emptyPath),
            IDTIMESTAMP_CHILD,
            _childGrant()
        );
        assertFalse(univocity.isLogInitialized(CHILD_LOG_ID));
    }

    /// @notice Fails closed: the leaf is sha256 over the grant's own fields, so
    ///    a caller cannot widen the grant and still match the committed peak.
    ///    Here the attacker asks for an AUTH log where the owner granted DATA.
    function test_emptyPath_escalatedGrant_reverts() public {
        PublishGrant memory child = _childGrant();
        _seedOwnerThreeLeaves(_leafCommitment(IDTIMESTAMP_CHILD, child));

        PublishGrant memory escalated = child;
        escalated.grant = GRANT_ROOT;
        escalated.request = GC_AUTH_LOG;

        bytes32[] memory emptyPath;
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            _childFirstCheckpoint(),
            _buildPaymentInclusionProof(0, emptyPath),
            IDTIMESTAMP_CHILD,
            escalated
        );
        assertFalse(univocity.isLogInitialized(CHILD_LOG_ID));
    }

    /// @notice Fails closed: the sequencing idtimestamp is committed too, so a
    ///    grant cannot be replayed under a different one.
    function test_emptyPath_wrongIdtimestamp_reverts() public {
        PublishGrant memory child = _childGrant();
        _seedOwnerThreeLeaves(_leafCommitment(IDTIMESTAMP_CHILD, child));

        bytes32[] memory emptyPath;
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            _childFirstCheckpoint(),
            _buildPaymentInclusionProof(0, emptyPath),
            bytes8(uint64(0xdead)),
            child
        );
        assertFalse(univocity.isLogInitialized(CHILD_LOG_ID));
    }
}
