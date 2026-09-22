// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Consistency proof chain tests (FOR-567). Every proof in a chain
///   must start at the size the contract holds (then at the previous proof's
///   treeSize2), grow to a complete MMR size, and carry paths of the length
///   the two sizes imply. Cases, each against a log that already holds an
///   accumulator:
///   - base 0 declared for a log at size 3
///   - base 3 declared for a log at size 1 (both sizes have one peak)
///   - a chain whose second proof does not start at the first proof's target
///   - a chain with a step that does not grow (3 -> 2)
///   - an incomplete target size; empty paths; missing and surplus rightPeaks
///   - a 1 -> 3 -> 4 -> 7 chain that is accepted, with the accumulator
///     checked at each step
///   ADR-0066: the protected header carries tree-size-2, so the
///   checkpoint signature covers it, and the contract requires it to equal
///   the last proof's treeSize2. tree-size-1 is not signed: each proof's
///   base is pinned by the fold to the anchored size.
///   - a receipt signed for 7 -> 8 submitted as 7 -> 10 (same proof shape)
///   - 15 -> 16 submitted as 18 and 22 (three targets, one shape)
///   - a header without the label, or carrying a negative size
///   - a two-proof receipt signed for the size its chain reaches, and for
///     the intermediate size
///   - header keys out of canonical order, duplicate keys, a tag, an
///     indefinite-length item, a key beyond int64, a non-shortest
///     argument, trailing bytes and an over-declared map length rejected;
///     a simple value under an unread label skipped
///   - a first checkpoint signed for size 1 submitted at 2^64 - 1 and at the
///     other one-peak sizes (second contract)
///   Split per test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {hashPosPair64} from "@univocity/algorithms/binUtils.sol";
import {
    ALG_KS256,
    LABEL_TREE_SIZE_2,
    MAJOR_TYPE_UINT,
    MAJOR_TYPE_NEGINT
} from "@univocity/cosecbor/constants.sol";
import {
    buildSigStructure,
    DuplicateHeaderLabel,
    HeaderLabelOrder,
    IntegerOutOfRange,
    InvalidCoseCborStructure,
    UnexpectedMajorType
} from "@univocity/cosecbor/cosecbor.sol";
import {
    cborInt,
    cborUint,
    VDS_CONSISTENCY
} from "../shared/ConsistencyHeader.sol";
import {
    inclusionProofPathLength
} from "../algorithms/InclusionProofPathOracle.sol";

/// @notice Expected revert data for ConsistencyReceiptSizeMismatch.
function sizeMismatch(uint64 declared, uint64 signed)
    pure
    returns (bytes memory)
{
    return abi.encodeWithSelector(
        IUnivocityErrors.ConsistencyReceiptSizeMismatch.selector,
        declared,
        signed
    );
}

/// @notice Harness so tests compute expected path lengths from the draft's
///    own walk (the test-tree oracle), independently of the bitmap
///    arithmetic the contract uses.
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

    // --- accepted extension ------------------------------------------------

    /// @notice Extension of TEST_LOG from size 1 to 3: the stored peak is
    ///    proven to the size-3 peak with the supplied sibling. Same shape as
    ///    the declared-base-3 case below, differing only in the declared
    ///    base.
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

    /// @notice A proof declaring base 0 for the authority log, which is at
    ///    size 3, reverts ConsistencyBaseMismatch(3, 0). The root grant and
    ///    inclusion proof are the ones the extension tests use. The declared
    ///    target (4) exceeds the current size so the base check is reached
    ///    rather than SizeMustIncrease.
    function test_publishCheckpoint_base0OnInitialisedLog_reverts() public {
        bytes32 replacement = keccak256("replacement-peak");
        bytes32 before = univocity.logState(AUTHORITY_LOG_ID).accumulator[0];
        assertTrue(before != replacement);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(0, 4, new bytes32[][](0), _toAcc(replacement));
        ConsistencyReceipt memory receipt =
            _signReceipt(proofs, _toAcc(replacement));

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

    /// @notice TEST_LOG is at size 1. A proof declaring base 3 reverts
    ///    ConsistencyBaseMismatch(1, 3). Both sizes have one peak, so a
    ///    peak-count check alone would not distinguish them.
    function test_publishCheckpoint_aliasedBaseOnInitialisedLog_reverts()
        public
    {
        bytes32[][] memory paths = _paths1(_path1(keccak256("sibling")));
        // The root proven with PEAK1 taken as node index 2.
        bytes32 proven =
            includedRootHarness.callIncludedRoot(2, PEAK1, paths[0]);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(3, 7, paths, new bytes32[](0));

        vm.expectRevert(_baseMismatch(1, 3));
        _publishTestLog(_signReceipt(proofs, _toAcc(proven)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], PEAK1);
    }

    /// @notice A 1 -> 3 proof followed by a proof declaring base 1 rather
    ///    than 3 reverts ConsistencyBaseMismatch(3, 1): each proof must start
    ///    at the previous proof's target.
    function test_publishCheckpoint_chainBaseMismatch_reverts() public {
        bytes32[][] memory paths0 = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths0[0]);
        bytes32[][] memory paths1 = _paths1(_path1(keccak256("sibling")));
        bytes32 proven =
            includedRootHarness.callIncludedRoot(0, root3, paths1[0]);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](2);
        proofs[0] = _proof(1, 3, paths0, new bytes32[](0));
        proofs[1] = _proof(1, 7, paths1, new bytes32[](0));

        vm.expectRevert(_baseMismatch(3, 1));
        _publishTestLog(_signReceipt(proofs, _toAcc(proven)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice A chain 1 -> 3 -> 2 -> 7 reverts InvalidConsistencyProof at
    ///    the 3 -> 2 step: every proof must grow the tree (and 2 is not a
    ///    complete MMR size).
    function test_publishCheckpoint_chainShrinks_reverts() public {
        bytes32 sibling = keccak256("sibling");
        bytes32[][] memory paths0 = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths0[0]);
        // 3 -> 2 step: root3 proven with `sibling`, padded with a second peak.
        bytes32[][] memory paths1 = _paths1(_path1(sibling));
        bytes32 node =
            includedRootHarness.callIncludedRoot(2, root3, paths1[0]);
        // 2 -> 7 step: both peaks prove the same root.
        bytes32[][] memory paths2 = new bytes32[][](2);
        paths2[0] = _path1(sibling);
        paths2[1] = _path1(node);
        bytes32 proven =
            includedRootHarness.callIncludedRoot(0, node, paths2[0]);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](3);
        proofs[0] = _proof(1, 3, paths0, new bytes32[](0));
        proofs[1] = _proof(3, 2, paths1, _toAcc(sibling));
        proofs[2] = _proof(2, 7, paths2, new bytes32[](0));

        vm.expectRevert(IUnivocityErrors.InvalidConsistencyProof.selector);
        _publishTestLog(_signReceipt(proofs, _toAcc(proven)));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    // --- proof shape -------------------------------------------------------

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
        _publishTestLog(_signReceipt(proofs, _toAcc(keccak256("unreached"))));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice An empty path at 1 -> 3 reverts
    ///    ConsistencyPathLengthMismatch(0, 1, 0): the path for peak index 0
    ///    must have length 1. With an empty path the proven root would be
    ///    the stored peak unchanged, so a receipt already published for size 1
    ///    would verify against a larger declared size.
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

    /// @notice The same shape at 1 -> 7: the expected length carried by the
    ///    error comes from inclusionProofPathLength rather than a literal.
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

    /// @notice 1 -> 4 with a correct origin path but no rightPeaks: MMR(4)
    ///    has two peaks, and the second (the new leaf) must arrive as a
    ///    rightPeak. Omitting it reverts
    ///    ConsistencyRightPeakCountMismatch(1, 0).
    function test_publishCheckpoint_missingRightPeakAt1To4_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 4, paths, new bytes32[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyRightPeakCountMismatch.selector,
                uint256(1),
                uint256(0)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(keccak256("unreached"))));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice 1 -> 3 with a correct origin path plus a surplus rightPeak:
    ///    MMR(3) has one peak, proven from the origin, so any
    ///    rightPeak reverts ConsistencyRightPeakCountMismatch(0, 1).
    function test_publishCheckpoint_surplusRightPeakAt1To3_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, _toAcc(keccak256("surplus")));

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyRightPeakCountMismatch.selector,
                uint256(0),
                uint256(1)
            )
        );
        _publishTestLog(_signReceipt(proofs, _toAcc(keccak256("unreached"))));

        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    // --- chained growth ----------------------------------------------------

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

    // --- ADR-0066: signed tree sizes -------------------------------------

    /// @notice 7 -> 8 and 7 -> 10 have the same proof shape (the stored
    ///    height-2 peak stays above the split with an empty path, one
    ///    rightPeak), so the fold accepts the same accumulator at both. A
    ///    receipt signed for 7 -> 8 submitted with treeSize2 = 10 reverts
    ///    ConsistencyReceiptSizeMismatch(10, 8) and the log stays at 7; the
    ///    same receipt at the size it was signed for is accepted.
    function test_publishCheckpoint_signedTargetDiffersFromDeclared_reverts()
        public
    {
        bytes32 root7 = _growTestLogTo7();
        bytes32 leaf = keccak256("leaf7");
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(7, 8, _paths1(new bytes32[](0)), _toAcc(leaf));
        ConsistencyReceipt memory receipt =
            _signReceipt(proofs, _acc2(root7, leaf));

        receipt.consistencyProofs[0].treeSize2 = 10;
        vm.expectRevert(sizeMismatch(10, 8));
        _publishTestLog(receipt);
        assertEq(univocity.logState(TEST_LOG_ID).size, 7);

        receipt.consistencyProofs[0].treeSize2 = 8;
        _publishTestLog(receipt);
        assertEq(univocity.logState(TEST_LOG_ID).size, 8);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], root7);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[1], leaf);
    }

    /// @notice From 15 the targets 16, 18 and 22 share one proof shape. A
    ///    receipt signed for 15 -> 16 reverts at 18 and 22 with the signed
    ///    size, and is accepted at 16 only.
    function test_publishCheckpoint_shapeSharingTargets_onlySignedAccepted()
        public
    {
        bytes32 root7 = _growTestLogTo7();
        bytes32[][] memory p = _paths1(_path1(keccak256("sibling715")));
        bytes32 root15 = includedRootHarness.callIncludedRoot(6, root7, p[0]);
        ConsistencyProof[] memory g = new ConsistencyProof[](1);
        g[0] = _proof(7, 15, p, new bytes32[](0));
        _publishTestLog(_signReceipt(g, _toAcc(root15)));
        assertEq(univocity.logState(TEST_LOG_ID).size, 15);

        bytes32 leaf = keccak256("leaf15");
        ConsistencyProof[] memory q = new ConsistencyProof[](1);
        q[0] = _proof(15, 16, _paths1(new bytes32[](0)), _toAcc(leaf));
        ConsistencyReceipt memory receipt =
            _signReceipt(q, _acc2(root15, leaf));

        uint64[2] memory others = [uint64(18), 22];
        for (uint256 k = 0; k < others.length; k++) {
            receipt.consistencyProofs[0].treeSize2 = others[k];
            vm.expectRevert(sizeMismatch(others[k], 16));
            _publishTestLog(receipt);
        }
        assertEq(univocity.logState(TEST_LOG_ID).size, 15);

        receipt.consistencyProofs[0].treeSize2 = 16;
        _publishTestLog(receipt);
        assertEq(univocity.logState(TEST_LOG_ID).size, 16);
    }

    /// @notice The alg-only header receipts carried before ADR-0066 reverts
    ///    MissingSignedTreeSize: the label is required.
    function test_publishCheckpoint_headerWithoutTreeSize2_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths[0]);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, new bytes32[](0));
        bytes memory algOnly = abi.encodePacked(hex"a101", cborInt(ALG_KS256));
        assertEq(algOnly, hex"a1013a00010106");

        vm.expectRevert(IUnivocityErrors.MissingSignedTreeSize.selector);
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), algOnly));
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice A size is a CBOR unsigned integer. A negative value under
    ///    tree-size-2 reverts UnexpectedMajorType(1, 0) rather than being
    ///    read through int64 and compared.
    function test_publishCheckpoint_negativeTreeSize2_reverts() public {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths[0]);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, new bytes32[](0));
        bytes memory negative = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            cborInt(-3)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                UnexpectedMajorType.selector,
                MAJOR_TYPE_NEGINT,
                MAJOR_TYPE_UINT
            )
        );
        _publishTestLog(
            _signReceiptWithHeader(proofs, _toAcc(root3), negative)
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice A receipt carrying two proofs, 1 -> 3 and 3 -> 4, is signed
    ///    for the size its chain reaches, 4. Signed for the intermediate
    ///    size 3 it reverts ConsistencyReceiptSizeMismatch(4, 3). The base
    ///    of each proof is pinned by the fold, not the header, which is
    ///    what lets the publisher relay several sealed steps under the
    ///    head checkpoint's signature.
    function test_publishCheckpoint_chainInOneReceipt_signedForFinalSize()
        public
    {
        bytes32 leaf1 = keccak256("leaf1");
        bytes32 node2 = hashPosPair64(3, PEAK1, leaf1);
        bytes32 leaf3 = keccak256("leaf3");
        ConsistencyProof[] memory proofs = new ConsistencyProof[](2);
        proofs[0] = _proof(1, 3, _paths1(_path1(leaf1)), new bytes32[](0));
        proofs[1] = _proof(3, 4, _paths1(new bytes32[](0)), _toAcc(leaf3));
        bytes32[] memory acc4 = _acc2(node2, leaf3);

        vm.expectRevert(sizeMismatch(4, 3));
        _publishTestLog(
            _signReceiptWithHeader(
                proofs, acc4, _consistencyProtectedHeader(ALG_KS256, 3)
            )
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);

        _publishTestLog(_signReceipt(proofs, acc4));
        assertEq(univocity.logState(TEST_LOG_ID).size, 4);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], node2);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[1], leaf3);
    }

    /// @notice Keys must be in canonical order. The sealer's header with
    ///    its keys reversed, {tree-size-2, 395, 1}, reverts
    ///    HeaderLabelOrder(395): the Go decoder rejects the same bytes.
    function test_publishCheckpoint_headerKeyOrder_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory reversed = abi.encodePacked(
            hex"a3",
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3),
            hex"19018b",
            cborUint(VDS_CONSISTENCY),
            hex"01",
            cborInt(ALG_KS256)
        );

        vm.expectRevert(
            abi.encodeWithSelector(HeaderLabelOrder.selector, int64(395))
        );
        _publishTestLog(
            _signReceiptWithHeader(proofs, _toAcc(root3), reversed)
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice tree-size-2 appearing twice, {.., ts2: 3, ts2: 10}, reverts
    ///    DuplicateHeaderLabel(-65933): a verifier reading the last
    ///    occurrence would anchor 10 where this contract reads 3.
    function test_publishCheckpoint_duplicateTreeSize2_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory header = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(10)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                DuplicateHeaderLabel.selector, LABEL_TREE_SIZE_2
            )
        );
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), header));
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice A duplicate of a label the contract does not read (395)
    ///    reverts the same way: the header is not well-formed CBOR and
    ///    strict decoders reject it.
    function test_publishCheckpoint_duplicateUnreadLabel_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory header = abi.encodePacked(
            hex"a4",
            hex"01",
            cborInt(ALG_KS256),
            hex"19018b",
            cborUint(3),
            hex"19018b",
            cborUint(3),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3)
        );

        vm.expectRevert(
            abi.encodeWithSelector(DuplicateHeaderLabel.selector, int64(395))
        );
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), header));
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice A tagged size (tag 0 over 3) reverts InvalidCoseCborStructure:
    ///    the walk skips only definite-length major types 0-5.
    function test_publishCheckpoint_taggedTreeSize2_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory header = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            hex"c0",
            cborUint(3)
        );

        vm.expectRevert(InvalidCoseCborStructure.selector);
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), header));
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice An indefinite-length bstr (5f .. ff) under an unread label
    ///    reverts InvalidCoseCborStructure; a simple value (f6) under one
    ///    is skipped and the checkpoint publishes.
    function test_publishCheckpoint_indefiniteRejected_simpleSkipped() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory indefinite = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_KS256),
            hex"04",
            hex"5f4101ff",
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3)
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        _publishTestLog(
            _signReceiptWithHeader(proofs, _toAcc(root3), indefinite)
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);

        bytes memory simple = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_KS256),
            hex"04",
            hex"f6",
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3)
        );
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), simple));
        assertEq(univocity.logState(TEST_LOG_ID).size, 3);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], root3);
    }

    /// @notice The unsigned key 2^64 - 65933, which a wrapping int64 cast
    ///    would read as the tree-size-2 label, reverts IntegerOutOfRange.
    ///    Other decoders read it as a large positive key and find no
    ///    tree-size-2; this contract must not read a size they do not.
    function test_publishCheckpoint_keyAliasingTreeSize2_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory header = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_KS256),
            hex"1bfffffffffffefe73",
            cborUint(3)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IntegerOutOfRange.selector, uint64(0xfffffffffffefe73)
            )
        );
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), header));
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice Non-canonical encodings of an otherwise valid header
    ///    revert: the size in a wider argument than it needs, and a
    ///    trailing byte after the map. Both are rejected by the Go decoder;
    ///    accepting either would anchor a checkpoint it does not read.
    function test_publishCheckpoint_nonCanonicalHeader_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory wideSize = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            hex"1803"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        _publishTestLog(
            _signReceiptWithHeader(proofs, _toAcc(root3), wideSize)
        );

        bytes memory trailing = abi.encodePacked(
            _consistencyProtectedHeader(ALG_KS256, 3), hex"00"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        _publishTestLog(
            _signReceiptWithHeader(proofs, _toAcc(root3), trailing)
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice A map declaring more pairs than its bytes hold reverts
    ///    InvalidCoseCborStructure before any key is read.
    function test_publishCheckpoint_overDeclaredMapLength_reverts() public {
        (ConsistencyProof[] memory proofs, bytes32 root3) = _proof1To3();
        bytes memory header = abi.encodePacked(
            hex"b8ff",
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3)
        );

        vm.expectRevert(InvalidCoseCborStructure.selector);
        _publishTestLog(_signReceiptWithHeader(proofs, _toAcc(root3), header));
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    // --- fixtures ----------------------------------------------------------

    /// @notice Grow TEST_LOG 1 -> 3 -> 7 so it holds a single height-2
    ///    peak. From 7, appending one leaf folds nothing, which is the
    ///    shape the signed sizes exist to pin.
    function _growTestLogTo7() internal returns (bytes32 root7) {
        bytes32[][] memory p13 = _paths1(_path1(keccak256("leaf1")));
        bytes32 root3 = includedRootHarness.callIncludedRoot(0, PEAK1, p13[0]);
        ConsistencyProof[] memory a = new ConsistencyProof[](1);
        a[0] = _proof(1, 3, p13, new bytes32[](0));
        _publishTestLog(_signReceipt(a, _toAcc(root3)));

        bytes32[][] memory p37 = _paths1(_path1(keccak256("sibling37")));
        root7 = includedRootHarness.callIncludedRoot(2, root3, p37[0]);
        ConsistencyProof[] memory b = new ConsistencyProof[](1);
        b[0] = _proof(3, 7, p37, new bytes32[](0));
        _publishTestLog(_signReceipt(b, _toAcc(root7)));
        assertEq(univocity.logState(TEST_LOG_ID).size, 7);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], root7);
    }

    /// @notice The 1 -> 3 proof for TEST_LOG and the root it proves.
    function _proof1To3()
        internal
        view
        returns (ConsistencyProof[] memory proofs, bytes32 root3)
    {
        bytes32[][] memory paths = _paths1(_path1(keccak256("leaf1")));
        root3 = includedRootHarness.callIncludedRoot(0, PEAK1, paths[0]);
        proofs = new ConsistencyProof[](1);
        proofs[0] = _proof(1, 3, paths, new bytes32[](0));
    }

    function _acc2(bytes32 a, bytes32 b)
        internal
        pure
        returns (bytes32[] memory out)
    {
        out = new bytes32[](2);
        out[0] = a;
        out[1] = b;
    }

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
    ///    key shared by both logs, under a header carrying the sizes the
    ///    proofs declare. The caller states the accumulator the proofs will
    ///    produce; a mismatch surfaces as a signature failure.
    function _signReceipt(
        ConsistencyProof[] memory proofs,
        bytes32[] memory finalAcc
    ) internal pure returns (ConsistencyReceipt memory) {
        return _signReceiptWithHeader(
            proofs,
            finalAcc,
            _consistencyProtectedHeader(
                ALG_KS256, proofs[proofs.length - 1].treeSize2
            )
        );
    }

    /// @notice As _signReceipt, under the header the caller supplies.
    function _signReceiptWithHeader(
        ConsistencyProof[] memory proofs,
        bytes32[] memory finalAcc,
        bytes memory protected
    ) internal pure returns (ConsistencyReceipt memory) {
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

/// @notice First checkpoint of a log: with base 0 nothing is folded, so the
///    fold accepts one signed accumulator at every complete size with the
///    same peak count. The signed tree-size-2 pins it. TEST_LOG is not
///    published in setUp; each test submits its first checkpoint.
contract UnivocityFirstCheckpointSignedSizeTest is UnivocityTestHelper {
    bytes32 internal constant PEAK1 = keccak256("peak1");

    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
        assertFalse(univocity.isLogInitialized(TEST_LOG_ID));
    }

    /// @notice A first checkpoint signed for size 1 and submitted with
    ///    treeSize2 = 2^64 - 1 (a complete size: one peak of height 63)
    ///    reverts ConsistencyReceiptSizeMismatch(2^64 - 1, 1). Anchored, no
    ///    later checkpoint could exceed it (SizeMustIncrease).
    function test_publishCheckpoint_firstCheckpointAtMaxSize_reverts() public {
        uint64 max = type(uint64).max;
        vm.expectRevert(sizeMismatch(max, 1));
        _publishFirstAtDeclaredSize(max);
        assertFalse(univocity.isLogInitialized(TEST_LOG_ID));
    }

    /// @notice The other one-peak sizes are rejected the same way, and the
    ///    signed size is then anchored with the signed accumulator.
    function test_publishCheckpoint_firstCheckpointAtOtherOnePeakSizes_reverts()
        public
    {
        uint64[4] memory sizes = [uint64(3), 7, 15, 31];
        for (uint256 k = 0; k < sizes.length; k++) {
            vm.expectRevert(sizeMismatch(sizes[k], 1));
            _publishFirstAtDeclaredSize(sizes[k]);
        }
        assertFalse(univocity.isLogInitialized(TEST_LOG_ID));

        _publishFirstAtDeclaredSize(1);
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], PEAK1);
    }

    /// @notice Submit TEST_LOG's first checkpoint: a receipt signed for
    ///    0 -> 1 over accumulator [PEAK1], with `declared` as the proof's
    ///    treeSize2.
    function _publishFirstAtDeclaredSize(uint64 declared) internal {
        ConsistencyProof[] memory p = new ConsistencyProof[](1);
        p[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: declared,
            paths: new bytes32[][](0),
            rightPeaks: _toAcc(PEAK1)
        });
        bytes memory protected = _consistencyProtectedHeader(ALG_KS256, 1);
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(_toAcc(PEAK1)));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        univocity.publishCheckpoint(
            ConsistencyReceipt({
                protectedHeader: protected,
                signature: abi.encodePacked(r, s, v),
                consistencyProofs: p,
                delegationProof: _emptyDelegationProof()
            }),
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            grantTestLog
        );
    }
}

/// @notice External wrapper so the chain verifier can be called directly,
///    at a call depth vm.expectRevert can catch.
contract ConsistencyChainCallHarness {
    function chain(
        bytes32[] memory initialAccumulator,
        uint64 initialSize,
        ConsistencyProof[] calldata proofs
    ) external pure returns (bytes32[] memory) {
        return
            verifyConsistencyProofChain(
                initialAccumulator, initialSize, proofs
            );
    }
}

/// @notice verifyConsistencyProofChain is exported and reachable without
///    publishCheckpoint's own checks, so it states its own precondition: a
///    chain of no proofs proves nothing about initialSize and must not
///    return an accumulator at all (FOR-568 I6).
contract ConsistencyChainEmptyTest is Test {
    ConsistencyChainCallHarness internal harness;

    function setUp() public {
        harness = new ConsistencyChainCallHarness();
    }

    function test_chainWithNoProofs_reverts() public {
        ConsistencyProof[] memory none = new ConsistencyProof[](0);

        vm.expectRevert(IUnivocityErrors.InvalidConsistencyProof.selector);
        harness.chain(new bytes32[](0), 0, none);
    }

    /// @notice The same for a non-empty initial state: the returned
    ///    accumulator would otherwise be empty while initialSize says the
    ///    log holds a tree.
    function test_chainWithNoProofsOverAnchoredState_reverts() public {
        ConsistencyProof[] memory none = new ConsistencyProof[](0);
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = keccak256("peak-0");

        vm.expectRevert(IUnivocityErrors.InvalidConsistencyProof.selector);
        harness.chain(acc, 3, none);
    }
}
