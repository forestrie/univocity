// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice FOR-568: the receipt_chains section of the cross-language KAT-39
///    fixture (test/fixtures/checkpoint-receipt-kat39.json, refreshed from
///    go-merklelog#15). Each row is a relayed checkpoint receipt whose
///    unprotected header carries vdp(396) => {-2 => [+ consistency-proof]}
///    on the wire — the draft's consistency-proofs = [ + consistency-proof ]
///    form, one proof per sealed step in fold order (see the fixture's
///    "conventions"."receipt_chain"). univocity does not decode that CBOR
///    array on-chain: ConsistencyReceipt.consistencyProofs
///    (src/interfaces/types.sol) is already the pre-decoded
///    ConsistencyProof[] a relayer would submit, so each row here is driven
///    by pre-decoding its consistency_proofs_hex entries off-chain (the
///    fixture's own CBOR array [tree_size_1, tree_size_2, paths,
///    rightPeaks] per proof) into that array and calling publishCheckpoint
///    exactly as a relayer would.
///
///    TEST_LOG is bootstrapped to tree-size 1 with the exact KAT-39
///    accumulator at that size (fixture receipts["es256/0-to-1"]: 0 -> 1,
///    af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc),
///    under a root key set to the fixture's fixed ES256 test key
///    (Kat39Vectors.ES256_X/Y). Every receipt_chains row declares
///    trusted_tree_size_1 = 1, so this bootstrap makes TEST_LOG's stored
///    state match the fixture's own fold exactly, and each row is submitted
///    to publishCheckpoint unchanged from its fixture bytes (protected
///    header, signature) beyond the off-chain proof decode.
import "./UnivocityTestHelper.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {Kat39Vectors} from "../fixtures/Kat39Vectors.sol";

contract Kat39ReceiptChainsTest is UnivocityTestHelper {
    PublishGrant internal grantTestLogES256;

    /// @notice KAT-39 accumulator at tree-size 1 (fixture
    ///    receipts["es256/0-to-1"].detached_payload_hex).
    bytes32 internal constant KAT_ACC_1 =
        0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;

    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();

        // Authority bootstrap (first checkpoint), same as
        // _publishBootstrapAndSecondCheckpoint. The second checkpoint below
        // differs: it includes TEST_LOG's grant under grantTestLogES256
        // (ES256 grantData) rather than the shared helper's grantTestLog
        // (KS256 grantData), so the inclusion proof TEST_LOG's own
        // checkpoints carry proves the grant actually anchored in the
        // authority tree.
        PublishGrant memory grant0 = _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        authorityLeaf0 = _leafCommitment(IDTIMESTAMP_AUTH, grant0);
        ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(authorityLeaf0));
        univocity.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant0
        );

        grantTestLogES256 = _publishGrant(
            TEST_LOG_ID,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(Kat39Vectors.ES256_X, Kat39Vectors.ES256_Y)
        );
        bytes32 testLogGrantLeaf =
            _leafCommitment(IDTIMESTAMP_TEST, grantTestLogES256);
        ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To3(authorityLeaf0, testLogGrantLeaf);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant0
        );

        // Bootstrap TEST_LOG to tree-size 1 at the exact KAT-39 accumulator,
        // signed by the fixture's fixed ES256 key (receipts["es256/0-to-1"]
        // protected_header_hex / signature_hex, copied unchanged).
        bytes32[] memory bootstrapPeak = _oneHash(KAT_ACC_1);
        ConsistencyProof[] memory bootstrapProofs = new ConsistencyProof[](1);
        bootstrapProofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: bootstrapPeak
        });
        ConsistencyReceipt memory bootstrap = ConsistencyReceipt({
            protectedHeader: hex"a3012619018b033a0001018c01",
            signature: hex"c3fb79cd07bebad57ed231c33ae318eb38f1e99a4df5a41f44a60dd488bc362d3cc0be4577643f30448b6fea3087efc0c5770fe23f8fd529658b3987db72f838",
            consistencyProofs: bootstrapProofs,
            delegationProof: _emptyDelegationProof()
        });
        univocity.publishCheckpoint(
            bootstrap,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            grantTestLogES256
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
        assertEq(univocity.logState(TEST_LOG_ID).accumulator[0], KAT_ACC_1);
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    function _oneHash(bytes32 a) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](1);
        out[0] = a;
    }

    function _twoHash(bytes32 a, bytes32 b)
        internal
        pure
        returns (bytes32[] memory out)
    {
        out = new bytes32[](2);
        out[0] = a;
        out[1] = b;
    }

    /// @notice The chain-1-3-4-7 row's three consistency_proofs_hex entries
    ///    (fixture "accept/chain-1-3-4-7", also the shared proof shape of
    ///    the two reject rows), pre-decoded off-chain from their CBOR
    ///    [tree_size_1, tree_size_2, paths, rightPeaks] form.
    function _chainProofs1347()
        internal
        pure
        returns (ConsistencyProof[] memory proofs)
    {
        proofs = new ConsistencyProof[](3);

        bytes32[][] memory paths0 = new bytes32[][](1);
        paths0[0] = _oneHash(
            0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50
        );
        proofs[0] = ConsistencyProof({
            treeSize1: 1,
            treeSize2: 3,
            paths: paths0,
            rightPeaks: new bytes32[](0)
        });

        bytes32[][] memory paths1 = new bytes32[][](1);
        paths1[0] = new bytes32[](0);
        proofs[1] = ConsistencyProof({
            treeSize1: 3,
            treeSize2: 4,
            paths: paths1,
            rightPeaks: _oneHash(
                0xd5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975
            )
        });

        bytes32[][] memory paths2 = new bytes32[][](2);
        paths2[0] = _oneHash(
            0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0
        );
        paths2[1] = _twoHash(
            0x8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc,
            0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8
        );
        proofs[2] = ConsistencyProof({
            treeSize1: 4,
            treeSize2: 7,
            paths: paths2,
            rightPeaks: new bytes32[](0)
        });
    }

    function _publishChain(ConsistencyReceipt memory receipt) internal {
        univocity.publishCheckpoint(
            receipt,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            grantTestLogES256
        );
    }

    // -----------------------------------------------------------------
    // rows
    // -----------------------------------------------------------------

    /// @notice accept/chain-1-3-4-7: three sealed steps relayed under one
    ///    signature; folding them in order from the tree-size-1 accumulator
    ///    reaches tree-size 7, the last proof's treeSize2 and the header's
    ///    signed size (label -65933, ADR-0066). Accepted; TEST_LOG advances
    ///    to size 7 at the KAT-39 accumulator for that size.
    function test_acceptChain1347() public {
        ConsistencyReceipt memory receipt = ConsistencyReceipt({
            protectedHeader: hex"a3012619018b033a0001018c07",
            signature: hex"c6ade0ccb6520ee0620457b4a8e47dd01207525f3d74602b24b5944c72c70cb45b549896b696dc444a29b867dbc7573f2f20d6ef010515fb7cec65ab40087eea",
            consistencyProofs: _chainProofs1347(),
            delegationProof: _emptyDelegationProof()
        });

        _publishChain(receipt);

        assertEq(univocity.logState(TEST_LOG_ID).size, 7);
        assertEq(
            univocity.logState(TEST_LOG_ID).accumulator[0],
            0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88
        );
    }

    /// @notice reject/chain-middle-step-off-by-one: the first step ends at
    ///    size 3, and the second declares size 2 as its origin. The paths
    ///    and the signature are the genuine ones from the accepted chain;
    ///    only the comparison between consecutive steps' sizes rejects it
    ///    (verifyConsistencyProofChain's base check, run inside
    ///    publishCheckpoint before the signature is read).
    function test_rejectChain_middleStepOffByOne() public {
        ConsistencyProof[] memory proofs = _chainProofs1347();
        proofs[1].treeSize1 = 2;

        ConsistencyReceipt memory receipt = ConsistencyReceipt({
            protectedHeader: hex"a3012619018b033a0001018c07",
            signature: hex"c6ade0ccb6520ee0620457b4a8e47dd01207525f3d74602b24b5944c72c70cb45b549896b696dc444a29b867dbc7573f2f20d6ef010515fb7cec65ab40087eea",
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyBaseMismatch.selector, 3, 2
            )
        );
        _publishChain(receipt);
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    /// @notice reject/chain-signed-size-is-an-intermediate-step: a genuine
    ///    receipt for the 1 -> 3 -> 4 -> 7 chain, but the protected header
    ///    signs tree-size-2 = 4 — an intermediate step of the chain, not
    ///    the last proof's treeSize2 (7). The proofs fold to 7 without
    ///    error; the mismatch is only between the signed size and the
    ///    size the chain actually reaches (ConsistencyReceiptSizeMismatch,
    ///    ADR-0066).
    function test_rejectChain_signedSizeIsIntermediateStep() public {
        ConsistencyReceipt memory receipt = ConsistencyReceipt({
            protectedHeader: hex"a3012619018b033a0001018c04",
            signature: hex"73f04f60526417cad6e8dd82b1fb33f7d3c768119e8f684c1068901ab03e7bb876b4567eb30e5edebcd53cb42ad5efe844d9186f7e48afd3ab79f3a11db4afb3",
            consistencyProofs: _chainProofs1347(),
            delegationProof: _emptyDelegationProof()
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.ConsistencyReceiptSizeMismatch.selector, 7, 4
            )
        );
        _publishChain(receipt);
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }
}
