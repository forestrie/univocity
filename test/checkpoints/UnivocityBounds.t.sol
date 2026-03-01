// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Bounds tests (maxHeight, minGrowth, grant exhausted). Split from
///   Univocity.t.sol per test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";

contract UnivocityBoundsTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

    /// @notice Grant with maxHeight=1 reverts when second checkpoint would
    ///    exceed it.
    function test_publishCheckpoint_revertsWhenSizeWouldExceedMaxHeight()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 logId = keccak256("other-target");
        IUnivocity.PaymentGrant memory g0 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );

        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(
                leaf0,
                _leafCommitment(
                    IDTIMESTAMP_TEST,
                    _paymentGrant(
                        logId,
                        KS256_SIGNER,
                        GRANT_DATA,
                        GC_DATA_LOG,
                        1,
                        0,
                        AUTHORITY_LOG_ID,
                        ""
                    )
                )
            );
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );

        IUnivocity.PaymentGrant memory grantEnd1 = _paymentGrant(
            logId,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            1,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantEnd1);
        bytes32 firstAuthorityLeaf = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        bytes32[] memory pathForRoi = _path1(firstAuthorityLeaf);
        _publishFirstToTestLogWithGrant(
            fresh, keccak256("peak1"), logId, grantEnd1, leaf1, pathForRoi
        );

        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(
                keccak256("peak1"), leaf1, keccak256("leaf2")
            );
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.MaxHeightExceeded.selector,
                uint64(3),
                uint64(1)
            )
        );
        fresh.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, pathForRoi),
            IDTIMESTAMP_TEST,
            grantEnd1
        );
    }

    function test_publishCheckpoint_revertsWhenSizeExceedsReceiptMaxHeight()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g0 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            1,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(leaf0, authorityLeaf1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.MaxHeightExceeded.selector,
                uint64(2),
                uint64(1)
            )
        );
        fresh.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );
    }

    /// @notice Rule 4: Grant requires minGrowth; publishing with too small an
    ///    increase reverts.
    function test_rule4_minGrowthNotMet_reverts() public {
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );
        assertEq(univocity.getLogState(TEST_LOG_ID).size, 1);

        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(
                keccak256("peak1"), keccak256("leaf2")
            );
        bytes32[] memory path = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            10,
            2,
            AUTHORITY_LOG_ID,
            ""
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.MinGrowthNotMet.selector,
                uint64(1),
                uint64(2),
                uint64(2)
            )
        );
        univocity.publishCheckpoint(
            consistency1to2,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_TEST,
            g
        );
    }

    /// @notice Rule 4 / grant exhaustion: Once log size reaches maxHeight,
    ///    grant is exhausted; next publish reverts.
    function test_rule4_grantExhausted_whenSizeReachesMaxHeight() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g0 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            2,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, g);
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        fresh.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );

        bytes32 peak1 = keccak256("peak1");
        bytes32 leaf2 = keccak256("leaf2");
        bytes32 leaf3 = keccak256("leaf3");
        bytes32[] memory path = _path1(leaf0);
        IUnivocity.ConsistencyReceipt memory receipt1 =
            _buildConsistencyReceipt(_toAcc(peak1));
        fresh.publishCheckpoint(
            receipt1, _buildPaymentInclusionProof(1, path), IDTIMESTAMP_TEST, g
        );
        assertEq(fresh.getLogState(TEST_LOG_ID).size, 1);

        IUnivocity.ConsistencyReceipt memory consistency1to2Data =
            _buildConsistencyReceipt1To2(peak1, leaf2);
        fresh.publishCheckpoint(
            consistency1to2Data,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_TEST,
            g
        );
        assertEq(fresh.getLogState(TEST_LOG_ID).size, 2);

        IUnivocity.ConsistencyReceipt memory consistency2to3 =
            _buildConsistencyReceipt2To3(peak1, leaf2, leaf3);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.MaxHeightExceeded.selector,
                uint64(3),
                uint64(2)
            )
        );
        fresh.publishCheckpoint(
            consistency2to3,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_TEST,
            g
        );
        assertEq(fresh.getLogState(TEST_LOG_ID).size, 2);
    }
}
