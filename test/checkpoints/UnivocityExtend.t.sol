// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Extend and second-checkpoint tests. Split from Univocity.t.sol per
///   test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";

contract UnivocityExtendTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

    function test_firstCheckpoint_sizeTwo_succeeds() public {
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
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, g1);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        assertEq(fresh.rootLogId(), AUTHORITY_LOG_ID);
        assertEq(fresh.getLogState(AUTHORITY_LOG_ID).size, 2);
    }

    /// @notice Root extension requires grant (inclusion proof) in root
    ///    (ADR-0004). After setUp root has size 2; prove inclusion of leaf 0.
    function test_publishCheckpoint_authorityLogSecondCheckpoint_noInclusionProofRequired()
        public
    {
        IUnivocity.ConsistencyReceipt memory consistency2 =
            _buildConsistencyReceipt2To3(
                authorityLeaf0, authorityLeaf1, keccak256("extra")
            );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32[] memory pathToLeaf0 = _path1(authorityLeaf1);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency2,
            _buildPaymentInclusionProof(0, pathToLeaf0),
            IDTIMESTAMP_AUTH,
            g
        );
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_publishCheckpoint_bootstrapCanPublishToAuthorityLog()
        public
    {
        IUnivocity.ConsistencyReceipt memory consistency2 =
            _buildConsistencyReceipt2To3(
                authorityLeaf0, authorityLeaf1, keccak256("third")
            );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32[] memory pathToLeaf0 = _path1(authorityLeaf1);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency2,
            _buildPaymentInclusionProof(0, pathToLeaf0),
            IDTIMESTAMP_AUTH,
            g
        );

        assertTrue(univocity.isLogInitialized(AUTHORITY_LOG_ID));
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_publishCheckpoint_bootstrapCanPublishToAnyLog() public {
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );

        assertTrue(univocity.isLogInitialized(TEST_LOG_ID));
    }

    /// @notice Invalid grant (e.g. maxHeight exceeded) reverts and does not
    ///    extend the log.
    function test_publishCheckpoint_invalidGrant_doesNotExtendLog() public {
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );
        uint256 sizeBefore = univocity.getLogState(TEST_LOG_ID).size;
        assertEq(sizeBefore, 1);

        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathInvalid = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory invalidGrant = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            1,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.MaxHeightExceeded.selector,
                uint64(3),
                uint64(1)
            )
        );
        univocity.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, pathInvalid),
            IDTIMESTAMP_TEST,
            invalidGrant
        );

        assertEq(
            univocity.getLogState(TEST_LOG_ID).size,
            sizeBefore,
            "log size must not change after invalid grant revert"
        );
    }

    /// @notice Plan 0012 Phase C: Idtimestamp optional test (4.3 item 7).
    function test_twoCheckpoints_differentIdtimestamps_bothSucceed() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 logId = keccak256("multi-idts");
        bytes8 idt0 = bytes8(0);
        bytes8 idt1 = bytes8(uint64(1));
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
        bytes32 leaf0 = _leafCommitment(idt0, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(consistency0, _emptyInclusionProof(), idt0, g0);
        assertEq(fresh.rootLogId(), AUTHORITY_LOG_ID);

        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            logId,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf1 = _leafCommitment(idt1, g1);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        fresh.publishCheckpoint(consistency1, _emptyInclusionProof(), idt0, g0);

        IUnivocity.PaymentGrant memory gTarget = _paymentGrant(
            logId,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32[] memory pathMulti = _path1(leaf0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(keccak256("peak"))),
            _buildPaymentInclusionProof(1, pathMulti),
            idt1,
            gTarget
        );
        assertEq(fresh.getLogState(logId).size, 1);
    }
}
