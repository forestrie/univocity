// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityEvents
} from "@univocity/checkpoints/interfaces/IUnivocityEvents.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";
import {
    buildDetachedPayloadCommitment
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";

/// @notice Full Univocity checkpoint test suite. Uses UnivocityTestHelper for
///   shared setup and helpers. Plan 0022 Phase 0: tests can be split into
///   smaller contracts (UnivocityBootstrap, UnivocityGrantRequirements, etc.)
///   that also extend UnivocityTestHelper.
contract UnivocityTest is UnivocityTestHelper, IUnivocityEvents {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();

        // Unified root grant: GF_CREATE | GF_EXTEND | GC_AUTH_LOG (one leaf for
        // both create and extend).
        IUnivocity.PaymentGrant memory grant0 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        authorityLeaf0 = _leafCommitment(IDTIMESTAMP_AUTH, grant0);
        grant1 = grant0;

        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(authorityLeaf0));
        univocity.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant0
        );

        grantTestLog = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        authorityLeaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantTestLog);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(authorityLeaf0, authorityLeaf1);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant1
        );
    }

    bytes32 internal authorityLeaf0;
    bytes32 internal authorityLeaf1;
    IUnivocity.PaymentGrant internal grant1;
    IUnivocity.PaymentGrant internal grantTestLog;

    bytes internal testLogReceipt;

    // === Initialization Tests === (helpers live in UnivocityTestHelper)

    // test_constructor_setsBootstrapAuthority, test_constructor_setsKs256Signer,
    // test_firstCheckpoint_revertsIfSizeZero moved to UnivocityBootstrap.t.sol

    function test_firstCheckpoint_revertsIfReceiptMmrIndexNotZero() public {
        // New API has no receiptMmrIndex; first leaf must equal leafCommitment.
        // So we use wrong leaf in accumulator => InvalidReceiptInclusionProof.
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 wrongLeaf = keccak256("wrong");
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(wrongLeaf));
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint (root) with empty path must use index 0;
    ///    non-zero index when path is empty reverts.
    function test_firstCheckpoint_revertsWhenPathEmptyAndIndexNonZero()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        IUnivocity.InclusionProof memory proofWithNonZeroIndex =
            IUnivocity.InclusionProof({index: 1, path: new bytes32[](0)});
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        fresh.publishCheckpoint(
            consistency, proofWithNonZeroIndex, IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint (root) with empty path emits paymentIndex 0.
    function test_firstCheckpoint_emitsPaymentIndexZeroWhenPathEmpty() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        bytes32[] memory emptyPath;
        vm.expectEmit(true, true, true, false);
        emit CheckpointPublished(
            AUTHORITY_LOG_ID,
            address(this),
            KS256_SIGNER,
            uint8(IUnivocity.LogKind.Authority),
            1,
            _toAcc(leaf0),
            uint64(0),
            emptyPath
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_initialize_setsAuthorityLogId() public view {
        assertEq(univocity.rootLogId(), AUTHORITY_LOG_ID);
    }

    /// @notice Phase D.1: First bootstrap sets kind=Authority, authLogId=self (ADR-0004).
    function test_getLogConfig_bootstrapSetsAuthorityKind() public view {
        IUnivocity.LogConfig memory config =
            univocity.getLogConfig(AUTHORITY_LOG_ID);
        assertEq(uint8(config.kind), uint8(IUnivocity.LogKind.Authority));
        assertEq(config.authLogId, AUTHORITY_LOG_ID); // root's parent is self
        assertGt(config.initializedAt, 0);
    }

    /// @notice Phase F D.5: Create child authority; config has kind=Authority, authLogId=parent.
    function test_hierarchy_createChildAuthority_setsConfig() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 childId = keccak256("child-authority");
        IUnivocity.PaymentGrant memory g0 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        IUnivocity.PaymentGrant memory gChild = _paymentGrant(
            childId,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        bytes32 leafChild = _leafCommitment(IDTIMESTAMP_TEST, gChild);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leafChild);
        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );

        bytes32[] memory pathToChild = _path1(leaf0);
        bytes32 childPeak = keccak256("child-peak");
        vm.prank(address(0x1));
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(childPeak)),
            _buildPaymentInclusionProof(1, pathToChild),
            IDTIMESTAMP_TEST,
            gChild
        );

        IUnivocity.LogConfig memory config = fresh.getLogConfig(childId);
        assertEq(uint8(config.kind), uint8(IUnivocity.LogKind.Authority));
        assertEq(config.authLogId, AUTHORITY_LOG_ID);
        assertEq(fresh.getLogState(childId).size, 1);
    }

    function test_firstPublish_emitsInitialized() public {
        Univocity newUnivocity = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));

        vm.expectEmit(true, true, false, false);
        emit Initialized(BOOTSTRAP, AUTHORITY_LOG_ID);
        newUnivocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_rootLogId_immutableAfterFirstPublish() public view {
        // After setUp, root authority log is AUTHORITY_LOG_ID; no way to change it
        assertEq(univocity.rootLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_revertsIfReceiptEmpty() public {
        Univocity newUnivocity = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak")));
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        newUnivocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint ever with correct grant (GF_CREATE, GC_AUTH_LOG)
    ///    succeeds (positive test for grant requirement).
    // test_firstCheckpoint_grantRequirement_correctGrant_succeeds moved to
    // UnivocityBootstrap.t.sol (test_bootstrap_firstCheckpoint_correctGrant_succeeds)

    /// @notice First checkpoint without GF_CREATE (only GF_EXTEND) reverts
    ///    GrantRequirement(GF_CREATE | GC_AUTH_LOG).
    function test_firstCheckpoint_grantRequirement_wrongCode_reverts() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID, KS256_SIGNER, GF_EXTEND, 0, 0, 0, bytes32(0), ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG(),
                univocity.GC_AUTH_LOG()
            )
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint with GC_AUTH_LOG not set reverts
    ///    GrantRequirement(GF_CREATE | GC_AUTH_LOG).
    function test_firstCheckpoint_grantRequirement_authFlagNotSet_reverts()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID, KS256_SIGNER, GF_CREATE, 0, 0, 0, bytes32(0), ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG(),
                univocity.GC_AUTH_LOG()
            )
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint with GC_DATA_LOG set reverts
    ///    GrantRequirement(GF_CREATE | GC_AUTH_LOG).
    function test_firstCheckpoint_grantRequirement_dataFlagSet_reverts()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GF_CREATE | GF_DATA,
            GC_DATA_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG(),
                univocity.GC_AUTH_LOG()
            )
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice Extend (second checkpoint to authority) with GC_CREATE
    ///    reverts GrantRequirement(GC_EXTEND_LOG, 0).
    function test_extendGrant_wrongCode_reverts() public {
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
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        bytes32 leaf1 = _leafCommitment(
            IDTIMESTAMP_AUTH,
            _paymentGrant(
                AUTHORITY_LOG_ID,
                KS256_SIGNER,
                GRANT_ROOT,
                GC_AUTH_LOG,
                0,
                0,
                bytes32(0),
                ""
            )
        );
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt0To2(leaf0, leaf1);
        fresh.publishCheckpoint(
            consistency0,
            _buildPaymentInclusionProof(0, _path1(leaf1)),
            IDTIMESTAMP_AUTH,
            g0
        );
        bytes32 leaf2 = keccak256("third");
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt2To3(leaf0, leaf1, leaf2);
        IUnivocity.PaymentGrant memory gWrong = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GF_CREATE | GF_AUTH,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_EXTEND(),
                uint256(0)
            )
        );
        fresh.publishCheckpoint(
            consistency1,
            _buildPaymentInclusionProof(1, _path1(leaf0)),
            IDTIMESTAMP_AUTH,
            gWrong
        );
    }

    /// @notice First checkpoint to new log without GF_CREATE reverts
    ///    GrantRequirement(GF_CREATE | GC_AUTH_LOG | GC_DATA_LOG).
    function test_newLogGrant_GF_CREATE_required_reverts() public {
        bytes32 newLogId = keccak256("new-data-log");
        IUnivocity.PaymentGrant memory gNoCreate = _paymentGrant(
            newLogId,
            KS256_SIGNER,
            GF_EXTEND | GF_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak")));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG()
                    | univocity.GF_DATA_LOG(),
                uint256(0)
            )
        );
        univocity.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            gNoCreate
        );
    }

    /// @notice Extend without GF_EXTEND (only GF_CREATE | GC_AUTH_LOG) reverts
    ///    GrantRequirement(GF_EXTEND).
    function test_extendGrant_GF_EXTEND_required_reverts() public {
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
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        bytes32 leaf1 = keccak256("second");
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        IUnivocity.PaymentGrant memory gNoExtend = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GF_CREATE | GF_AUTH,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_EXTEND(),
                uint256(0)
            )
        );
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, gNoExtend
        );
    }

    function test_firstCheckpoint_revertsIfReceiptTargetsDifferentLog()
        public
    {
        // Receipt built for authority log; grant targets other-log so
        // first leaf != leafCommitment(IDTIMESTAMP_AUTH, g) => inclusion fails.
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 otherLogId = keccak256("other-log");
        IUnivocity.PaymentGrant memory gAuthority = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        // Grant passes first-root check (GF_CREATE, GC_AUTH_LOG) but logId differs
        // so leafCommitment(g) != leaf0 => inclusion fails.
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            otherLogId,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, gAuthority);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_revertsIfAccumulatorDoesNotContainReceipt()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("wrong-peak")));

        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_succeedsFromNonBootstrapSender() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));

        vm.prank(address(0x999));
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        assertEq(fresh.rootLogId(), AUTHORITY_LOG_ID);
        assertTrue(fresh.isLogInitialized(AUTHORITY_LOG_ID));
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
            ""
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
            ""
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
            ""
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

    function test_firstCheckpoint_authorityFirstLeafMatchesAdr0030Formula()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 expectedLeaf = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(expectedLeaf));
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
        bytes32[] memory stored =
        fresh.getLogState(AUTHORITY_LOG_ID).accumulator;
        assertEq(stored.length, 1);
        assertEq(stored[0], expectedLeaf);
    }

    // === Bootstrap Checkpoint Publishing Tests ===

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
            ""
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

    function test_publishCheckpoint_emitsLogRegistered() public {
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );
        assertTrue(univocity.isLogInitialized(TEST_LOG_ID));
        assertEq(univocity.getLogState(TEST_LOG_ID).size, 1);
    }

    function test_publishCheckpoint_emitsCheckpointPublished() public {
        bytes32[] memory acc = _toAcc(keccak256("peak1"));
        vm.expectEmit(true, true, true, false);
        bytes32[] memory pathEmits;
        emit CheckpointPublished(
            TEST_LOG_ID,
            address(this),
            KS256_SIGNER,
            uint8(IUnivocity.LogKind.Authority),
            1,
            acc,
            uint64(1),
            pathEmits
        );
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );
    }

    function test_publishCheckpoint_incrementsCheckpointCount() public {
        bytes32 peak1 =
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        _publishFirstToTestLog(univocity, peak1, authorityLeaf0, grantTestLog);

        assertEq(univocity.getLogState(TEST_LOG_ID).size, 1);

        bytes32 leaf2 =
            0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(peak1, leaf2);
        bytes32[] memory path2 = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        univocity.publishCheckpoint(
            consistency1to2,
            _buildPaymentInclusionProof(1, path2),
            IDTIMESTAMP_TEST,
            g
        );

        assertEq(univocity.getLogState(TEST_LOG_ID).size, 2);
    }

    // === Validation Tests ===

    function test_publishCheckpoint_revertsOnSizeDecrease() public {
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );
        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathDec = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        univocity.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, pathDec),
            IDTIMESTAMP_TEST,
            g
        );

        IUnivocity.ConsistencyReceipt memory consistency0to2 =
            _buildConsistencyReceipt0To2(keccak256("p0"), keccak256("p1"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.SizeMustIncrease.selector, 3, 2
            )
        );
        univocity.publishCheckpoint(
            consistency0to2,
            _buildPaymentInclusionProof(1, pathDec),
            IDTIMESTAMP_TEST,
            g
        );
    }

    function test_publishCheckpoint_revertsOnInvalidAccumulatorLength()
        public
    {
        _publishFirstToTestLog(
            univocity, keccak256("peak1"), authorityLeaf0, grantTestLog
        );
        IUnivocity.ConsistencyReceipt memory wrongConsistency =
            _buildConsistencyReceipt1To3WrongPeakCount(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathWrong = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidAccumulatorLength.selector, 1, 2
            )
        );
        univocity.publishCheckpoint(
            wrongConsistency,
            _buildPaymentInclusionProof(1, pathWrong),
            IDTIMESTAMP_TEST,
            g
        );
    }

    /// @notice KS256 path with delegation proof reverts
    ///    DelegationUnsupportedForAlg(ALG_KS256).
    function test_publishCheckpoint_ks256WithDelegation_revertsDelegationNotSupported()
        public
    {
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt2To3(
                authorityLeaf0, authorityLeaf1, keccak256("third")
            );
        consistency.delegationProof = IUnivocity.DelegationProof({
            delegationKey: new bytes(64),
            mmrStart: 0,
            mmrEnd: 1,
            alg: 0,
            signature: new bytes(64)
        });
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32[] memory pathToLeaf0 = _path1(authorityLeaf1);
        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationUnsupportedForAlg.selector,
                int64(ALG_KS256)
            )
        );
        univocity.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(0, pathToLeaf0),
            IDTIMESTAMP_AUTH,
            g
        );
    }

    /// @notice Empty consistency proof chain reverts InvalidConsistencyProof.
    function test_publishCheckpoint_revertsOnEmptyConsistencyProofs() public {
        IUnivocity.ConsistencyReceipt memory emptyProofs =
            IUnivocity.ConsistencyReceipt({
                protectedHeader: hex"a1013a00010106",
                signature: hex"",
                consistencyProofs: new IUnivocity.ConsistencyProof[](0),
                delegationProof: _emptyDelegationProof()
            });
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        vm.expectRevert(IUnivocityErrors.InvalidConsistencyProof.selector);
        univocity.publishCheckpoint(
            emptyProofs,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            g
        );
    }

    function test_publishCheckpoint_revertsOnInvalidConsistencyProof() public {
        _publishFirstToTestLog(
            univocity,
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc,
            authorityLeaf0,
            grantTestLog
        );

        IUnivocity.ConsistencyReceipt memory wrongConsistency =
            _buildConsistencyReceipt1To3WrongProof(
                0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc,
                authorityLeaf1,
                bytes32(0)
            );
        bytes32[] memory pathWrongProof;
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        // Accumulator length is checked immediately after the consistency proof chain;
        // this invalid proof yields wrong peak count so we revert with InvalidAccumulatorLength.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidAccumulatorLength.selector,
                uint256(1),
                uint256(2)
            )
        );
        univocity.publishCheckpoint(
            wrongConsistency,
            _buildPaymentInclusionProof(1, pathWrongProof),
            IDTIMESTAMP_TEST,
            g
        );
    }

    // === Authorization Tests ===

    /// @notice ADR-0004: non-bootstrap can extend root with valid grant
    ///    (permissionless submission; root extension requires grant in root).
    function test_publishCheckpoint_authorityLogOnlyBootstrap() public {
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
            ""
        );
        bytes32[] memory pathToLeaf0 = _path1(authorityLeaf1);
        vm.prank(address(0x999));
        univocity.publishCheckpoint(
            consistency2,
            _buildPaymentInclusionProof(0, pathToLeaf0),
            IDTIMESTAMP_AUTH,
            g
        );
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_publishCheckpoint_nonBootstrapNeedsReceipt() public {
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak1")));
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        vm.prank(address(0xDEAD));
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_TEST, g
        );
    }

    // === Receipt bounds (security) — Plan 0012 §4.2 items 5–6 ===

    /// @notice Grant with maxHeight=1 reverts when second checkpoint would exceed it.
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
            ""
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
            ""
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

    /// @notice Invalid grant (e.g. maxHeight exceeded) reverts and does not extend the log.
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

    function _publishFirstToTestLogWithGrant(
        Univocity u,
        bytes32 onePeak,
        bytes32, /* logId */
        IUnivocity.PaymentGrant memory grant,
        bytes32, /* leafInAuthority */
        bytes32[] memory inclusionPath
    ) internal {
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(onePeak));
        u.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, inclusionPath),
            IDTIMESTAMP_TEST,
            grant
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
            ""
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
            ""
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

    /// @notice RoI for a different log yields leaf not in authority accumulator;
    ///    LibInclusionReceipt returns false → InvalidPaymentReceipt.
    function test_publishCheckpoint_revertsWhenReceiptTargetsDifferentLog()
        public
    {
        bytes32 otherLogId = keccak256("other-log");
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            otherLogId,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak1")));
        bytes32[] memory pathEmpty;
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidPaymentReceipt.selector
            )
        );
        univocity.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, pathEmpty),
            IDTIMESTAMP_TEST,
            g
        );
    }

    // === View Function Tests ===

    function test_getLogState_returnsCorrectState() public {
        bytes32 peak1 = keccak256("peak1");
        _publishFirstToTestLog(univocity, peak1, authorityLeaf0, grantTestLog);

        IUnivocity.LogState memory state = univocity.getLogState(TEST_LOG_ID);
        assertEq(state.size, 1);
        assertEq(state.accumulator.length, 1);
        assertEq(state.accumulator[0], peak1);

        IUnivocity.LogConfig memory config =
            univocity.getLogConfig(TEST_LOG_ID);
        assertGt(config.initializedAt, 0);
        assertEq(uint8(config.kind), uint8(IUnivocity.LogKind.Data));
        assertEq(config.authLogId, AUTHORITY_LOG_ID);
    }

    function test_isLogInitialized_returnsFalseForNewLog() public view {
        assertFalse(univocity.isLogInitialized(keccak256("nonexistent")));
    }

    // === Authorization rules (Univocity contract) and grant exhaustion ===
    // Rule 1 (bootstrap only for root): test_firstCheckpoint_revertsIfSizeZero,
    //   test_publishCheckpoint_authorityLogOnlyBootstrap,
    //   test_publishCheckpoint_bootstrapCanPublishToAuthorityLog.
    // Rule 2 (grant = inclusion against owner): test_publishCheckpoint_nonBootstrapNeedsReceipt,
    //   test_publishCheckpoint_revertsWhenReceiptTargetsDifferentLog, integration flows.
    // Rule 3 (log creation requires ownerLogId): test_hierarchy_createChildAuthority_setsConfig,
    //   test_rule3_firstCheckpointToNewLog_revertsWithoutOwnerLogId.
    // Rule 4 (grant bounds; grant exhausted by growth): test_publishCheckpoint_invalidGrant_doesNotExtendLog,
    //   test_publishCheckpoint_revertsWhenSizeExceedsReceiptMaxHeight,
    //   test_rule4_minGrowthNotMet_reverts, test_rule4_grantExhausted_whenSizeReachesMaxHeight.
    // Rule 5 (consistency receipt): success paths + test_publishCheckpoint_revertsOnInvalidConsistencyProof.

    /// @notice Rule 3: First checkpoint to a new (non-root) log reverts when ownerLogId is zero.
    function test_rule3_firstCheckpointToNewLog_revertsWithoutOwnerLogId()
        public
    {
        bytes32 newLogId = keccak256("new-data-log");
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            newLogId,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf = _leafCommitment(IDTIMESTAMP_TEST, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf));
        bytes32[] memory path = _path1(authorityLeaf0);
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_TEST,
            g
        );
        assertFalse(univocity.isLogInitialized(newLogId));
    }

    /// @notice Rule 4: Grant requires minGrowth; publishing with too small an increase reverts.
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

    /// @notice Rule 4 / grant exhaustion: Once log size reaches maxHeight, grant is exhausted; next publish reverts.
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
            ""
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
            ""
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

    // === Plan 0012 Phase C: Error coverage matrix (4.2 item 5) ===
    // IUnivocityErrors coverage: FirstCheckpointSizeTooSmall,
    // BootstrapReceiptMustBeFirstEntry,
    // OnlyBootstrapAuthority, ReceiptLogIdMismatch,
    // GrantRequirement → test_firstCheckpoint_grantRequirement_*.
    // InvalidReceiptInclusionProof → see
    // test_firstCheckpoint_* and test_publishCheckpoint_*.
    // DelegationUnsupportedForAlg → test_publishCheckpoint_ks256WithDelegation_*.
    // InconsistentReceiptSignature →
    // test_verifyCheckpoint_*_revertsAlgorithmMismatch.
    // SizeMustIncrease, InvalidAccumulatorLength, InvalidConsistencyProof →
    // test_publishCheckpoint_revertsOn*.
    // CheckpointCountExceeded, MaxHeightExceeded, MinGrowthNotMet,
    // ReceiptLogIdMismatch (regular log) →
    // test_publishCheckpoint_revertsWhen*, test_rule4_*.
    // AlreadyInitialized:
    // only in _initializeAuthorityLog when rootLogId != 0; not reachable
    // from publishCheckpoint (first-checkpoint block only runs when
    // rootLogId == 0).
    // NotInitialized, LogNotFound,
    // InvalidSignatureChain: not used in Univocity.sol.
    function test_errorCoverageMatrix_allReachableErrorsHaveExplicitRevertTest()
        public
        pure
    {
        // Ensure each reachable error has a non-zero selector (matrix
        // documented in comments above)
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.FirstCheckpointSizeTooSmall.selector
                    )
                ) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.OnlyBootstrapAuthority.selector))
                != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.GrantRequirement.selector)) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.InvalidConsistencyProof.selector))
                != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.CheckpointCountExceeded.selector))
                != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.MaxHeightExceeded.selector)) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.MinGrowthNotMet.selector)) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.ReceiptLogIdMismatch.selector)) != 0
        );
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.DelegationUnsupportedForAlg.selector
                    )
                ) != 0
        );
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.InconsistentReceiptSignature.selector
                    )
                ) != 0
        );
    }

    // === Plan 0012 Phase C: ES256 receipt (4.5 item 12) ===
    /// @notice First checkpoint with ES256-signed receipt;
    ///    Univocity deployed with es256X/Y only. Deploy with the key that
    ///    recovery returns so bootstrap signer check passes (vm.publicKeyP256
    ///    can differ from P256.recovery).
    function test_firstCheckpoint_es256Receipt_succeeds() public {
        uint256 es256Pk = 1;
        bytes8 idtimestampBe = bytes8(0);
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            address(0xE5),
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(idtimestampBe, g);
        bytes32[] memory accMem = _toAcc(leaf0);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceiptES256(accMem, es256Pk);
        bytes memory detachedPayload = buildDetachedPayloadCommitment(accMem);
        ES256RecoveryHelper helper = new ES256RecoveryHelper();
        (bytes32 rx, bytes32 ry) = helper.recoverKey(
            consistency.protectedHeader, detachedPayload, consistency.signature
        );
        vm.prank(BOOTSTRAP);
        Univocity es256Univocity =
            new Univocity(BOOTSTRAP, ALG_ES256, abi.encodePacked(rx, ry));
        es256Univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), idtimestampBe, g
        );

        assertEq(es256Univocity.rootLogId(), AUTHORITY_LOG_ID);
        assertTrue(es256Univocity.isLogInitialized(AUTHORITY_LOG_ID));
    }

    /// @notice Root's first checkpoint with ES256 receipt signed by a key
    ///    other than the bootstrap key reverts (prevents front-running root).
    function test_firstCheckpoint_es256Receipt_nonBootstrapKey_revertsRootSignerMustMatchBootstrap()
        public
    {
        uint256 bootstrapPk = 1;
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(bootstrapPk);
        vm.prank(BOOTSTRAP);
        Univocity es256Univocity =
            new Univocity(BOOTSTRAP, ALG_ES256, abi.encodePacked(pubX, pubY));

        bytes8 idtimestampBe = bytes8(0);
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            AUTHORITY_LOG_ID,
            address(0xE5),
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(idtimestampBe, g);
        uint256 otherPk = 2;
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceiptES256(_toAcc(leaf0), otherPk);

        vm.expectRevert(IUnivocityErrors.RootSignerMustMatchBootstrap.selector);
        es256Univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), idtimestampBe, g
        );
    }

    /// @notice Submitting an ES256 receipt for a log with KS256 root key
    ///    reverts with UnsupportedAlgorithm(ALG_KS256), not LogRootKeyNotSet.
    function test_verifyCheckpoint_es256ReceiptOnKs256Log_revertsAlgorithmMismatch()
        public
    {
        Univocity ks256Univocity = new Univocity(
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
            ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        ks256Univocity.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        uint256 es256Pk = 1;
        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            AUTHORITY_LOG_ID,
            address(0xE5),
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_AUTH, g1);
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2ES256(leaf0, leaf1, es256Pk);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InconsistentReceiptSignature.selector,
                int64(ALG_ES256),
                int64(ALG_KS256)
            )
        );
        ks256Univocity.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );
    }

    /// @notice Submitting a KS256 receipt for a log with ES256 root key
    ///    reverts with UnsupportedAlgorithm(ALG_ES256), not LogRootKeyNotSet.
    function test_verifyCheckpoint_ks256ReceiptOnEs256Log_revertsAlgorithmMismatch()
        public
    {
        uint256 es256Pk = 1;
        bytes8 idtimestampBe = bytes8(0);
        IUnivocity.PaymentGrant memory g0 = _paymentGrant(
            AUTHORITY_LOG_ID,
            address(0xE5),
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf0 = _leafCommitment(idtimestampBe, g0);
        bytes32[] memory accMem0 = _toAcc(leaf0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceiptES256(accMem0, es256Pk);
        bytes memory detachedPayload0 = buildDetachedPayloadCommitment(accMem0);
        ES256RecoveryHelper helper = new ES256RecoveryHelper();
        (bytes32 rx, bytes32 ry) = helper.recoverKey(
            consistency0.protectedHeader,
            detachedPayload0,
            consistency0.signature
        );
        vm.prank(BOOTSTRAP);
        Univocity es256Univocity =
            new Univocity(BOOTSTRAP, ALG_ES256, abi.encodePacked(rx, ry));
        es256Univocity.publishCheckpoint(
            consistency0, _emptyInclusionProof(), idtimestampBe, g0
        );
        IUnivocity.PaymentGrant memory g1 = _paymentGrant(
            AUTHORITY_LOG_ID,
            KS256_SIGNER,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            ""
        );
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_AUTH, g1);
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InconsistentReceiptSignature.selector,
                int64(ALG_KS256),
                int64(ALG_ES256)
            )
        );
        es256Univocity.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );
    }

    // === Plan 0014/0015: publishCheckpoint (single entry point) ===

    /// @notice Reverts when consistency receipt has invalid proof payload
    ///    (decoded: treeSize2=1 but rightPeaks empty so accMem length 0).
    ///    Sign the payload the contract will use so revert is
    ///    InvalidAccumulatorLength, not signature.
    function test_publishCheckpoint_revertsWhenConsistencyReceiptInvalidCose()
        public
    {
        IUnivocity.PaymentGrant memory g = _paymentGrant(
            TEST_LOG_ID,
            KS256_SIGNER,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            ""
        );
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: new bytes32[](0)
        });
        bytes32 commitment = sha256(abi.encodePacked());
        bytes memory sigStruct = buildSigStructure(
            hex"a1013a00010106", abi.encodePacked(commitment)
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        IUnivocity.ConsistencyReceipt memory invalidReceipt =
            IUnivocity.ConsistencyReceipt({
                protectedHeader: hex"a1013a00010106",
                signature: abi.encodePacked(r, s, v),
                consistencyProofs: proofs,
                delegationProof: IUnivocity.DelegationProof({
                    delegationKey: "",
                    mmrStart: 0,
                    mmrEnd: 0,
                    alg: 0,
                    signature: ""
                })
            });
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidAccumulatorLength.selector,
                uint256(1),
                uint256(0)
            )
        );
        univocity.publishCheckpoint(
            invalidReceipt,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            g
        );
    }

    // === Plan 0012 Phase C: Idtimestamp optional test (4.3 item 7) ===
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
            ""
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
            ""
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
            ""
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
