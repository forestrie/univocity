// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {IUnivocityEvents} from "@univocity/checkpoints/interfaces/IUnivocityEvents.sol";
import {IUnivocityErrors} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";

contract UnivocityTest is Test, IUnivocityEvents {
    Univocity internal univocity;

    address internal constant BOOTSTRAP = address(0xB007);
    uint256 internal constant SIGNER_PK = 1;
    address internal KS256_SIGNER;
    bytes32 internal constant AUTHORITY_LOG_ID = keccak256("authority-log");
    bytes32 internal constant TEST_LOG_ID = keccak256("test-log");
    bytes8 internal constant IDTIMESTAMP_AUTH = bytes8(0);   // first receipt (authority bootstrap)
    bytes8 internal constant IDTIMESTAMP_TEST = bytes8(uint64(1)); // second receipt (TEST_LOG) in authority

    function setUp() public {
        KS256_SIGNER = vm.addr(SIGNER_PK);
        vm.prank(BOOTSTRAP);
        univocity = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));

        // First checkpoint: bootstrap receipt must be first entry; leaf = H(idtimestampBe ‖ sha256(receipt)) (ADR-0030)
        (bytes memory receipt, bytes32[] memory acc,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);
        univocity.publishCheckpoint(AUTHORITY_LOG_ID, 1, acc, receipt, new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_AUTH);

        // Second checkpoint to authority: add TEST_LOG receipt at index 1 (size 2 = two peaks)
        (bytes memory testReceipt,,) = _buildBootstrapReceiptAndAcc(TEST_LOG_ID, IDTIMESTAMP_TEST);
        testLogReceipt = testReceipt;
        bytes32[] memory accSize2 = new bytes32[](2);
        accSize2[0] = sha256(abi.encodePacked(IDTIMESTAMP_AUTH, sha256(receipt)));
        accSize2[1] = sha256(abi.encodePacked(IDTIMESTAMP_TEST, sha256(testReceipt)));
        bytes32[][] memory consistencyProof = new bytes32[][](1);
        consistencyProof[0] = new bytes32[](0);
        univocity.publishCheckpoint(AUTHORITY_LOG_ID, 2, accSize2, receipt, consistencyProof, 0, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    bytes internal testLogReceipt;

    /// @notice Build a bootstrap receipt and accumulator; leaf = H(receiptIdtimestampBe ‖ sha256(receipt)) per ADR-0030.
    function _buildBootstrapReceiptAndAcc(bytes32 logId, bytes8 receiptIdtimestampBe)
        internal
        view
        returns (bytes memory receipt, bytes32[] memory accumulator, bytes32[] memory inclusionProof)
    {
        bytes memory payload = abi.encodePacked(
            hex"a5",
            hex"025820", logId,
            hex"2054", KS256_SIGNER,
            hex"21", _uintCbor(0),
            hex"22", _uintCbor(10),
            hex"23", _uintCbor(0)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, keccak256(sigStruct));
        receipt = abi.encodePacked(hex"84", _cborBstr(protected), hex"a0", _cborBstr(payload), _cborBstr(abi.encodePacked(r, s, v)));
        accumulator = new bytes32[](1);
        accumulator[0] = sha256(abi.encodePacked(receiptIdtimestampBe, sha256(receipt)));
        inclusionProof = new bytes32[](0);
    }

    function _uintCbor(uint64 n) internal pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(bytes1(uint8(n)));
        if (n < 256) return abi.encodePacked(hex"18", bytes1(uint8(n)));
        return abi.encodePacked(hex"19", bytes2(uint16(n)));
    }

    function _cborBstr(bytes memory data) internal pure returns (bytes memory) {
        if (data.length < 24) return abi.encodePacked(bytes1(uint8(0x40 + data.length)), data);
        if (data.length < 256) return abi.encodePacked(hex"58", bytes1(uint8(data.length)), data);
        revert("unsupported length");
    }

    // === Initialization Tests ===

    function test_constructor_setsBootstrapAuthority() public view {
        assertEq(univocity.bootstrapAuthority(), BOOTSTRAP);
    }

    function test_constructor_setsKs256Signer() public view {
        assertEq(univocity.ks256Signer(), KS256_SIGNER);
    }

    function test_firstCheckpoint_revertsIfSizeZero() public {
        (bytes memory receipt,,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);
        Univocity fresh = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        vm.expectRevert(IUnivocityErrors.FirstCheckpointSizeTooSmall.selector);
        fresh.publishCheckpoint(AUTHORITY_LOG_ID, 0, new bytes32[](0), receipt, new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    function test_firstCheckpoint_revertsIfReceiptMmrIndexNotZero() public {
        (bytes memory receipt, bytes32[] memory acc,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);
        Univocity fresh = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        vm.expectRevert(IUnivocityErrors.BootstrapReceiptMustBeFirstEntry.selector);
        fresh.publishCheckpoint(AUTHORITY_LOG_ID, 1, acc, receipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    function test_initialize_setsAuthorityLogId() public view {
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_emitsInitialized() public {
        Univocity newUnivocity = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        (bytes memory receipt, bytes32[] memory acc, bytes32[] memory proof) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);

        vm.expectEmit(true, true, false, false);
        emit Initialized(BOOTSTRAP, AUTHORITY_LOG_ID);
        newUnivocity.publishCheckpoint(AUTHORITY_LOG_ID, 1, acc, receipt, new bytes32[][](0), 0, proof, IDTIMESTAMP_AUTH);
    }

    function test_authorityLogId_immutableAfterFirstPublish() public view {
        // After setUp, authority log is AUTHORITY_LOG_ID; no way to change it
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_revertsIfReceiptEmpty() public {
        Univocity newUnivocity = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = keccak256("peak");

        vm.expectRevert(IUnivocityErrors.OnlyBootstrapAuthority.selector);
        newUnivocity.publishCheckpoint(AUTHORITY_LOG_ID, 1, acc, "", new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    function test_firstCheckpoint_revertsIfReceiptTargetsDifferentLog() public {
        // Receipt for AUTHORITY_LOG_ID but we pass a different logId => ReceiptLogIdMismatch
        (bytes memory receipt, bytes32[] memory acc,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);
        Univocity fresh = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes32 otherLogId = keccak256("other-log");

        vm.expectRevert(
            abi.encodeWithSelector(IUnivocityErrors.ReceiptLogIdMismatch.selector, otherLogId, AUTHORITY_LOG_ID)
        );
        fresh.publishCheckpoint(otherLogId, 1, acc, receipt, new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    function test_firstCheckpoint_revertsIfAccumulatorDoesNotContainReceipt() public {
        (bytes memory receipt,,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);
        Univocity fresh = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes32[] memory wrongAcc = new bytes32[](1);
        wrongAcc[0] = keccak256("wrong-peak"); // not H(idtimestampBe ‖ sha256(receipt))

        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(AUTHORITY_LOG_ID, 1, wrongAcc, receipt, new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    function test_firstCheckpoint_succeedsFromNonBootstrapSender() public {
        // First checkpoint is permissionless: any sender with valid bootstrap receipt can initialize
        Univocity fresh = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        (bytes memory receipt, bytes32[] memory acc,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);

        vm.prank(address(0x999)); // not BOOTSTRAP
        fresh.publishCheckpoint(AUTHORITY_LOG_ID, 1, acc, receipt, new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_AUTH);

        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);
        assertTrue(fresh.isLogInitialized(AUTHORITY_LOG_ID));
    }

    // === Bootstrap Checkpoint Publishing Tests ===

    function test_publishCheckpoint_bootstrapCanPublishToAuthorityLog() public {
        // Third checkpoint on authority log (setUp has size 2; now size 2→3, one peak)
        (bytes memory receipt,,) = _buildBootstrapReceiptAndAcc(AUTHORITY_LOG_ID, IDTIMESTAMP_AUTH);
        bytes32 authLeaf = sha256(abi.encodePacked(IDTIMESTAMP_AUTH, sha256(receipt)));
        bytes32 testLeaf = sha256(abi.encodePacked(IDTIMESTAMP_TEST, sha256(testLogReceipt)));
        bytes32 peak3 = LibBinUtils.hashPosPair64(3, authLeaf, testLeaf);
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = peak3;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = testLeaf;
        proofs[1] = new bytes32[](1);
        proofs[1][0] = authLeaf;

        univocity.publishCheckpoint(AUTHORITY_LOG_ID, 3, accumulator, receipt, proofs, 0, new bytes32[](0), IDTIMESTAMP_AUTH);

        assertTrue(univocity.isLogInitialized(AUTHORITY_LOG_ID));
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_publishCheckpoint_bootstrapCanPublishToAnyLog() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);

        assertTrue(univocity.isLogInitialized(TEST_LOG_ID));
    }

    function test_publishCheckpoint_emitsLogRegistered() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        vm.expectEmit(true, true, false, true);
        emit LogRegistered(TEST_LOG_ID, BOOTSTRAP, 1);
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);
    }

    function test_publishCheckpoint_emitsCheckpointPublished() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        vm.expectEmit(true, true, false, false);
        emit CheckpointPublished(TEST_LOG_ID, 1, 1, accumulator, testLogReceipt);
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);
    }

    function test_publishCheckpoint_incrementsCheckpointCount() public {
        // First checkpoint: size=1, one peak (from consistentRoots test_consistentRoots_0_to_2)
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = 0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;

        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 1);

        // Second checkpoint: size=3, one peak (consistency proof from same test vector; peaks(2).length == 1)
        bytes32[] memory accumulator2 = new bytes32[](1);
        accumulator2[0] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;

        univocity.publishCheckpoint(TEST_LOG_ID, 3, accumulator2, testLogReceipt, proofs, 1, new bytes32[](0), IDTIMESTAMP_TEST);

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 2);
    }

    // === Validation Tests ===

    function test_publishCheckpoint_revertsOnSizeDecrease() public {
        // size=3 has 1 peak (peaks(2).length)
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        univocity.publishCheckpoint(TEST_LOG_ID, 3, accumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);

        // size=2 has 2 peaks; try to publish smaller size
        bytes32[] memory accumulator2 = new bytes32[](2);
        accumulator2[0] = keccak256("peak1");
        accumulator2[1] = keccak256("peak2");

        vm.expectRevert(abi.encodeWithSelector(IUnivocityErrors.SizeMustIncrease.selector, 3, 2));
        univocity.publishCheckpoint(TEST_LOG_ID, 2, accumulator2, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);
    }

    function test_publishCheckpoint_revertsOnInvalidAccumulatorLength() public {
        // size=3 has 1 peak (peaks(2).length), but we provide 2
        bytes32[] memory wrongAccumulator = new bytes32[](2);
        wrongAccumulator[0] = keccak256("peak1");
        wrongAccumulator[1] = keccak256("peak2");

        vm.expectRevert(abi.encodeWithSelector(IUnivocityErrors.InvalidAccumulatorLength.selector, 1, 2));
        univocity.publishCheckpoint(TEST_LOG_ID, 3, wrongAccumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);
    }

    function test_publishCheckpoint_revertsOnInvalidConsistencyProof() public {
        // First checkpoint (size=1)
        bytes32[] memory acc1 = new bytes32[](1);
        acc1[0] = 0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        univocity.publishCheckpoint(TEST_LOG_ID, 1, acc1, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);

        // Second checkpoint size=3 (1 peak) with wrong proof (wrong sibling hash so root won't match)
        bytes32[] memory acc2 = new bytes32[](1);
        acc2[0] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
        bytes32[][] memory wrongProofs = new bytes32[][](1);
        wrongProofs[0] = new bytes32[](1);
        wrongProofs[0][0] = bytes32(0); // Wrong proof element

        vm.prank(BOOTSTRAP);
        vm.expectRevert(IUnivocityErrors.InvalidConsistencyProof.selector);
        univocity.publishCheckpoint(TEST_LOG_ID, 3, acc2, testLogReceipt, wrongProofs, 1, new bytes32[](0), IDTIMESTAMP_TEST);
    }

    // === Authorization Tests ===

    function test_publishCheckpoint_authorityLogOnlyBootstrap() public {
        // Non-bootstrap (no valid receipt) cannot publish to authority log
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;

        vm.expectRevert(IUnivocityErrors.OnlyBootstrapAuthority.selector);
        univocity.publishCheckpoint(AUTHORITY_LOG_ID, 3, accumulator, "", proofs, 0, new bytes32[](0), IDTIMESTAMP_AUTH);
    }

    function test_publishCheckpoint_nonBootstrapNeedsReceipt() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        // Non-bootstrap trying to publish without valid receipt should fail
        // (Will revert during receipt decoding since empty bytes is invalid COSE)
        vm.prank(address(0xDEAD));
        vm.expectRevert(); // Will fail during COSE decoding
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", new bytes32[][](0), 0, new bytes32[](0), IDTIMESTAMP_TEST);
    }

    // === View Function Tests ===

    function test_getLogState_returnsCorrectState() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, testLogReceipt, new bytes32[][](0), 1, new bytes32[](0), IDTIMESTAMP_TEST);

        Univocity.LogState memory state = univocity.getLogState(TEST_LOG_ID);
        assertEq(state.size, 1);
        assertEq(state.checkpointCount, 1);
        assertEq(state.accumulator.length, 1);
        assertEq(state.accumulator[0], accumulator[0]);
        assertGt(state.initializedAt, 0);
    }

    function test_isLogInitialized_returnsFalseForNewLog() public view {
        assertFalse(univocity.isLogInitialized(keccak256("nonexistent")));
    }
}
