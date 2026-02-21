// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocityEvents} from "@univocity/checkpoints/interfaces/IUnivocityEvents.sol";
import {IUnivocityErrors} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";

contract UnivocityTest is Test, IUnivocityEvents {
    Univocity internal univocity;

    address internal constant BOOTSTRAP = address(0xB007);
    address internal constant KS256_SIGNER = address(0x5196);
    bytes32 internal constant AUTHORITY_LOG_ID = keccak256("authority-log");
    bytes32 internal constant TEST_LOG_ID = keccak256("test-log");

    function setUp() public {
        vm.prank(BOOTSTRAP);
        univocity = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));

        vm.prank(BOOTSTRAP);
        univocity.initialize(AUTHORITY_LOG_ID);
    }

    // === Initialization Tests ===

    function test_constructor_setsBootstrapAuthority() public view {
        assertEq(univocity.bootstrapAuthority(), BOOTSTRAP);
    }

    function test_constructor_setsKs256Signer() public view {
        assertEq(univocity.ks256Signer(), KS256_SIGNER);
    }

    function test_initialize_setsAuthorityLogId() public view {
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_initialize_emitsInitialized() public {
        Univocity newUnivocity = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));

        vm.prank(BOOTSTRAP);
        vm.expectEmit(true, true, false, false);
        emit Initialized(BOOTSTRAP, AUTHORITY_LOG_ID);
        newUnivocity.initialize(AUTHORITY_LOG_ID);
    }

    function test_initialize_revertsIfCalledTwice() public {
        vm.prank(BOOTSTRAP);
        vm.expectRevert(IUnivocityErrors.AlreadyInitialized.selector);
        univocity.initialize(keccak256("other"));
    }

    function test_initialize_revertsIfNotBootstrap() public {
        Univocity newUnivocity = new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));

        vm.prank(address(0xDEAD));
        vm.expectRevert(IUnivocityErrors.OnlyBootstrapAuthority.selector);
        newUnivocity.initialize(AUTHORITY_LOG_ID);
    }

    // === Bootstrap Checkpoint Publishing Tests ===

    function test_publishCheckpoint_bootstrapCanPublishToAuthorityLog() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            AUTHORITY_LOG_ID,
            1, // size=1 has 1 peak
            accumulator,
            "", // no receipt needed for bootstrap
            "", // no consistency proof for first checkpoint
            "" // no inclusion proof for bootstrap
        );

        assertTrue(univocity.isLogInitialized(AUTHORITY_LOG_ID));
    }

    function test_publishCheckpoint_bootstrapCanPublishToAnyLog() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", "", "");

        assertTrue(univocity.isLogInitialized(TEST_LOG_ID));
    }

    function test_publishCheckpoint_emitsLogRegistered() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        vm.expectEmit(true, true, false, true);
        emit LogRegistered(TEST_LOG_ID, BOOTSTRAP, 1);
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", "", "");
    }

    function test_publishCheckpoint_emitsCheckpointPublished() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        vm.expectEmit(true, true, false, false);
        emit CheckpointPublished(TEST_LOG_ID, 1, 1, accumulator, "");
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", "", "");
    }

    function test_publishCheckpoint_incrementsCheckpointCount() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", "", "");

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 1);

        // Second checkpoint (size=3 has 2 peaks: binary 11)
        bytes32[] memory accumulator2 = new bytes32[](2);
        accumulator2[0] = keccak256("peak1");
        accumulator2[1] = keccak256("peak2");

        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(TEST_LOG_ID, 3, accumulator2, "", "", "");

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 2);
    }

    // === Validation Tests ===

    function test_publishCheckpoint_revertsOnSizeDecrease() public {
        bytes32[] memory accumulator = new bytes32[](2);
        accumulator[0] = keccak256("peak1");
        accumulator[1] = keccak256("peak2");

        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(TEST_LOG_ID, 3, accumulator, "", "", "");

        bytes32[] memory accumulator2 = new bytes32[](1);
        accumulator2[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        vm.expectRevert(abi.encodeWithSelector(IUnivocityErrors.SizeMustIncrease.selector, 3, 2));
        univocity.publishCheckpoint(TEST_LOG_ID, 2, accumulator2, "", "", "");
    }

    function test_publishCheckpoint_revertsOnInvalidAccumulatorLength() public {
        // size=3 has 2 peaks (binary 11), but we provide 1
        bytes32[] memory wrongAccumulator = new bytes32[](1);
        wrongAccumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        vm.expectRevert(abi.encodeWithSelector(IUnivocityErrors.InvalidAccumulatorLength.selector, 2, 1));
        univocity.publishCheckpoint(TEST_LOG_ID, 3, wrongAccumulator, "", "", "");
    }

    // === Authorization Tests ===

    function test_publishCheckpoint_authorityLogOnlyBootstrap() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(address(0xDEAD));
        vm.expectRevert(IUnivocityErrors.OnlyBootstrapAuthority.selector);
        univocity.publishCheckpoint(AUTHORITY_LOG_ID, 1, accumulator, "", "", "");
    }

    function test_publishCheckpoint_nonBootstrapNeedsReceipt() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        // Non-bootstrap trying to publish without valid receipt should fail
        // (Will revert during receipt decoding since empty bytes is invalid COSE)
        vm.prank(address(0xDEAD));
        vm.expectRevert(); // Will fail during COSE decoding
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", "", "");
    }

    // === View Function Tests ===

    function test_getLogState_returnsCorrectState() public {
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = keccak256("peak1");

        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(TEST_LOG_ID, 1, accumulator, "", "", "");

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
