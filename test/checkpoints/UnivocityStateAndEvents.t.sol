// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice getLogState, events, isLogInitialized. Split from Univocity.t.sol
///   per test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityEvents
} from "@univocity/checkpoints/interfaces/IUnivocityEvents.sol";

contract UnivocityStateAndEventsTest is UnivocityTestHelper, IUnivocityEvents {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

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
}
