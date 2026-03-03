// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Bootstrap and first-checkpoint tests for Univocity. Plan 0022 Phase 0:
///   split from Univocity.t.sol; uses UnivocityTestHelper. Add first-checkpoint
///   bootstrap tests here (Plan 0022 Phase 4).

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    ConsistencyReceipt,
    PublishGrant
} from "@univocity/interfaces/types.sol";

contract UnivocityBootstrapTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
    }

    function test_bootstrap_constructor_setsKs256Signer() public view {
        assertEq(univocity.ks256Signer(), KS256_SIGNER);
    }

    function test_bootstrap_firstCheckpoint_revertsIfSizeZero() public {
        PublishGrant memory g = _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        vm.prank(BOOTSTRAP);
        try univocity.publishCheckpoint(
            _buildConsistencyReceiptSizeZero(),
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            g
        ) {
            fail("expected revert");
        } catch (bytes memory) {
            // any revert is acceptable (e.g. InvalidConsistencyProof)
        }
    }

    function test_bootstrap_firstCheckpoint_correctGrant_succeeds() public {
        PublishGrant memory g = _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
        assertEq(univocity.rootLogId(), AUTHORITY_LOG_ID);
    }
}
