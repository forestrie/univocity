// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Bootstrap and first-checkpoint tests for Univocity. Plan 0022 Phase 0:
///   split from Univocity.t.sol; uses UnivocityTestHelper. Add GF_REQUIRE_SIGNER
///   bootstrap tests here (Plan 0022 Phase 4).

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";

contract UnivocityBootstrapTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
    }

    function test_bootstrap_constructor_setsBootstrapAuthority() public view {
        assertEq(univocity.bootstrapAuthority(), BOOTSTRAP);
    }

    function test_bootstrap_constructor_setsKs256Signer() public view {
        assertEq(univocity.ks256Signer(), KS256_SIGNER);
    }

    function test_bootstrap_firstCheckpoint_revertsIfSizeZero() public {
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
        univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
        assertEq(univocity.rootLogId(), AUTHORITY_LOG_ID);
    }
}
