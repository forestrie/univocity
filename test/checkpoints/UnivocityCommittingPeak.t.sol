// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice committingPeak on a real instance: the peak read from storage
///    equals the peak found by walking the accumulator from logState.

import "./UnivocityTestHelper.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";
import {
    ConsistencyReceipt,
    PublishGrant
} from "@univocity/interfaces/types.sol";

contract UnivocityCommittingPeakTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

    /// @dev Oracle independent of the contract's formula: the committing
    ///    peak of node `index` is the first peak position at or after it.
    function _expected(bytes32 logId, uint256 index)
        internal
        view
        returns (uint64 size, bytes32 peak)
    {
        bytes32[] memory acc = univocity.logState(logId).accumulator;
        size = univocity.logState(logId).size;
        if (size == 0 || index >= size) return (size, bytes32(0));
        uint256[] memory pos = peaks(size - 1);
        for (uint256 k = 0; k < pos.length; k++) {
            if (pos[k] >= index) return (size, acc[k]);
        }
    }

    function _checkEveryIndex(uint256 size) internal view {
        assertEq(univocity.logState(AUTHORITY_LOG_ID).size, size);
        for (uint256 i = 0; i < size + 3; i++) {
            (uint64 s, bytes32 p) =
                univocity.committingPeak(AUTHORITY_LOG_ID, i);
            (uint64 es, bytes32 ep) = _expected(AUTHORITY_LOG_ID, i);
            assertEq(s, es, "size");
            assertEq(p, ep, "peak");
            if (i >= size) assertEq(p, bytes32(0), "beyond size");
            else assertTrue(p != bytes32(0), "in range");
        }
    }

    function test_committingPeak_sizeThree_matchesLogState() public view {
        _checkEveryIndex(3);
    }

    function test_committingPeak_sizeFour_matchesLogState() public {
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
        univocity.publishCheckpoint(
            _buildConsistencyReceipt3To4(
                authorityLeaf0, authorityLeaf1, keccak256("extra")
            ),
            _buildPaymentInclusionProof(0, _path1(authorityLeaf1)),
            IDTIMESTAMP_AUTH,
            g
        );
        _checkEveryIndex(4);
    }

    function test_committingPeak_uninitialisedLog_isZero() public view {
        (uint64 s, bytes32 p) =
            univocity.committingPeak(keccak256("unknown"), 0);
        assertEq(s, 0);
        assertEq(p, bytes32(0));
    }
}
