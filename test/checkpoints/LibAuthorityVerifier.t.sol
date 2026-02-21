// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibAuthorityVerifier} from "@univocity/checkpoints/lib/LibAuthorityVerifier.sol";

/// @notice Harness so tests can pass proof/accumulator as calldata (external call boundary)
contract LibAuthorityVerifierHarness {
    function verifyReceiptInclusion(
        bytes32 receiptHash,
        bytes32[] calldata proof,
        bytes32[] calldata accumulator,
        uint64 mmrIndex
    ) external pure returns (bool) {
        bytes32[] memory acc = accumulator;
        return LibAuthorityVerifier.verifyReceiptInclusion(receiptHash, proof, acc, mmrIndex);
    }
}

contract LibAuthorityVerifierTest is Test {
    LibAuthorityVerifierHarness harness = new LibAuthorityVerifierHarness();
    bytes32 constant LOG_A = keccak256("log-a");
    bytes32 constant LOG_B = keccak256("log-b");
    address constant PAYER = address(0x1234);

    function test_checkBounds_allPass() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims = LibAuthorityVerifier.PaymentClaims({
            targetLogId: LOG_A,
            payer: PAYER,
            checkpointStart: 0,
            checkpointEnd: 10,
            maxHeight: 1000
        });
        assertTrue(LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 500));
    }

    function test_checkBounds_logIdMismatch() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims = LibAuthorityVerifier.PaymentClaims({
            targetLogId: LOG_A,
            payer: PAYER,
            checkpointStart: 0,
            checkpointEnd: 10,
            maxHeight: 1000
        });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_B, 5, 500));
    }

    function test_checkBounds_belowStart() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims = LibAuthorityVerifier.PaymentClaims({
            targetLogId: LOG_A,
            payer: PAYER,
            checkpointStart: 5,
            checkpointEnd: 10,
            maxHeight: 1000
        });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_A, 3, 500));
    }

    function test_checkBounds_atOrAboveEnd() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims = LibAuthorityVerifier.PaymentClaims({
            targetLogId: LOG_A,
            payer: PAYER,
            checkpointStart: 0,
            checkpointEnd: 10,
            maxHeight: 1000
        });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_A, 10, 500));
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_A, 11, 500));
    }

    function test_checkBounds_maxHeightExceeded() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims = LibAuthorityVerifier.PaymentClaims({
            targetLogId: LOG_A,
            payer: PAYER,
            checkpointStart: 0,
            checkpointEnd: 10,
            maxHeight: 100
        });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 101));
    }

    function test_checkBounds_maxHeightZeroUnlimited() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims = LibAuthorityVerifier.PaymentClaims({
            targetLogId: LOG_A,
            payer: PAYER,
            checkpointStart: 0,
            checkpointEnd: 10,
            maxHeight: 0
        });
        assertTrue(LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 1e18));
    }

    /// @notice Empty proof: leaf is the only node, so root = leafHash (SHA-256 per MMR profile)
    function test_verifyReceiptInclusion_emptyProof_singlePeak() public view {
        bytes32 receiptHash = sha256("receipt");
        bytes32[] memory proof;
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = receiptHash;

        assertTrue(harness.verifyReceiptInclusion(receiptHash, proof, accumulator, 0));
    }

    /// @notice Wrong receipt hash does not match peak
    function test_verifyReceiptInclusion_wrongHash_fails() public view {
        bytes32 receiptHash = sha256("receipt");
        bytes32 wrongHash = sha256("wrong");
        bytes32[] memory proof;
        bytes32[] memory accumulator = new bytes32[](1);
        accumulator[0] = receiptHash;

        assertFalse(harness.verifyReceiptInclusion(wrongHash, proof, accumulator, 0));
    }
}
