// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    LibAuthorityVerifier
} from "@univocity/checkpoints/lib/LibAuthorityVerifier.sol";

contract LibAuthorityVerifierTest is Test {
    bytes32 constant LOG_A = keccak256("log-a");
    bytes32 constant LOG_B = keccak256("log-b");
    address constant PAYER = address(0x1234);

    function test_checkBounds_allPass() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 1000,
                minGrowth: 0
            });
        assertTrue(LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 0, 500));
    }

    function test_checkBounds_logIdMismatch() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 1000,
                minGrowth: 0
            });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_B, 5, 0, 500));
    }

    function test_checkBounds_belowStart() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 5,
                checkpointEnd: 10,
                maxHeight: 1000,
                minGrowth: 0
            });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_A, 3, 0, 500));
    }

    function test_checkBounds_atOrAboveEnd() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 1000,
                minGrowth: 0
            });
        assertFalse(
            LibAuthorityVerifier.checkBounds(claims, LOG_A, 10, 0, 500)
        );
        assertFalse(
            LibAuthorityVerifier.checkBounds(claims, LOG_A, 11, 0, 500)
        );
    }

    function test_checkBounds_maxHeightExceeded() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 100,
                minGrowth: 0
            });
        assertFalse(LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 0, 101));
    }

    function test_checkBounds_maxHeightZeroUnlimited() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 0,
                minGrowth: 0
            });
        assertTrue(LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 0, 1e18));
    }

    function test_checkBounds_minGrowthMet() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 1000,
                minGrowth: 100
            });
        assertTrue(
            LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 400, 500)
        );
    }

    function test_checkBounds_minGrowthNotMet() public pure {
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.PaymentClaims({
                logId: LOG_A,
                payer: PAYER,
                checkpointStart: 0,
                checkpointEnd: 10,
                maxHeight: 1000,
                minGrowth: 100
            });
        assertFalse(
            LibAuthorityVerifier.checkBounds(claims, LOG_A, 5, 400, 499)
        );
    }
}
