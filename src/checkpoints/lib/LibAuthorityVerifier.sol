// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";

/// @title LibAuthorityVerifier
/// @notice Verifies SCITT-format payment receipts for R5 authorization
/// @dev Payment receipts are standard COSE_Sign1 with CBOR payload claims
/// @dev Uses custom CBOR parsing with WitnetBuffer for safety
library LibAuthorityVerifier {
    /// @notice Decoded payment claims from SCITT receipt
    /// @dev Uses uint64 for counters (CBOR max int size,
    ///    practically sufficient)
    struct PaymentClaims {
        bytes32 logId;
        address payer;
        uint64 checkpointStart;
        uint64 checkpointEnd;
        uint64 maxHeight;
        uint64 minGrowth;
    }

    error InvalidReceiptSignature();
    error ReceiptLogIdMismatch(bytes32 expected, bytes32 actual);
    error CheckpointCountBelowStart(uint64 current, uint64 start);
    error CheckpointCountExceeded(uint64 current, uint64 end);
    error MaxHeightExceeded(uint64 size, uint64 maxHeight);

    /// @notice Verify and decode a SCITT payment receipt
    /// @param receipt Raw COSE_Sign1 receipt bytes
    /// @param keys Verifier keys for signature (ES256 and/or KS256)
    /// @return claims Decoded payment claims
    function verifyAndDecode(
        bytes calldata receipt,
        LibCose.CoseVerifierKeys memory keys
    ) internal view returns (PaymentClaims memory claims) {
        // 1.
        // Decode COSE_Sign1 structure (extracts algorithm from protected
        // header)
        LibCose.CoseSign1 memory cose = LibCose.decodeCoseSign1(receipt);

        // 2. Verify signature with algorithm dispatch (ES256 or KS256)
        //    ES256: OpenZeppelin P256 (RIP-7212 when available)
        //    KS256: Native ecrecover
        if (!LibCose.verifySignature(cose, keys)) {
            revert InvalidReceiptSignature();
        }

        // 3. Decode CBOR payload claims
        LibCbor.PaymentClaims memory decoded =
            LibCbor.decodePaymentClaims(cose.payload);

        // Copy to our struct
        claims.logId = decoded.logId;
        claims.payer = decoded.payer;
        claims.checkpointStart = decoded.checkpointStart;
        claims.checkpointEnd = decoded.checkpointEnd;
        claims.maxHeight = decoded.maxHeight;
        claims.minGrowth = decoded.minGrowth;
    }

    /// @notice Check R5 authorization bounds
    /// @param claims Decoded payment claims
    /// @param logId Log being checkpointed
    /// @param checkpointCount Current checkpoint count for log
    /// @param currentSize Current size (leaf count) of log
    /// @param size Proposed checkpoint size (uint64 per SCITT profile)
    /// @return True if authorized
    function checkBounds(
        PaymentClaims memory claims,
        bytes32 logId,
        uint64 checkpointCount,
        uint64 currentSize,
        uint64 size
    ) internal pure returns (bool) {
        // Verify logId matches receipt subject
        if (claims.logId != logId) return false;

        // Verify checkpoint count in range [start, end)
        if (checkpointCount < claims.checkpointStart) return false;
        if (checkpointCount >= claims.checkpointEnd) return false;

        // Verify size within maxHeight (0 = unlimited)
        if (claims.maxHeight != 0 && size > claims.maxHeight) return false;

        // Verify min_growth (size must be at least currentSize + minGrowth)
        if (size < currentSize + claims.minGrowth) return false;

        return true;
    }
}
