// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";

/// @title LibAuthorityVerifier
/// @notice Verifies SCITT-format payment receipts for R5 authorization
/// @dev Payment receipts are standard COSE_Sign1 with CBOR payload claims
/// @dev Uses custom CBOR parsing with WitnetBuffer for safety
library LibAuthorityVerifier {
    /// @notice Decoded payment claims from SCITT receipt
    /// @dev Uses uint64 for counters (CBOR max int size,
    ///    practically sufficient)
    struct PaymentClaims {
        bytes32 targetLogId;
        address payer;
        uint64 checkpointStart;
        uint64 checkpointEnd;
        uint64 maxHeight;
    }

    error InvalidReceiptSignature();
    error ReceiptLogIdMismatch(bytes32 expected, bytes32 actual);
    error CheckpointCountBelowStart(uint64 current, uint64 start);
    error CheckpointCountExceeded(uint64 current, uint64 end);
    error MaxHeightExceeded(uint64 size, uint64 maxHeight);

    /// @notice Verify and decode a SCITT payment receipt
    /// @param receipt Raw COSE_Sign1 receipt bytes
    /// @param keys Bootstrap keys for signature verification (ES256 and/or
    ///    KS256)
    /// @return claims Decoded payment claims
    function verifyAndDecode(
        bytes calldata receipt,
        LibCose.BootstrapKeys memory keys
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
        claims.targetLogId = decoded.targetLogId;
        claims.payer = decoded.payer;
        claims.checkpointStart = decoded.checkpointStart;
        claims.checkpointEnd = decoded.checkpointEnd;
        claims.maxHeight = decoded.maxHeight;
    }

    /// @notice Check R5 authorization bounds
    /// @param claims Decoded payment claims
    /// @param logId Log being checkpointed
    /// @param checkpointCount Current checkpoint count for log
    /// @param size Proposed checkpoint size (uint64 per SCITT profile)
    /// @return True if authorized
    function checkBounds(
        PaymentClaims memory claims,
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size
    ) internal pure returns (bool) {
        // Verify logId matches receipt subject
        if (claims.targetLogId != logId) return false;

        // Verify checkpoint count in range [start, end)
        if (checkpointCount < claims.checkpointStart) return false;
        if (checkpointCount >= claims.checkpointEnd) return false;

        // Verify size within maxHeight (0 = unlimited)
        if (claims.maxHeight != 0 && size > claims.maxHeight) return false;

        return true;
    }

    /// @notice Verify receipt is included in authority log
    /// @dev Caller supplies the leaf hash.
    ///    Univocity computes leaf = H(receiptIdtimestampBe ||
    ///    sha256(receipt))
    ///    per ADR-0030 and passes it as receiptHash.
    /// @param receiptHash Leaf hash:
    ///    H(receiptIdtimestampBe || sha256(receipt)) when called from
    ///    Univocity
    /// @param proof MMR path (sibling hashes), calldata
    /// @param accumulator Current authority log accumulator
    /// @param mmrIndex Zero-based MMR index of the receipt leaf (leaf position
    ///    - 1)
    /// @return True if inclusion verified
    function verifyReceiptInclusion(
        bytes32 receiptHash,
        bytes32[] calldata proof,
        bytes32[] memory accumulator,
        uint64 mmrIndex
    ) internal pure returns (bool) {
        bytes32 computedRoot = includedRoot(mmrIndex, receiptHash, proof);

        for (uint256 i = 0; i < accumulator.length; i++) {
            if (accumulator[i] == computedRoot) {
                return true;
            }
        }

        return false;
    }
}
