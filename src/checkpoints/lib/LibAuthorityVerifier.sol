// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../../algorithms/LibBinUtils.sol";
import "../../cose/lib/LibCose.sol";
import "../../cbor/lib/LibCbor.sol";

/// @title LibAuthorityVerifier
/// @notice Verifies SCITT-format payment receipts for R5 authorization
/// @dev Payment receipts are standard COSE_Sign1 with CBOR payload claims
/// @dev Uses custom CBOR parsing with WitnetBuffer for safety
library LibAuthorityVerifier {
    /// @notice Decoded payment claims from SCITT receipt
    /// @dev Uses uint64 for counters (CBOR max int size, practically sufficient)
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
    /// @param keys Bootstrap keys for signature verification (ES256 and/or KS256)
    /// @return claims Decoded payment claims
    function verifyAndDecode(bytes calldata receipt, LibCose.BootstrapKeys memory keys)
        internal
        view
        returns (PaymentClaims memory claims)
    {
        // 1. Decode COSE_Sign1 structure (extracts algorithm from protected header)
        LibCose.CoseSign1 memory cose = LibCose.decodeCoseSign1(receipt);

        // 2. Verify signature with algorithm dispatch (ES256 or KS256)
        //    ES256: OpenZeppelin P256 (RIP-7212 when available)
        //    KS256: Native ecrecover
        if (!LibCose.verifySignature(cose, keys)) {
            revert InvalidReceiptSignature();
        }

        // 3. Decode CBOR payload claims
        LibCbor.PaymentClaims memory decoded = LibCbor.decodePaymentClaims(cose.payload);

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
    function checkBounds(PaymentClaims memory claims, bytes32 logId, uint64 checkpointCount, uint64 size)
        internal
        pure
        returns (bool)
    {
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
    /// @param receiptHash Hash of the receipt content
    /// @param proof Inclusion proof (MMR path)
    /// @param accumulator Current authority log accumulator
    /// @param leafIndex Index of receipt in MMR
    /// @return True if inclusion verified
    function verifyReceiptInclusion(
        bytes32 receiptHash,
        bytes32[] memory proof,
        bytes32[] memory accumulator,
        uint64 leafIndex
    ) internal pure returns (bool) {
        // Compute the root implied by the inclusion proof
        bytes32 computedRoot = _includedRootMemory(leafIndex, receiptHash, proof);

        // Check if computed root matches any peak in the accumulator
        for (uint256 i = 0; i < accumulator.length; i++) {
            if (accumulator[i] == computedRoot) {
                return true;
            }
        }

        return false;
    }

    /// @notice Internal version of includedRoot that works with memory arrays
    /// @dev Mirrors the logic from includedRoot.sol but accepts memory proof
    function _includedRootMemory(uint64 i, bytes32 nodeHash, bytes32[] memory proof)
        private
        pure
        returns (bytes32 root)
    {
        root = nodeHash;
        uint256 idx = i;
        uint256 g = LibBinUtils.indexHeight(idx);

        for (uint256 j = 0; j < proof.length; j++) {
            bytes32 sibling = proof[j];

            if (LibBinUtils.indexHeight(idx + 1) > g) {
                idx = idx + 1;
                root = LibBinUtils.hashPosPair64(uint64(idx + 1), sibling, root);
            } else {
                idx = idx + (2 << g);
                root = LibBinUtils.hashPosPair64(uint64(idx + 1), root, sibling);
            }

            g = g + 1;
        }
    }
}
