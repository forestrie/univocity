// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCoseReceipt} from "@univocity/cose/lib/LibCoseReceipt.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";
import {
    includedRoot,
    verifyInclusion
} from "@univocity/algorithms/includedRoot.sol";

/// @title LibInclusionReceipt
/// @notice MMR profile: decode and verify Receipt of Inclusion per draft
///    "Verifying the Receipt of inclusion". Uses includedRoot from
///    src/algorithms.
library LibInclusionReceipt {
    /// @notice Verify Receipt of Inclusion: decode proof, verify signature
    ///    over the implied root, verify inclusion via deterministic peak check
    ///    (go-merklelog/mmr).
    /// @param receipt Raw COSE_Sign1 Receipt of Inclusion (payload detached).
    /// @param leafHash The leaf whose inclusion is proved (e.g.
    ///    H(paymentIDTimestampBe || H(grant))).
    /// @param accumulator Peak hashes of the MMR (same order as peaks()).
    /// @param mmrSize Number of nodes in the MMR (last index + 1).
    /// @param keys Verifier keys for signature (bootstrap or delegated).
    /// @return True if receipt is valid and leaf is included in the
    ///    accumulator.
    function verifyReceiptOfInclusion(
        bytes calldata receipt,
        bytes32 leafHash,
        bytes32[] memory accumulator,
        uint64 mmrSize,
        LibCose.CoseVerifierKeys memory keys
    ) internal view returns (bool) {
        (LibCose.CoseSign1 memory decoded, bytes[] memory inclusionProofs) =
            LibCoseReceipt.decodeReceiptOfInclusionCoseSign1(receipt);

        if (inclusionProofs.length == 0) return false;

        LibCbor.InclusionProofPayload memory p =
            LibCbor.decodeInclusionProofPayload(inclusionProofs[0]);
        bytes32 root = includedRoot(p.index, leafHash, p.path);

        bytes memory detachedPayload = abi.encodePacked(root);
        if (!LibCose.verifySignatureDetachedPayload(
                decoded, detachedPayload, keys
            )) {
            return false;
        }

        return verifyInclusion(
            uint256(p.index), leafHash, p.path, accumulator, uint256(mmrSize)
        );
    }
}
