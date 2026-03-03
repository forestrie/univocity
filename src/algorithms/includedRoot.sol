// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Computes the implied MMR root from a node hash and inclusion proof.
// Implements the included_root algorithm from
// draft-bryce-cose-receipts-mmr-profile.
// For a valid COSE receipt of inclusion, the returned root can be used as the
// detached payload to verify the receipt's signature.
// VerifyInclusion follows go-merklelog/mmr/verify.go: proven root must equal
// the single peak that commits the leaf (determined by proof length).

import {indexHeight, hashPosPair64} from "@univocity/algorithms/binUtils.sol";
import {leafCount, peakIndex} from "@univocity/algorithms/peaks.sol";

/// @notice Verify that a node is included in the MMR committed to by
///    accumulator (with non-empty proof). Matches go-merklelog/mmr
///    VerifyInclusion: peak chosen by PeakIndex(LeafCount(mmrSize),
///    len(proof)); root compared to that peak.
/// @param leafIndex Zero-based MMR index of the node.
/// @param nodeHash Hash of the node whose inclusion is proven.
/// @param proof Sibling hashes on the path to the peak (calldata).
/// @param accumulator Peak hashes for MMR(mmrSize-1), same order as peaks().
/// @param mmrSize Number of nodes in the MMR (last index + 1).
/// @return True if includedRoot matches the committing peak. Proof may be
///    empty (e.g. first leaf in single-peak MMR); pass the caller's path
///    from calldata.
function verifyInclusion(
    uint256 leafIndex,
    bytes32 nodeHash,
    bytes32[] calldata proof,
    bytes32[] memory accumulator,
    uint256 mmrSize
) pure returns (bool) {
    if (mmrSize == 0) return false;

    bytes32 root = proofLengthRoot(accumulator, mmrSize, proof.length);
    if (root == bytes32(0)) return false;

    return root == includedRoot(leafIndex, nodeHash, proof);
}

/// @notice Storage variant of verifyInclusion; reads peak from storage via
///    proofLengthRootStorage (no full accumulator copy to memory).
function verifyInclusionStorage(
    uint256 leafIndex,
    bytes32 nodeHash,
    bytes32[] calldata proof,
    bytes32[] storage accumulator,
    uint256 mmrSize
) view returns (bool) {
    if (mmrSize == 0) return false;

    bytes32 root = proofLengthRootStorage(accumulator, mmrSize, proof.length);
    if (root == bytes32(0)) return false;

    return root == includedRoot(leafIndex, nodeHash, proof);
}

/// @notice Returns the peak hash that commits a proof of the given length
///    (PeakIndex(LeafCount(mmrSize), proofLength)). Used by verifyInclusion.
/// @return The committing peak, or bytes32(0) if peak index out of range.
function proofLengthRoot(
    bytes32[] memory accumulator,
    uint256 mmrSize,
    uint256 proofLength
) pure returns (bytes32) {
    uint256 lc = leafCount(mmrSize);
    uint256 ipeak = peakIndex(lc, proofLength);

    if (ipeak >= accumulator.length) return bytes32(0);

    return accumulator[ipeak];
}

/// @notice Storage variant of proofLengthRoot; reads peak from storage
///    (no accumulator copy to memory).
function proofLengthRootStorage(
    bytes32[] storage accumulator,
    uint256 mmrSize,
    uint256 proofLength
) view returns (bytes32) {
    uint256 lc = leafCount(mmrSize);
    uint256 ipeak = peakIndex(lc, proofLength);

    if (ipeak >= accumulator.length) return bytes32(0);

    return accumulator[ipeak];
}

/// @notice Computes the MMR root implied by the inclusion proof for a node.
/// @dev Traverses the proof path from the node at index `i` up to the root,
///    hashing with each sibling along the way. Proof is calldata to avoid
///    copy when called from consistency chain or verifyInclusion.
/// @param i The zero-based MMR index where `nodeHash` is located.
/// @param nodeHash The hash of the node whose inclusion is being proven.
/// @param proof The sibling hashes required to produce the root from nodeHash.
/// @return root The root hash produced by applying the proof to nodeHash.
///    If proof is empty, returns nodeHash unchanged.
function includedRoot(uint256 i, bytes32 nodeHash, bytes32[] calldata proof)
    pure
    returns (bytes32 root)
{
    root = nodeHash;
    uint256 g = indexHeight(i);
    for (uint256 j = 0; j < proof.length; j++) {
        bytes32 sibling = proof[j];
        if (indexHeight(i + 1) > g) {
            i = i + 1;
            // forge-lint: disable-next-line(unsafe-typecast)
            root = hashPosPair64(uint64(i + 1), sibling, root);
        } else {
            // forge-lint: disable-next-line(incorrect-shift)
            i = i + (2 << g);
            // forge-lint: disable-next-line(unsafe-typecast)
            root = hashPosPair64(uint64(i + 1), root, sibling);
        }
        g = g + 1;
    }
}
