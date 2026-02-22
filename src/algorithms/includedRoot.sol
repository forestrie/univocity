// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Computes the implied MMR root from a node hash and inclusion proof.
// Implements the included_root algorithm from
// draft-bryce-cose-receipts-mmr-profile.
// For a valid COSE receipt of inclusion, the returned root can be used as the
// detached payload to verify the receipt's signature.
// VerifyInclusion follows go-merklelog/mmr/verify.go: proven root must equal
// the single peak that commits the leaf (determined by proof length).

import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @notice Returns the MMR peak index reached after applying pathLength steps
///    from leafIndex (same traversal as includedRoot, no hashing). Used to
///    select the single accumulator entry to check. Aligns with
///    go-merklelog/mmr PeakIndex(LeafCount(size), len(proof)).
/// @param leafIndex Zero-based MMR index of the node.
/// @param pathLength Number of proof elements (sibling steps to peak).
/// @return peakIndex The peak MMR index that contains the leaf.
function peakIndexForInclusionProof(uint256 leafIndex, uint256 pathLength)
    pure
    returns (uint256 peakIndex)
{
    uint256 i = leafIndex;
    uint256 g = LibBinUtils.indexHeight(leafIndex);

    for (uint256 j = 0; j < pathLength; j++) {
        if (LibBinUtils.indexHeight(i + 1) > g) {
            i = i + 1;
        } else {
            // forge-lint: disable-next-line(incorrect-shift)
            i = i + (2 << g);
        }
        g = g + 1;
    }
    return i;
}

/// @notice Verify that a node is included in the MMR committed to by
///    accumulator. The peak that commits the leaf is determined by proof
///    length; only that accumulator entry is checked (no scan).
/// @param leafIndex Zero-based MMR index of the node.
/// @param nodeHash Hash of the node whose inclusion is proven.
/// @param proof Sibling hashes on the path to the peak.
/// @param accumulator Peak hashes for MMR(mmrSize-1), same order as peaks().
/// @param mmrSize Number of nodes in the MMR (last index + 1).
/// @return True if includedRoot matches the committing peak.
function verifyInclusion(
    uint256 leafIndex,
    bytes32 nodeHash,
    bytes32[] memory proof,
    bytes32[] memory accumulator,
    uint256 mmrSize
) pure returns (bool) {
    if (mmrSize == 0) return false;

    uint256[] memory peakIndices = peaks(mmrSize - 1);
    if (peakIndices.length != accumulator.length) return false;

    uint256 peakIdx = peakIndexForInclusionProof(leafIndex, proof.length);
    bytes32 computedRoot = includedRoot(leafIndex, nodeHash, proof);

    for (uint256 k = 0; k < peakIndices.length; k++) {
        if (peakIndices[k] == peakIdx) {
            return computedRoot == accumulator[k];
        }
    }
    return false;
}

/// @notice Computes the MMR root implied by the inclusion proof for a node.
/// @dev Traverses the proof path from the node at index `i` up to the root,
///    hashing with each sibling along the way. The proof path direction
///    is determined by comparing heights: if the node at i+1 has greater
///    height than current height g, then i is a right child.
/// @param i The zero-based MMR index where `nodeHash` is located.
/// @param nodeHash The hash of the node whose inclusion is being proven.
/// @param proof The sibling hashes required to produce the root from nodeHash.
/// @return root The root hash produced by applying the proof to nodeHash.
///    If proof is empty, returns nodeHash unchanged.
function includedRoot(uint256 i, bytes32 nodeHash, bytes32[] memory proof)
    pure
    returns (bytes32 root)
{
    // Set root to the value whose inclusion is to be proven
    root = nodeHash;

    // Set g to the zero-based height of index i
    uint256 g = LibBinUtils.indexHeight(i);

    // For each sibling in the proof
    for (uint256 j = 0; j < proof.length; j++) {
        bytes32 sibling = proof[j];

        // If the height of the entry immediately after i is greater than g,
        // then i is a right child
        if (LibBinUtils.indexHeight(i + 1) > g) {
            // Advance i to the parent.
            // As i is a right child, the parent is at i+1
            i = i + 1;
            // Set root to H(i+1 || sibling || root)
            // Note: i+1 is the 1-based position used in the hash
            // forge-lint: disable-next-line(unsafe-typecast)
            root = LibBinUtils.hashPosPair64(uint64(i + 1), sibling, root);
        } else {
            // Advance i to the parent.
            // As i is a left child, the parent is at i + 2^(g+1)
            // forge-lint: disable-next-line(incorrect-shift)
            i = i + (2 << g);
            // Set root to H(i+1 || root || sibling)
            // forge-lint: disable-next-line(unsafe-typecast)
            root = LibBinUtils.hashPosPair64(uint64(i + 1), root, sibling);
        }

        // Set g to the height index above the current
        g = g + 1;
    }

    // Return the hash produced.
    // If proof length was zero, the original nodeHash is returned
}
