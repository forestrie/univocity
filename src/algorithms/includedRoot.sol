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

    uint256 lc = leafCount(mmrSize);
    uint256 ipeak = peakIndex(lc, proof.length);
    if (ipeak >= accumulator.length) return false;

    bytes32 computedRoot = includedRoot(leafIndex, nodeHash, proof);
    return computedRoot == accumulator[ipeak];
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
    uint256 g = LibBinUtils.indexHeight(i);
    for (uint256 j = 0; j < proof.length; j++) {
        bytes32 sibling = proof[j];
        if (LibBinUtils.indexHeight(i + 1) > g) {
            i = i + 1;
            // forge-lint: disable-next-line(unsafe-typecast)
            root = LibBinUtils.hashPosPair64(uint64(i + 1), sibling, root);
        } else {
            // forge-lint: disable-next-line(incorrect-shift)
            i = i + (2 << g);
            // forge-lint: disable-next-line(unsafe-typecast)
            root = LibBinUtils.hashPosPair64(uint64(i + 1), root, sibling);
        }
        g = g + 1;
    }
}
