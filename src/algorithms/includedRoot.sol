// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Computes the implied MMR root from a node hash and inclusion proof.
// Implements the included_root algorithm from
// draft-bryce-cose-receipts-mmr-profile.
// For a valid COSE receipt of inclusion, the returned root can be used as the
// detached payload to verify the receipt's signature.
// VerifyInclusion follows go-merklelog/mmr/verify.go: proven root must equal
// the single peak that commits the leaf (determined by proof length).

import {
    bitLength,
    indexHeight,
    hashPosPair64
} from "@univocity/algorithms/binUtils.sol";
import {
    completeLeafCount,
    leafCount,
    peakIndex
} from "@univocity/algorithms/peaks.sol";

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

/// @notice Length of the path from node `index` to the peak that commits it
///    in MMR(mmrSize). Walks parents until the next one lies beyond the MMR.
/// @dev mmrSize must be complete, as an anchored size always is: in a
///    complete MMR a node's sibling is present exactly when its parent is.
/// @param index Zero-based MMR index of the node; index < mmrSize.
/// @param mmrSize Number of nodes in the MMR.
/// @return length Number of siblings from `index` to its committing peak.
function committingPathLength(uint256 index, uint256 mmrSize)
    pure
    returns (uint256 length)
{
    uint256 g = indexHeight(index);
    while (true) {
        // forge-lint: disable-next-line(incorrect-shift)
        uint256 parent =
            indexHeight(index + 1) > g ? index + 1 : index + (2 << g);
        if (parent >= mmrSize) return length;
        index = parent;
        g++;
        length++;
    }
}

/// @notice Verify that a leaf is included in MMR(mmrSize) with a path that
///    may have been built at a later size (the witness-age rule).
/// @dev MMR nodes never change once written, so a path built at any later
///    size starts with the path to the leaf's committing peak at mmrSize.
///    Only that prefix is used; the rest is ignored. A path shorter than
///    the prefix (built at an earlier size whose peak has since merged) is
///    refused. Leaves only: verifyInclusion picks the committing peak by
///    path length, which is right only for height-0 nodes.
/// @param leafIndex Zero-based MMR index of the leaf.
/// @param leafHash Hash of the leaf.
/// @param proof Sibling hashes from the leaf, at mmrSize or any later size.
/// @param accumulator Peak hashes for MMR(mmrSize), as peaks() orders them.
/// @param mmrSize Number of nodes in the anchored MMR.
/// @return True if the trimmed path proves the leaf against its peak.
function verifyInclusionAtSize(
    uint256 leafIndex,
    bytes32 leafHash,
    bytes32[] calldata proof,
    bytes32[] memory accumulator,
    uint256 mmrSize
) pure returns (bool) {
    if (leafIndex >= mmrSize) return false;
    if (indexHeight(leafIndex) != 0) return false;
    uint256 n = committingPathLength(leafIndex, mmrSize);
    if (proof.length < n) return false;
    return
        verifyInclusion(leafIndex, leafHash, proof[:n], accumulator, mmrSize);
}

/// @notice Single-peak variant of verifyInclusionAtSize: the caller supplies
///    the one accumulator peak that commits the leaf at mmrSize, so the
///    whole accumulator is never needed (see LibLogState.committingPeak).
/// @dev Same witness-age rule and path trimming as verifyInclusionAtSize,
///    in work linear in the path length (at most 63 steps): two passes of
///    completeLeafCount, then includedLeafRoot. Leaf e of a log of L leaves
///    has its committing peak at height bitLength(e ^ L) - 1, the highest
///    bit where the two differ, and for a leaf that height is the
///    committing path length. The caller must take `peak` from the
///    anchored state for the same mmrSize.
/// @param leafIndex Zero-based MMR index of the leaf.
/// @param leafHash Hash of the leaf.
/// @param proof Sibling hashes from the leaf, at mmrSize or any later size.
/// @param peak The peak committing the leaf in MMR(mmrSize).
/// @param mmrSize Number of nodes in the anchored MMR; an incomplete size,
///    which no anchored size is, is refused.
/// @return True if the trimmed path proves the leaf against `peak`.
function verifyInclusionAtPeak(
    uint256 leafIndex,
    bytes32 leafHash,
    bytes32[] calldata proof,
    bytes32 peak,
    uint256 mmrSize
) pure returns (bool) {
    if (leafIndex >= mmrSize) return false;
    (uint256 leafNumber, bool isLeaf) = completeLeafCount(leafIndex);
    if (!isLeaf) return false;
    (uint256 leaves, bool complete) = completeLeafCount(mmrSize);
    if (!complete) return false;
    // Both sizes are complete and leafIndex < mmrSize, so leafNumber <
    // leaves and their xor is not zero.
    uint256 n = bitLength(leafNumber ^ leaves) - 1;
    if (proof.length < n) return false;
    if (peak == bytes32(0)) return false;
    return includedLeafRoot(leafIndex, leafNumber, leafHash, proof[:n]) == peak;
}

/// @notice includedRoot for a leaf, reading each step's direction from one
///    bit of the leaf's number instead of from node heights.
/// @dev Bit g of leafNumber is set when the leaf's ancestor at height g is
///    a right child, whose parent is the next index, and clear when it is a
///    left child, whose parent is 2^(g+1) further on. Constant work and one
///    hash per sibling; includedRoot computes a height at every step. Walks
///    the whole path, so the caller trims it.
/// @param i Zero-based MMR index of the leaf.
/// @param leafNumber The leaf's zero-based number among the leaves, as
///    completeLeafCount(i) returns it.
/// @param leafHash Hash of the leaf.
/// @param path Sibling hashes from the leaf up.
/// @return root The root the path implies; leafHash for an empty path.
function includedLeafRoot(
    uint256 i,
    uint256 leafNumber,
    bytes32 leafHash,
    bytes32[] calldata path
) pure returns (bytes32 root) {
    root = leafHash;
    for (uint256 g = 0; g < path.length; g++) {
        if ((leafNumber >> g) & 1 == 1) {
            i = i + 1;
            // forge-lint: disable-next-line(unsafe-typecast)
            root = hashPosPair64(uint64(i + 1), path[g], root);
        } else {
            // forge-lint: disable-next-line(incorrect-shift)
            i = i + (2 << g);
            // forge-lint: disable-next-line(unsafe-typecast)
            root = hashPosPair64(uint64(i + 1), root, path[g]);
        }
    }
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
