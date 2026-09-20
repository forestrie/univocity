// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// TEST-ONLY ORACLE. Position-only form of inclusion_proof_path from
// draft-bryce-cose-receipts-mmr-profile, walked hop by hop exactly as the
// draft writes it. The contract does not use this: consistentRootsForSizes
// derives the same path lengths from the peaks bitmaps without walking. The
// walk is kept so fuzz tests can show the bitmap arithmetic agrees with the
// draft's definition on random size pairs (ConsistencyShape.t.sol) and so
// checkpoint tests can state expected lengths without hardcoding them.

import {indexHeight} from "@univocity/algorithms/binUtils.sol";

/// @notice Length of the inclusion proof path for node `i` in MMR(c + 1), and
///    the index of the peak that commits `i` there. Mirrors the draft's
///    `inclusion_proof_path(i, c)` walk without materialising the siblings.
/// @dev MMR(c + 1) must be complete (indexHeight(c + 1) == 0); callers check.
///    In a complete MMR a right child's parent is always present, so the walk
///    ends only when a left child's sibling would lie beyond `c`.
/// @param i Zero-based index of the node whose path length is wanted; i <= c.
/// @param c Index of the last node of the MMR containing `i`.
/// @return length Number of siblings on the path from `i` to its peak.
/// @return peak Index of the peak of MMR(c + 1) that commits `i`.
function inclusionProofPathLength(uint256 i, uint256 c)
    pure
    returns (uint256 length, uint256 peak)
{
    uint256 g = indexHeight(i);
    while (true) {
        // The sibling of i is at i +/- 2^(g+1)
        uint256 siblingOffset = 2 << g;
        uint256 isibling;
        peak = i;
        if (indexHeight(i + 1) > g) {
            // i is a right sibling; its parent is stored immediately after
            isibling = i - siblingOffset + 1;
            i += 1;
        } else {
            // i is a left sibling; the parent follows the right sibling
            isibling = i + siblingOffset - 1;
            i += siblingOffset;
        }
        // A sibling beyond the range of MMR(c + 1) means i was the peak
        if (isibling > c) {
            return (length, peak);
        }
        length++;
        g++;
    }
}
