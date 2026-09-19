// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Position-only form of inclusion_proof_path from
// draft-bryce-cose-receipts-mmr-profile. The draft's function returns the
// sibling indices; a verifier only needs how many there are and where the
// walk ends, so this returns the path length and the committing peak. The
// draft asks that "the implementation SHOULD check the lengths of the proof
// paths are appropriate for the provided tree sizes"; this is that check's
// arithmetic.

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
