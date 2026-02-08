// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibBinUtils} from "./LibBinUtils.sol";

/// @title LibIncludedRoot
/// @notice Computes the implied MMR root from a node hash and inclusion proof.
/// @dev Implements the included_root algorithm from draft-bryce-cose-receipts-mmr-profile.
///      For a valid COSE receipt of inclusion, the returned root can be used as the
///      detached payload to verify the receipt's signature.
library LibIncludedRoot {
    /// @notice Computes the MMR root implied by the inclusion proof for a node.
    /// @dev Traverses the proof path from the node at index `i` up to the root,
    ///      hashing with each sibling along the way. The proof path direction
    ///      is determined by comparing heights: if the node at i+1 has greater
    ///      height than current height g, then i is a right child.
    /// @param i The zero-based MMR index where `nodeHash` is located.
    /// @param nodeHash The hash of the node whose inclusion is being proven.
    /// @param proof The sibling hashes required to produce the root from nodeHash.
    /// @return root The root hash produced by applying the proof to nodeHash.
    ///         If proof is empty, returns nodeHash unchanged.
    function includedRoot(uint256 i, bytes32 nodeHash, bytes32[] calldata proof) internal pure returns (bytes32 root) {
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
                // Advance i to the parent. As i is a right child, the parent is at i+1
                i = i + 1;
                // Set root to H(i+1 || sibling || root)
                // Note: i+1 is the 1-based position used in the hash
                root = LibBinUtils.hashPosPair64(uint64(i + 1), sibling, root);
            } else {
                // Advance i to the parent. As i is a left child, the parent is at i + 2^(g+1)
                i = i + (2 << g);
                // Set root to H(i+1 || root || sibling)
                root = LibBinUtils.hashPosPair64(uint64(i + 1), root, sibling);
            }

            // Set g to the height index above the current
            g = g + 1;
        }

        // Return the hash produced. If proof length was zero, the original nodeHash is returned
    }
}
