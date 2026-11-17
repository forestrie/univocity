// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// TEST-ONLY ORACLE. includedRoot and committingPathLength as they were
// written before the contract read each step's direction from a leaf index:
// every step finds the next node's height with indexHeight, itself a loop,
// so the work is quadratic in the path length. Each follows the draft's
// included_root (draft-bryce-cose-receipts-mmr-profile) step for step, and
// the linear forms in src/algorithms/includedRoot.sol must agree with them
// for every input (leafWalk.t.sol). Fixture builders that must not depend on
// the code under test use them too (ConsistencyShape.t.sol).

import {hashPosPair64, indexHeight} from "@univocity/algorithms/binUtils.sol";

/// @notice The root a path implies from node `i`, deciding at every step
///    whether the node is a right child (its parent is the next index) or a
///    left child (its parent is 2^(g+1) further on) from the next index's
///    height.
/// @param i Zero-based MMR index of the node the path starts from.
/// @param nodeHash Hash of that node.
/// @param proof Sibling hashes from the node up.
/// @return root The root the path implies; nodeHash for an empty path.
function includedRootReference(
    uint256 i,
    bytes32 nodeHash,
    bytes32[] calldata proof
) pure returns (bytes32 root) {
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

/// @notice Length of the path from node `index` to the peak that commits it
///    in the complete MMR(mmrSize): walks parents, finding each one from
///    the next index's height, until the next one lies beyond the MMR.
/// @param index Zero-based MMR index of the node; index < mmrSize.
/// @param mmrSize Number of nodes in the complete MMR.
/// @return length Number of siblings from `index` to its committing peak.
function committingPathLengthReference(uint256 index, uint256 mmrSize)
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
