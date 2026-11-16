// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// TEST-ONLY. Builds a small MMR in memory so tests can state accumulators
// and inclusion paths at any complete size without fixtures. Node hashing
// and positions follow draft-bryce-cose-receipts-mmr-profile, as the
// contract's includedRoot does.

import {hashPosPair64, indexHeight} from "@univocity/algorithms/binUtils.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @notice An MMR held as its node array, in MMR index order.
struct Mmr {
    bytes32[] nodes;
    uint256 size;
}

library MmrBuilder {
    /// @notice An empty MMR with room for `capacity` nodes.
    function create(uint256 capacity) internal pure returns (Mmr memory m) {
        m.nodes = new bytes32[](capacity);
    }

    /// @notice Appends a leaf, then every parent it completes.
    /// @return index MMR index of the appended leaf.
    function append(Mmr memory m, bytes32 leaf)
        internal
        pure
        returns (uint256 index)
    {
        index = m.size;
        m.nodes[m.size++] = leaf;
        uint256 h = 0;
        // The next index is a parent while its height exceeds the last
        // node's; the parent's left child sits 2^(h+1) - 1 back.
        while (indexHeight(m.size) > h) {
            uint256 parent = m.size;
            bytes32 left = m.nodes[parent - (2 << h)];
            bytes32 right = m.nodes[parent - 1];
            // forge-lint: disable-next-line(unsafe-typecast)
            m.nodes[m.size++] = hashPosPair64(uint64(parent + 1), left, right);
            h++;
        }
    }

    /// @notice Accumulator (peaks, highest first) of the MMR at `size`.
    function accumulatorAt(Mmr memory m, uint256 size)
        internal
        pure
        returns (bytes32[] memory acc)
    {
        uint256[] memory ix = peaks(size - 1);
        acc = new bytes32[](ix.length);
        for (uint256 i = 0; i < ix.length; i++) {
            acc[i] = m.nodes[ix[i]];
        }
    }

    /// @notice Inclusion path for node `index` in the MMR at `size`.
    function pathAt(Mmr memory m, uint256 index, uint256 size)
        internal
        pure
        returns (bytes32[] memory path)
    {
        bytes32[] memory tmp = new bytes32[](64);
        uint256 n = 0;
        uint256 g = indexHeight(index);
        while (true) {
            uint256 sibling;
            uint256 parent;
            if (indexHeight(index + 1) > g) {
                sibling = index + 1 - (2 << g);
                parent = index + 1;
            } else {
                sibling = index + (2 << g) - 1;
                parent = index + (2 << g);
            }
            if (sibling >= size) break;
            tmp[n++] = m.nodes[sibling];
            index = parent;
            g++;
        }
        path = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            path[i] = tmp[i];
        }
    }
}
