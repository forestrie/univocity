// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// TEST-ONLY ORACLE. The draft's consistent_roots exactly as written
// (draft-bryce-cose-receipts-mmr-profile): fold each origin peak along
// whatever path it is given and collapse consecutive duplicate roots. It
// performs no shape checks, which is why the contract no longer uses it
// (see consistentRootsForSizes, pinned to the same KAT-39 vectors in
// consistentRoots.t.sol). Fixture builders use this to compute the
// commitment a receipt signs.

import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @notice Draft consistent_roots over a storage accumulator.
/// @param ifrom The MMR index of the origin state (must be a complete MMR).
/// @param accumulatorFrom The peak hashes of MMR(ifrom), descending height.
/// @param proofs Inclusion proofs for each peak, one per accumulator entry.
/// @return roots The unique roots proven, in descending height order.
function consistentRoots(
    uint256 ifrom,
    bytes32[] storage accumulatorFrom,
    bytes32[][] calldata proofs
) view returns (bytes32[] memory roots) {
    uint256[] memory fromPeaks = peaks(ifrom);

    require(fromPeaks.length == accumulatorFrom.length, "Peak count mismatch");
    require(fromPeaks.length == proofs.length, "Proof count mismatch");

    roots = new bytes32[](fromPeaks.length);
    uint256 rootCount = 0;

    for (uint256 i = 0; i < fromPeaks.length; i++) {
        bytes32 root =
            includedRoot(fromPeaks[i], accumulatorFrom[i], proofs[i]);

        if (rootCount > 0 && roots[rootCount - 1] == root) {
            continue;
        }

        roots[rootCount] = root;
        rootCount++;
    }

    assembly {
        mstore(roots, rootCount)
    }
}
