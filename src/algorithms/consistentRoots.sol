// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Computes the implied accumulator roots from consistency proofs.
// Implements the consistent_roots algorithm from
// draft-bryce-cose-receipts-mmr-profile.
// For a valid COSE receipt of consistency,
// the returned roots can be used as the
// detached payload to verify the receipt's signature.

import {peaks} from "@univocity/algorithms/peaks.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";

/// @notice Computes the implied roots from consistency proofs for each peak.
/// @dev Applies inclusion proof paths for each origin accumulator peak.
///    The returned list contains elements from the accumulator of a
///    consistent
///    future state, in descending height order. It may be exactly the future
///    accumulator or a prefix of it.
///
///      Consecutive duplicate roots are collapsed (when multiple peaks prove
///    to the same future peak, only one is included in the result).
///
/// @param ifrom The MMR index of the origin state (must be a complete MMR).
/// @param accumulatorFrom The peak hashes of MMR(ifrom),
///    in descending height order (storage).
/// @param proofs Inclusion proofs for each peak, one per accumulator entry.
/// @return roots The unique roots proven, in descending height order.
///
/// @custom:throws If accumulatorFrom.length != peaks(ifrom).length
/// @custom:throws If proofs.length != accumulatorFrom.length
function consistentRoots(
    uint256 ifrom,
    bytes32[] storage accumulatorFrom,
    bytes32[][] memory proofs
) view returns (bytes32[] memory roots) {
    bytes32[] memory accMem = new bytes32[](accumulatorFrom.length);
    for (uint256 i = 0; i < accMem.length; i++) {
        accMem[i] = accumulatorFrom[i];
    }
    return consistentRootsMemory(ifrom, accMem, proofs);
}

/// @notice Same as consistentRoots with memory accumulator (for chained
///    verification per draft "Verifying the Receipt of consistency").
function consistentRootsMemory(
    uint256 ifrom,
    bytes32[] memory accumulatorFrom,
    bytes32[][] memory proofs
) pure returns (bytes32[] memory roots) {
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
