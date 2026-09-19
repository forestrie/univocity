// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Computes the implied accumulator roots from consistency proofs.
// Implements the consistent_roots algorithm from
// draft-bryce-cose-receipts-mmr-profile.
// For a valid COSE receipt of consistency,
// the returned roots can be used as the
// detached payload to verify the receipt's signature.

import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {
    mmrSizeForLeafCount,
    peaks,
    peaksBitmap
} from "@univocity/algorithms/peaks.sol";
import {bitLength, popcount64} from "@univocity/algorithms/binUtils.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

/// @notice Check a consistency proof's shape against the draft's
///    `consistency_proof_paths(ifrom, ito)`: both sizes must be complete
///    MMRs, there must be one path per peak of MMR(sizeFrom), and each path
///    must have exactly the length the two sizes imply. Position arithmetic
///    only; no hashing. Without this a prover chooses the path lengths, and
///    so the heights at which the origin peaks are re-homed.
///
///    For a complete MMR the set bits of peaksBitmap(size) are the peak
///    heights, high to low, which is accumulator order. So the shape is a
///    comparison of two integers: let `split` be the highest bit on which
///    the two bitmaps differ. As sizeTo > sizeFrom, the target has that bit
///    and the origin does not. Origin peaks above `split` are still peaks
///    of the target (path length 0, each carried); every origin peak below
///    `split` is committed by the single target peak of height `split`
///    (path length split - h, one carried root between them); the target's
///    remaining peaks arrive as rightPeaks. Equivalent to walking the
///    draft's inclusion_proof_path from each origin peak (the test tree
///    keeps that walk as an oracle) without any per-hop work.
/// @param sizeFrom Node count of the origin state (0 for an empty log).
/// @param sizeTo Node count of the target state; must exceed sizeFrom.
/// @param proofs One path per origin peak, in accumulator order.
/// @return carried Number of MMR(sizeTo) peaks that commit at least one
///    origin peak; the proven roots must number exactly this many.
/// @return expectedRight Number of MMR(sizeTo) peaks committing no origin
///    peak; rightPeaks must supply exactly these.
function checkConsistencyProofShape(
    uint64 sizeFrom,
    uint64 sizeTo,
    bytes32[][] calldata proofs
) pure returns (uint256 carried, uint256 expectedRight) {
    // peaksBitmap rounds an incomplete size down to the largest MMR below
    // it, so the bitmaps only describe these trees if the sizes are
    // complete. Without this a target such as 6 anchors an accumulator that
    // is no MMR's, and an offline verifier reads its entries at the wrong
    // heights. The base is anchored state and is complete whenever it was
    // written by this check; the test names state anchored before it.
    uint256 from = peaksBitmap(sizeFrom);
    if (mmrSizeForLeafCount(from) != sizeFrom) {
        revert IUnivocityErrors.IncompleteTreeSize(sizeFrom);
    }
    uint256 to = peaksBitmap(sizeTo);
    if (mmrSizeForLeafCount(to) != sizeTo) {
        revert IUnivocityErrors.IncompleteTreeSize(sizeTo);
    }
    uint256 fromCount = popcount64(from);
    if (proofs.length != fromCount) {
        revert IUnivocityErrors.ConsistencyPeakCountMismatch(
            fromCount, proofs.length
        );
    }
    if (fromCount == 0) {
        return (0, popcount64(to));
    }

    uint256 split = bitLength(from ^ to) - 1;
    uint256 i = 0;
    for (uint256 h = bitLength(from); h > 0;) {
        h--;
        if ((from >> h) & 1 == 0) continue;
        uint256 expected = h > split ? 0 : split - h;
        if (proofs[i].length != expected) {
            revert IUnivocityErrors.ConsistencyPathLengthMismatch(
                i, expected, proofs[i].length
            );
        }
        i++;
    }

    uint256 below = from & ((uint256(1) << split) - 1);
    carried = popcount64(from >> (split + 1)) + (below != 0 ? 1 : 0);
    expectedRight = popcount64(to) - carried;
}

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
///    in descending height order (storage). Read in place; not copied.
/// @param proofs Inclusion proofs for each peak, one per accumulator entry
///    (calldata; no copy).
/// @return roots The unique roots proven, in descending height order.
///
/// @custom:throws If accumulatorFrom.length != peaks(ifrom).length
/// @custom:throws If proofs.length != accumulatorFrom.length
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

/// @notice consistentRootsMemory keyed by tree size rather than last index.
///    MMR(0) has no peaks, so a zero-size origin is consistent only with an
///    empty accumulator and no proofs; the same count checks apply as for any
///    other size. Lets a chain fold from an empty log without a special case.
/// @param sizeFrom Node count of the origin state (0 for an empty log).
function consistentRootsFromSize(
    uint256 sizeFrom,
    bytes32[] memory accumulatorFrom,
    bytes32[][] calldata proofs
) pure returns (bytes32[] memory roots) {
    if (sizeFrom == 0) {
        require(accumulatorFrom.length == 0, "Peak count mismatch");
        require(proofs.length == 0, "Proof count mismatch");
        return new bytes32[](0);
    }
    return consistentRootsMemory(sizeFrom - 1, accumulatorFrom, proofs);
}

/// @notice Same as consistentRoots with memory accumulator (for chained
///    verification per draft "Verifying the Receipt of consistency").
///    proofs is calldata to avoid copy when called from consistencyReceipt.
function consistentRootsMemory(
    uint256 ifrom,
    bytes32[] memory accumulatorFrom,
    bytes32[][] calldata proofs
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
