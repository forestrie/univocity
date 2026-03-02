// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    consistentRootsMemory
} from "@univocity/algorithms/consistentRoots.sol";

/// @notice Run the consistency proof chain from initial accumulator (memory).
///    Caller supplies pre-decoded proof payloads (calldata). Caller must copy
///    storage accumulator to memory before calling.
/// @param initialAccumulator Peaks of the log state (tree-size before first
///    proof). Must be memory (copy from storage in caller if needed).
/// @param decodedProofs Pre-decoded consistency proof payloads (order
///    preserved). Passed as calldata; no copy of proof material.
/// @return finalAccumulator Peaks after applying all proofs (memory). The
///    proven tree size is the last proof's treeSize2; caller should use that
///    for grant bounds and state update.
function verifyConsistencyProofChain(
    bytes32[] memory initialAccumulator,
    IUnivocity.ConsistencyProof[] calldata decodedProofs
) pure returns (bytes32[] memory finalAccumulator) {
    uint256 n = decodedProofs.length;
    if (n == 0) {
        return new bytes32[](0);
    }

    bytes32[] memory accMem;
    bytes32[] memory accumulatorFrom;

    for (uint256 idx = 0; idx < n; idx++) {
        IUnivocity.ConsistencyProof calldata p = decodedProofs[idx];

        if (idx == 0) {
            accumulatorFrom = initialAccumulator;
        } else {
            accumulatorFrom = accMem;
        }

        if (p.treeSize1 == 0) {
            accMem = _copyPeaks(p.rightPeaks);
        } else {
            uint256 ifrom = uint256(p.treeSize1) - 1;
            bytes32[] memory roots =
                consistentRootsMemory(ifrom, accumulatorFrom, p.paths);
            accMem = _concatAccumulator(roots, p.rightPeaks);
        }
    }

    return accMem;
}

/// @notice Build the detached payload (commitment) for consistency receipt
///    signature verification. Draft: "use the consistent accumulator as
///    the detached payload".
/// @param accumulator Peak hashes (MMR accumulator).
/// @return commitment 32-byte SHA-256 commitment.
function buildDetachedPayloadCommitment(bytes32[] memory accumulator)
    pure
    returns (bytes memory commitment)
{
    commitment = abi.encodePacked(sha256(abi.encodePacked(accumulator)));
}

/// @notice MMR profile: verify a series of pre-decoded consistency proofs per
///    draft "Verifying the Receipt of consistency". No CBOR decode on-chain.
///    Aligns with algorithms as free functions (consistentRoots, includedRoot).

/// @notice Copy rightPeaks from calldata to memory (only when treeSize1==0;
///    we need a mutable accumulator for the chain).
function _copyPeaks(bytes32[] calldata peaksIn)
    pure
    returns (bytes32[] memory out)
{
    out = new bytes32[](peaksIn.length);
    for (uint256 i = 0; i < peaksIn.length; i++) {
        out[i] = peaksIn[i];
    }
}

/// @notice Concat roots then rightPeaks into one accumulator.
function _concatAccumulator(
    bytes32[] memory roots,
    bytes32[] calldata rightPeaks
) pure returns (bytes32[] memory out) {
    out = new bytes32[](roots.length + rightPeaks.length);
    for (uint256 i = 0; i < roots.length; i++) {
        out[i] = roots[i];
    }
    for (uint256 j = 0; j < rightPeaks.length; j++) {
        out[roots.length + j] = rightPeaks[j];
    }
}

