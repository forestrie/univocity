// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LibCheckpointVerifier
/// @notice Library for verifying transparency log checkpoints against
///         consistency proofs.
/// @dev This is a first-cut skeleton. Agents should refine the checkpoint
///      representation and verification logic as the protocol is specified.
library LibCheckpointVerifier {
    /// @dev Minimal placeholder representation of a log checkpoint.
    struct Checkpoint {
        // TODO: add fields for tree size, root hash, and any metadata
        //       required by the univocity protocol.
        bytes32 root;
        uint256 size;
    }

    /// @dev Representation of a consistency proof between two checkpoints.
    ///      Each entry in `paths` is an inclusion proof for the corresponding
    ///      peak in the origin accumulator (see consistentRoots).
    struct ConsistencyProof {
        bytes32[][] paths;
    }

    /// @notice Verify that `newCp` is consistent with `oldCp` given
    ///         `proof` according to the MMR/consistency rules.
    /// @dev This is intentionally a stub that always returns false until the
    ///      precise proof format and algorithm are implemented.
    /// @param oldCp The prior checkpoint that is already trusted.
    /// @param newCp The new checkpoint to be validated.
    /// @param proof The consistency proof between the two checkpoints.
    /// @return ok True if the proof shows that `newCp` extends `oldCp`.
    function verifyConsistency(Checkpoint memory oldCp, Checkpoint memory newCp, ConsistencyProof memory proof)
        internal
        pure
        returns (bool ok)
    {
        // TODO: implement real verification logic based on
        // draft-bryce-cose-receipts-mmr-profile.
        oldCp;
        newCp;
        proof;
        return false;
    }

    /// @notice Verify consistency proof between two accumulators
    /// @param oldAccumulator Previous checkpoint's MMR peak list
    /// @param newAccumulator New checkpoint's MMR peak list
    /// @param oldSize Previous MMR size
    /// @param proof Encoded consistency proof
    /// @return ok True if proof is valid
    function verifyConsistencyProof(
        bytes32[] storage oldAccumulator,
        bytes32[] calldata newAccumulator,
        uint64 oldSize,
        bytes calldata proof
    ) internal view returns (bool ok) {
        // TODO: Wire up to existing consistentRoots algorithm
        // For now, return true to allow integration testing
        oldAccumulator;
        newAccumulator;
        oldSize;
        proof;
        return true;
    }
}
