// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICheckpointEvents} from "@univocity/checkpoints/interfaces/IE.sol";
import {LibCoseReceipt} from "@univocity/cose/lib/LibCoseReceipt.sol";
import {LibCheckpointVerifier} from "@univocity/checkpoints/lib/LibCheckpointVerifier.sol";

/// @title Univocity
/// @notice Primary contract that ties together COSE receipt decoding and
///         checkpoint verification for the forestrie transparency logs.
/// @dev This is an initial skeleton intended to stabilise types and data
///      flow. It does not yet enforce cryptographic verification.
contract Univocity is ICheckpointEvents {
    using LibCheckpointVerifier for LibCheckpointVerifier.Checkpoint;

    /// @notice The latest checkpoint that has been published via this
    ///         contract.
    LibCheckpointVerifier.Checkpoint public latestCheckpoint;

    /// @notice Publish an initial checkpoint without a consistency proof.
    /// @dev This is intended for bootstrapping only. Can only be called once
    ///      (before any checkpoint has been set). Once
    ///      LibCheckpointVerifier.verifyConsistency is implemented, agents
    ///      should consider adding access control and stronger invariants.
    /// @param root Root hash of the initial checkpoint.
    /// @param size Log size of the initial checkpoint.
    function publishInitialCheckpoint(bytes32 root, uint256 size) external {
        require(latestCheckpoint.size == 0, "Already initialized");

        latestCheckpoint = LibCheckpointVerifier.Checkpoint({root: root, size: size});

        emit CheckpointPublished(root, size, "");
    }

    /// @notice Publish a new checkpoint backed by a COSE receipt and (future)
    ///         consistency proof.
    /// @dev As LibCheckpointVerifier.verifyConsistency is currently a stub,
    ///      this function does not yet enforce consistency. It wires together
    ///      the data flow and emits a checkpoint event so that tests and
    ///      further development can build on a stable interface.
    /// @param newRoot Root hash of the new checkpoint.
    /// @param newSize Log size of the new checkpoint.
    /// @param proofPaths Inclusion proof paths, one per peak in the current
    ///        accumulator (see consistentRoots).
    /// @param receipt Raw COSE receipt bytes.
    function publishCheckpoint(
        bytes32 newRoot,
        uint256 newSize,
        bytes32[][] calldata proofPaths,
        bytes calldata receipt
    ) external {
        require(newSize > latestCheckpoint.size, "New size must exceed current");

        // Decode the receipt to exercise LibCoseReceipt and surface type
        // expectations (no-op until COSE parsing is implemented).
        LibCoseReceipt.CoseReceipt memory decoded = LibCoseReceipt.decode(receipt);
        decoded;

        LibCheckpointVerifier.Checkpoint memory next = LibCheckpointVerifier.Checkpoint({root: newRoot, size: newSize});

        LibCheckpointVerifier.ConsistencyProof memory proof =
            LibCheckpointVerifier.ConsistencyProof({paths: proofPaths});

        // TODO: once implemented, enforce verifyConsistency(latestCheckpoint,
        //       next, proof) before updating state.
        bool ok = LibCheckpointVerifier.verifyConsistency(latestCheckpoint, next, proof);
        ok;

        latestCheckpoint = next;

        emit CheckpointPublished(newRoot, newSize, receipt);
    }
}
