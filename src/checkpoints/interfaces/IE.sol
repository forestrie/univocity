// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICheckpointEvents
/// @notice Events related to transparency log checkpoints in univocity.
interface ICheckpointEvents {
    /// @notice Emitted when a new checkpoint is published.
    event CheckpointPublished(
        bytes32 indexed logId,
        address indexed sender,
        address indexed payer,
        bytes32[] accumulator,
        uint256 size
    );
}
