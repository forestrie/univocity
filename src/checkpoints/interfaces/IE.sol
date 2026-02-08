// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICheckpointEvents
/// @notice Events related to transparency log checkpoints in univocity.
interface ICheckpointEvents {
    /// @notice Emitted when a new checkpoint is published.
    /// @param root Root hash of the transparency log at this checkpoint.
    /// @param size Number of leaves (or log size) at this checkpoint.
    /// @param receipt Raw COSE receipt attesting to this checkpoint.
    event CheckpointPublished(bytes32 indexed root, uint256 size, bytes receipt);
}
