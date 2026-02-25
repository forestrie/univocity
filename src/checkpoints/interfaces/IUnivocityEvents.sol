// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityEvents
/// @notice Events for univocity transparency log checkpoints and R5
///    authorization
interface IUnivocityEvents {
    /// @notice Contract initialized
    event Initialized(
        address indexed bootstrapAuthority, bytes32 indexed authorityLogId
    );

    /// @notice New log registered (first checkpoint)
    event LogRegistered(
        bytes32 indexed logId, address indexed registeredBy, uint64 initialSize
    );

    /// @notice Checkpoint published (all logs including authority)
    /// @dev Block number recoverable from tx receipt. size = MMR size after
    ///    checkpoint (last mmrIndex + 1). Both sender and payer are attributed
    ///    and indexed (filterable). sender = submitter; payer = from
    ///    PaymentGrant (who paid). paymentIndex and paymentPath are the
    ///    inclusion proof payload (empty when no payment receipt).
    event CheckpointPublished(
        bytes32 indexed logId,
        address indexed sender,
        address indexed payer,
        uint64 size,
        uint64 checkpointCount,
        bytes32[] accumulator,
        uint64 paymentIndex,
        bytes32[] paymentPath
    );

    /// @notice R5 authorization verified (not emitted for bootstrap)
    event CheckpointAuthorized(
        bytes32 indexed logId,
        address indexed payer,
        uint64 checkpointStart,
        uint64 checkpointEnd,
        uint64 maxHeight
    );

    /// @notice Payment receipt added to authority log
    event PaymentReceiptRegistered(
        bytes32 indexed logId,
        address indexed payer,
        uint64 checkpointStart,
        uint64 checkpointEnd,
        uint64 maxHeight,
        uint64 minGrowth
    );

    /// @notice Authorization failed (emitted before revert for debugging)
    event AuthorizationFailed(
        bytes32 indexed logId, address indexed payer, string reason
    );
}
