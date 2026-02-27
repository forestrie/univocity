// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityEvents
/// @notice Events for univocity transparency log checkpoints and
///    payment-grant authorization.
interface IUnivocityEvents {
    /// @notice Contract initialized
    event Initialized(
        address indexed bootstrapAuthority, bytes32 indexed rootLogId
    );

    /// @notice New log registered (first checkpoint)
    event LogRegistered(
        bytes32 indexed logId, address indexed registeredBy, uint64 initialSize
    );

    /// @notice Checkpoint published (all logs including root/auth logs).
    /// @dev Block number recoverable from tx receipt. size = MMR size after
    ///    checkpoint. logKind = config.kind (Authority or Data). Both sender
    ///    and payer are attributed and indexed. paymentIndex and paymentPath
    ///    are the inclusion proof payload (empty when no payment proof).
    event CheckpointPublished(
        bytes32 indexed logId,
        address indexed sender,
        address indexed payer,
        uint8 logKind,
        uint64 size,
        bytes32[] accumulator,
        uint64 paymentIndex,
        bytes32[] paymentPath
    );
}
