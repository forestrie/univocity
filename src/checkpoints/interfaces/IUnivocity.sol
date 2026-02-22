// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocityEvents} from "./IUnivocityEvents.sol";

/// @title IUnivocity
/// @notice Interface for univocity transparency log contract with R5
///    authorization
interface IUnivocity is IUnivocityEvents {
    struct LogState {
        bytes32[] accumulator;
        uint64 size;
        uint64 checkpointCount;
        uint256 initializedAt;
    }

    // === View Functions ===

    function bootstrapAuthority() external view returns (address);
    function authorityLogId() external view returns (bytes32);
    function getLogState(bytes32 logId) external view returns (LogState memory);
    function isLogInitialized(bytes32 logId) external view returns (bool);

    // === State-Changing Functions ===

    /// @notice Publish a checkpoint for a log
    /// @param logId The log to checkpoint
    /// @param size The MMR size (leaf count) at this checkpoint (uint64 per
    ///    SCITT profile)
    /// @param accumulator The MMR peak list
    /// @param receipt COSE_Sign1 payment receipt (SCITT format)
    /// @param consistencyProof One inclusion proof per old peak (calldata);
    ///    empty for first
    ///    checkpoint
    /// @param receiptMmrIndex Zero-based MMR index of the receipt leaf (leaf
    ///    position - 1); ignored if receipt is empty.
    /// @param receiptInclusionProof MMR path (sibling hashes) for receipt
    ///    inclusion. May be empty only when bootstrapping the authority log.
    /// @param receiptIdtimestampBe Receipt's idtimestamp (Snowflake64) in
    ///    8-byte big-endian;
    ///    required when receipt non-empty.
    ///    Leaf = H(receiptIdtimestampBe ‖ sha256(receipt)) per
    ///    ADR-0030.
    function publishCheckpoint(
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt,
        bytes32[][] calldata consistencyProof,
        uint64 receiptMmrIndex,
        bytes32[] calldata receiptInclusionProof,
        bytes8 receiptIdtimestampBe
    ) external;
}
