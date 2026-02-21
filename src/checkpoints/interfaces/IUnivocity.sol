// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IUnivocityEvents.sol";

/// @title IUnivocity
/// @notice Interface for univocity transparency log contract with R5 authorization
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

    function initialize(bytes32 _authorityLogId) external;

    /// @notice Publish a checkpoint for a log
    /// @param logId The log to checkpoint
    /// @param size The MMR size (leaf count) at this checkpoint (uint64 per SCITT profile)
    /// @param accumulator The MMR peak list
    /// @param receipt COSE_Sign1 payment receipt (SCITT format)
    /// @param consistencyProof Proof that new accumulator extends previous
    /// @param receiptInclusionProof MMR inclusion proof for receipt in authority log
    function publishCheckpoint(
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt,
        bytes calldata consistencyProof,
        bytes calldata receiptInclusionProof
    ) external;
}
