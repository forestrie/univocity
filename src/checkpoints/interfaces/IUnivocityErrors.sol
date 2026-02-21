// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityErrors
/// @notice Custom errors for univocity contract
interface IUnivocityErrors {
    // Initialization
    error AlreadyInitialized();
    error NotInitialized();
    error OnlyBootstrapAuthority();

    // Log state
    error LogNotFound(bytes32 logId);
    error SizeMustIncrease(uint64 current, uint64 proposed);
    error InvalidAccumulatorLength(uint256 expected, uint256 actual);

    // Proofs
    error InvalidConsistencyProof();
    error InvalidSignatureChain();
    error InvalidReceiptInclusionProof();

    // R5 Authorization
    error CheckpointCountExceeded(uint64 current, uint64 limit);
    error MaxHeightExceeded(uint64 size, uint64 maxHeight);
    error ReceiptLogIdMismatch(bytes32 expected, bytes32 actual);
}
