// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityErrors
/// @notice Custom errors for univocity contract
interface IUnivocityErrors {
    // Initialization
    error AlreadyInitialized();
    error NotInitialized();
    error OnlyBootstrapAuthority();
    error FirstCheckpointSizeTooSmall();
    error BootstrapReceiptMustBeFirstEntry();

    // Log state
    error LogNotFound(bytes32 logId);
    error SizeMustIncrease(uint64 current, uint64 proposed);
    error InvalidAccumulatorLength(uint256 expected, uint256 actual);
    error InvalidRootKeyLength(uint256 length);

    // Proofs
    error InvalidConsistencyProof();
    error InvalidSignatureChain();
    error InvalidReceiptInclusionProof();

    // R5 Authorization
    error CheckpointCountExceeded(uint64 current, uint64 limit);
    error MaxHeightExceeded(uint64 size, uint64 maxHeight);
    error ReceiptLogIdMismatch(bytes32 expected, bytes32 actual);

    // ADR-0032 checkpoint COSE / delegation
    error InvalidCheckpointCose();
    error MissingDelegationCert();
    error InvalidDelegationSignatureLength(uint256 length);
    error InvalidRecoveryId(uint8 value);
    error RecoveryIdDuplicate();
    error DuplicateRootKeyInDelegation();
    error RecoveredKeyMismatchIncludedKey();
    error MissingRootKeyForRecovery();
    error DelegationSignatureInvalid();
    error DelegationLogIdMismatch();
    error CheckpointIndexOutOfDelegationRange();

    // Plan 0014: Receipt of Consistency
    error MissingCheckpointSignerKey();
    error ConsistencyReceiptSignatureInvalid();
    /// @notice Consistency or inclusion proof array length exceeds MAX_HEIGHT
    error ProofPayloadExceedsMaxHeight();

    // Plan 0015: Payment receipt as Receipt of Inclusion
    error InvalidPaymentReceipt();
    error MinGrowthNotMet(
        uint64 currentSize, uint64 newSize, uint64 minGrowth
    );
}
