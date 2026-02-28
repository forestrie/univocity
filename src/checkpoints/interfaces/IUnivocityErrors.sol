// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityErrors
/// @notice Custom errors for univocity contract
interface IUnivocityErrors {
    // Initialization
    error AlreadyInitialized();
    error NotInitialized();
    error OnlyBootstrapAuthority();
    /// @notice Bootstrap algorithm not supported (use COSE ALG_ES256 or
    ///    ALG_KS256).
    error InvalidBootstrapAlgorithm(int64 alg);
    /// @notice Bootstrap key length invalid for the given alg (KS256 = 20,
    ///    ES256 = 64).
    error InvalidBootstrapKeyLength(int64 alg, uint256 length);
    error FirstCheckpointSizeTooSmall();
    error BootstrapReceiptMustBeFirstEntry();
    /// @notice Root's first checkpoint: recovered signer must match bootstrap
    ///    key to prevent front-running (no grant-based protection for root).
    error RootSignerMustMatchBootstrap();

    // Log state
    error LogNotFound(bytes32 logId);
    error SizeMustIncrease(uint64 current, uint64 proposed);
    error InvalidAccumulatorLength(uint256 expected, uint256 actual);
    error InvalidRootKeyLength(uint256 length);
    /// @notice Log has no root key set; only allowed on first checkpoint for
    ///    that log (root key is then established from receipt/delegation).
    error LogRootKeyNotSet();

    // Proofs
    error InvalidConsistencyProof();
    error InvalidSignatureChain();
    error InvalidReceiptInclusionProof();

    // Grant bounds / payment authorization
    error CheckpointCountExceeded(uint64 current, uint64 limit);
    error MaxHeightExceeded(uint64 size, uint64 maxHeight);
    error ReceiptLogIdMismatch(bytes32 expected, bytes32 actual);

    // ADR-0032 checkpoint COSE / delegation
    /// @notice Delegation proof supplied but algorithm does not support
    ///    delegation (e.g. KS256).
    error DelegationUnsupportedForAlg(int64 alg);
    /// @notice Receipt signed with one algorithm but log configured for another
    ///    (e.g. ES256 receipt for a KS256 log).
    error InconsistentReceiptSignature(int64 algProvided, int64 algLog);
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
    /// @notice Grant code or flags do not match the required values for this
    ///    operation (e.g. first root checkpoint requires GC_CREATE, GF_AUTH_LOG).
    error GrantRequirement(uint256 requiredGrant);
    error MinGrowthNotMet(
        uint64 currentSize, uint64 newSize, uint64 minGrowth
    );
}
