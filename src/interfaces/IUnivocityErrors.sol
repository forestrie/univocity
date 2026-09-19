// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityErrors
/// @notice Custom errors for univocity contract
interface IUnivocityErrors {
    // Initialization
    error AlreadyInitialized();
    error NotInitialized();
    error BootstrapLogMustUseSelf();
    error BootstrapLogMustBeAuthLog();
    /// @notice Bootstrap algorithm not supported (use COSE ALG_ES256 or
    ///    ALG_KS256).
    error InvalidBootstrapAlgorithm(int64 alg);
    /// @notice Bootstrap key length invalid for the given alg (KS256 = 20,
    ///    ES256 = 64).
    error InvalidBootstrapKeyLength(int64 alg, uint256 length);
    error FirstCheckpointSizeTooSmall();
    error BootstrapReceiptMustBeFirstEntry();
    /// @notice Root's first checkpoint: grantData (signer key) must match
    ///    bootstrap key to prevent front-running.
    error RootSignerMustMatchBootstrap();
    /// @notice First checkpoint: grantData must be the signer key; length must
    ///    be 20 (KS256) or 64 (ES256).
    error GrantDataInvalidKeyLength(uint256 length);
    /// @notice Root's first checkpoint: grantData bytes must equal bootstrap
    ///    key (wrong key supplied).
    error GrantDataMustMatchBootstrap();

    // Log state
    error LogNotFound(bytes32 logId);
    error SizeMustIncrease(uint64 current, uint64 proposed);
    error InvalidAccumulatorLength(uint256 expected, uint256 actual);
    error InvalidRootKeyLength(uint256 length);
    /// @notice Log has no root key set; only allowed on first checkpoint for
    ///    that log (root key is then taken from grantData and verified).
    error LogRootKeyNotSet();

    // Proofs
    error InvalidConsistencyProof();
    /// @notice A consistency proof declared a base (treeSize1) other than
    ///    the size it follows: the anchored size for the first proof, the
    ///    previous proof's treeSize2 thereafter (FOR-567).
    error ConsistencyBaseMismatch(uint64 expected, uint64 declared);
    /// @notice A declared tree size is not a complete MMR
    ///    (indexHeight(size) != 0), so no MMR has that many nodes.
    error IncompleteTreeSize(uint64 size);
    /// @notice Consistency proof path `peak` (position in the origin
    ///    accumulator) has a length other than the one the two declared
    ///    sizes imply (draft inclusion_proof_path).
    error ConsistencyPathLengthMismatch(
        uint256 peak, uint256 expected, uint256 actual
    );
    /// @notice A proof, proven-root or rightPeaks count differs from what
    ///    the declared sizes imply.
    error ConsistencyPeakCountMismatch(uint256 expected, uint256 actual);
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

    // ALG_ES256_WEBAUTHN delegation (WebAuthn assertion envelope)
    /// @notice WebAuthn assertion envelope malformed: bad
    ///    abi.encode(WebAuthnAuth) shape, short authenticatorData, wrong
    ///    clientDataJSON type, or inconsistent BE/BS flags.
    error InvalidWebAuthnAssertion();
    /// @notice clientDataJSON.challenge is not
    ///    base64url(sha256(Sig_structure)) for the canonical delegation
    ///    payload — the assertion does not bind this delegation.
    error DelegationChallengeMismatch();
    /// @notice Assertion lacks the UP (user present) flag.
    error DelegationUserPresenceRequired();
    /// @notice Log policy requires UV (user verified) but the assertion
    ///    lacks the flag.
    error DelegationUserVerificationRequired();
    /// @notice Log policy pins the relying party and the assertion's
    ///    rpIdHash does not match.
    error DelegationRpIdMismatch();
    /// @notice Grant carries alg-policy flags (GF_ALG_MASK band) that the
    ///    supplied delegation algorithm does not consume — including no
    ///    delegation at all. Rejected so a stated policy is never
    ///    silently dropped (ADR-0008).
    error UnsupportedDelegationPolicyFlags(uint256 unsupported);
    /// @notice DelegationProof.algData supplied for an algorithm that
    ///    defines no elements (ADR-0008).
    error UnexpectedDelegationAlgData(uint256 count);

    // Plan 0014: Receipt of Consistency
    error MissingCheckpointSignerKey();
    error ConsistencyReceiptSignatureInvalid();
    /// @notice Consistency or inclusion proof array length exceeds MAX_HEIGHT
    error ProofPayloadExceedsMaxHeight();

    // Plan 0015: Payment receipt as Receipt of Inclusion
    error InvalidPaymentReceipt();
    /// @notice Grant or request does not match the required values for this
    ///    operation. requiredGrant = GF_* flags; requiredRequest = GC_* (or 0).
    error GrantRequirement(uint256 requiredGrant, uint256 requiredRequest);
    error MinGrowthNotMet(
        uint64 currentSize, uint64 newSize, uint64 minGrowth
    );
}
