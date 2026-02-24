// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";
import {
    LibDelegationVerifier
} from "@univocity/checkpoints/lib/LibDelegationVerifier.sol";
import {
    LibConsistencyReceipt
} from "@univocity/checkpoints/lib/LibConsistencyReceipt.sol";
import {MAX_HEIGHT} from "@univocity/algorithms/constants.sol";
import {verifyInclusion} from "@univocity/algorithms/includedRoot.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @title Univocity
/// @notice Multi-log transparency contract with R5 payment-bounded
///    authorization
/// @dev Implements permissionless checkpoint submission with SCITT-format
///    receipts
contract Univocity is IUnivocity, IUnivocityErrors {
    // === State ===

    /// @notice Address permitted to publish the first checkpoint (establishing
    ///    the authority log)
    ///    and to publish to the authority log.
    address public immutable bootstrapAuthority;

    /// @notice Ethereum address used to verify KS256 (secp256k1) signatures on
    ///    COSE receipts.
    address public immutable ks256Signer;

    /// @notice P-256 public key x-coordinate for ES256 (WebAuthn/passkey)
    ///    receipt verification.
    bytes32 public immutable es256X;

    /// @notice P-256 public key y-coordinate for ES256 receipt verification.
    bytes32 public immutable es256Y;

    /// @notice The log ID of the authority log.
    ///    Set on the first successful publishCheckpoint call
    ///    from the bootstrap authority; zero until then.
    bytes32 public authorityLogId;

    mapping(bytes32 => LogState) private _logs;

    // === Constructor ===

    /// @notice Deploys the Univocity transparency contract with bootstrap
    ///    authority and signing
    ///    keys.
    /// @dev At least one of KS256 or ES256 must be configured for receipt
    ///    verification.
    ///    The authority log is not set here;
    ///    it is established by the first call to
    ///    publishCheckpoint from the bootstrap authority (that call's logId
    ///    becomes the authority
    ///    log).
    /// @param _bootstrapAuthority Address allowed to publish the first
    ///    checkpoint (any log) and to
    ///    publish
    ///    to the authority log. Must not be zero.
    /// @param _ks256Signer Ethereum address used to verify KS256 (secp256k1)
    ///    signatures on COSE
    ///    receipts.
    ///    Pass address(0) to disable KS256.
    /// @param _es256X P-256 public key x-coordinate for ES256
    ///    (WebAuthn/passkey) receipt
    ///    verification.
    ///    Pass bytes32(0) with _es256Y to disable ES256.
    /// @param _es256Y P-256 public key y-coordinate for ES256 verification.
    /// @custom:throws OnlyBootstrapAuthority If _bootstrapAuthority is zero or
    /// both KS256 and ES256
    /// are disabled.
    constructor(
        address _bootstrapAuthority,
        address _ks256Signer,
        bytes32 _es256X,
        bytes32 _es256Y
    ) {
        if (_bootstrapAuthority == address(0)) {
            revert OnlyBootstrapAuthority();
        }
        // At least one signing key must be set
        if (_ks256Signer == address(0) && _es256X == bytes32(0)) {
            revert OnlyBootstrapAuthority();
        }

        bootstrapAuthority = _bootstrapAuthority;
        ks256Signer = _ks256Signer;
        es256X = _es256X;
        es256Y = _es256Y;
    }

    /// @notice Returns the bootstrap keys used to verify COSE_Sign1 receipt
    ///    signatures.
    /// @dev Used by LibCose for KS256 (ecrecover) and
    ///    ES256 (P-256)
    ///    verification.
    /// @return A struct containing ks256Signer, es256X,
    ///    and es256Y (as in the constructor).
    function getBootstrapKeys()
        public
        view
        returns (LibCose.CoseVerifierKeys memory)
    {
        return LibCose.CoseVerifierKeys({
            ks256Signer: ks256Signer, es256X: es256X, es256Y: es256Y
        });
    }

    // === Modifiers ===

    modifier onlyBootstrap() {
        _onlyBootstrap();
        _;
    }

    function _onlyBootstrap() internal view {
        if (msg.sender != bootstrapAuthority) revert OnlyBootstrapAuthority();
    }

    // === Initialization (internal;
    // authority established by first bootstrap checkpoint) ===

    /// @notice Set authority log from first checkpoint;
    ///    only callable when not yet initialized.
    /// @dev Called from publishCheckpoint when authorityLogId is unset and
    ///    msg.sender is bootstrap.
    function _initializeAuthorityLog(bytes32 logId) internal {
        if (authorityLogId != bytes32(0)) revert AlreadyInitialized();
        authorityLogId = logId;
        emit Initialized(bootstrapAuthority, logId);
    }

    // === View Functions ===

    /// @notice Returns the full state of a log (accumulator, size,
    ///    checkpoint count, initialization
    ///    block).
    /// @param logId The 32-byte log identifier (e.g.
    ///    keccak256 of a log name or config).
    /// @return The log's accumulator (MMR peak hashes),
    ///    current size (leaf count), checkpoint
    ///    count,
    ///    and block number when the log was first initialized (0 if never
    ///    initialized).
    function getLogState(bytes32 logId)
        external
        view
        returns (LogState memory)
    {
        return _logs[logId];
    }

    /// @notice Returns the per-log root public key for delegation
    ///    verification (ADR-0032). Decodes stored opaque rootKey.
    /// @param logId The 32-byte log identifier.
    /// @return rootKeyX P-256 x-coordinate; zero if root not yet established.
    /// @return rootKeyY P-256 y-coordinate; zero if root not yet established.
    function getLogRootKey(bytes32 logId)
        external
        view
        returns (bytes32 rootKeyX, bytes32 rootKeyY)
    {
        return _decodeLogRootKey(_logs[logId]);
    }

    /// @notice Set the root public key for a log (bootstrap only). Plan 0016:
    ///    root is never derived from a delegation cert. P-256 only: 64 bytes.
    /// @param logId The 32-byte log identifier.
    /// @param rootKey Opaque key; must be 64 bytes (P-256 x || y).
    function setLogRoot(bytes32 logId, bytes calldata rootKey)
        external
        onlyBootstrap
    {
        if (rootKey.length != 64) {
            revert InvalidRootKeyLength(rootKey.length);
        }
        LogState storage log = _logs[logId];
        log.rootKey = rootKey;
    }

    /// @notice Returns whether a log has received at least one checkpoint.
    /// @param logId The 32-byte log identifier.
    /// @return True if the log has been initialized (first checkpoint
    ///    published), false otherwise.
    function isLogInitialized(bytes32 logId) external view returns (bool) {
        return _logs[logId].initializedAt != 0;
    }

    // === Checkpoint Publishing ===

    /// @notice Plan 0016: publish checkpoint from pre-decoded consistency
    ///    receipt and optional pre-decoded inclusion proof.
    function publishCheckpoint(
        IUnivocity.ConsistencyReceipt calldata consistencyParts,
        IUnivocity.InclusionProof calldata paymentInclusionProof,
        bytes8 paymentIDTimestampBe,
        IUnivocity.PaymentGrant calldata paymentGrant
    ) external {
        bytes32 logId = paymentGrant.logId;
        LogState storage log = _logs[logId];

        _checkPaymentGrantBoundsCheckpointRange(log, paymentGrant);

        _validateConsistencyProofBounds(consistencyParts.consistencyProofs);
        (bytes32[] memory accMem, uint64 size) = LibConsistencyReceipt.verifyConsistencyProofChain(
            log.accumulator, consistencyParts.consistencyProofs
        );

        _validateCheckpointSizeIncrease(log, size);
        _checkPaymentGrantBoundsMaxHeight(size, paymentGrant);
        uint64 currentSize = log.size;
        if (size < currentSize + paymentGrant.minGrowth) {
            revert MinGrowthNotMet(currentSize, size, paymentGrant.minGrowth);
        }

        bytes memory detachedPayload =
            LibConsistencyReceipt.buildDetachedPayloadCommitment(accMem);

        bool useDelegation =
            consistencyParts.delegationProof.signature.length > 0;

        // Decode log root key at most once per transaction (P-256: 64 bytes).
        (bytes32 rootKeyX, bytes32 rootKeyY) = _decodeLogRootKey(log);

        if (useDelegation) {
            LibDelegationVerifier.DelegationResult memory delResult =
                LibDelegationVerifier.verifyDelegationProof(
                    consistencyParts.delegationProof.delegationKey,
                    consistencyParts.delegationProof.mmrStart,
                    consistencyParts.delegationProof.mmrEnd,
                    consistencyParts.delegationProof.alg,
                    consistencyParts.delegationProof.signature,
                    logId,
                    size > 0 ? size - 1 : 0,
                    rootKeyX,
                    rootKeyY
                );
            if (!LibCose.verifySignatureDetachedPayload(
                    consistencyParts.protectedHeader,
                    consistencyParts.signature,
                    detachedPayload,
                    LibCbor.extractAlgorithm(consistencyParts.protectedHeader),
                    LibCose.fromDelegatedEs256(
                        delResult.delegatedKeyX, delResult.delegatedKeyY
                    )
                )) {
                revert ConsistencyReceiptSignatureInvalid();
            }
        } else {
            if (authorityLogId == bytes32(0)) {
                if (!LibCose.verifySignatureDetachedPayload(
                        consistencyParts.protectedHeader,
                        consistencyParts.signature,
                        detachedPayload,
                        LibCbor.extractAlgorithm(
                            consistencyParts.protectedHeader
                        ),
                        getBootstrapKeys()
                    )) {
                    revert ConsistencyReceiptSignatureInvalid();
                }
            } else if (rootKeyX == bytes32(0) && rootKeyY == bytes32(0)) {
                if (!LibCose.verifySignatureDetachedPayload(
                        consistencyParts.protectedHeader,
                        consistencyParts.signature,
                        detachedPayload,
                        LibCbor.extractAlgorithm(
                            consistencyParts.protectedHeader
                        ),
                        getBootstrapKeys()
                    )) {
                    revert ConsistencyReceiptSignatureInvalid();
                }
            } else {
                if (!LibCose.verifySignatureDetachedPayload(
                        consistencyParts.protectedHeader,
                        consistencyParts.signature,
                        detachedPayload,
                        LibCbor.extractAlgorithm(
                            consistencyParts.protectedHeader
                        ),
                        LibCose.fromDelegatedEs256(rootKeyX, rootKeyY)
                    )) {
                    revert ConsistencyReceiptSignatureInvalid();
                }
            }
        }

        if (authorityLogId == bytes32(0)) {
            if (size < 1) revert FirstCheckpointSizeTooSmall();
            if (paymentInclusionProof.path.length != 0) {
                revert InvalidPaymentReceipt();
            }
            bytes32 leafCommitment =
                _leafCommitment(paymentIDTimestampBe, paymentGrant);
            if (!verifyInclusion(
                    0, leafCommitment, paymentInclusionProof.path, accMem, size
                )) {
                revert InvalidReceiptInclusionProof();
            }
            _initializeAuthorityLog(logId);
        } else if (paymentGrant.logId == authorityLogId) {
            if (paymentInclusionProof.path.length != 0) {
                revert InvalidPaymentReceipt();
            }
            if (msg.sender != bootstrapAuthority) {
                revert OnlyBootstrapAuthority();
            }
        } else {
            if (paymentInclusionProof.path.length == 0) {
                revert InvalidPaymentReceipt();
            }
            if (paymentInclusionProof.path.length > MAX_HEIGHT) {
                revert ProofPayloadExceedsMaxHeight();
            }
            bytes32 leafCommitment =
                _leafCommitment(paymentIDTimestampBe, paymentGrant);
            LogState storage authorityLog = _logs[authorityLogId];
            if (!verifyInclusion(
                    paymentInclusionProof.index,
                    leafCommitment,
                    paymentInclusionProof.path,
                    authorityLog.accumulator,
                    authorityLog.size
                )) {
                revert InvalidPaymentReceipt();
            }
        }

        _validateCheckpointAccumulatorLength(size, accMem);

        _updateLogState(
            logId,
            log,
            size,
            accMem,
            paymentInclusionProof.index,
            paymentInclusionProof.path
        );
    }

    /// @notice Revert if any consistency proof payload array length exceeds
    ///    MAX_HEIGHT (read from calldata; no copy).
    function _validateConsistencyProofBounds(IUnivocity
                .ConsistencyProof[] calldata decodedProofs) private pure {
        for (uint256 i = 0; i < decodedProofs.length; i++) {
            IUnivocity.ConsistencyProof calldata p = decodedProofs[i];
            if (p.paths.length > MAX_HEIGHT) {
                revert ProofPayloadExceedsMaxHeight();
            }
            if (p.rightPeaks.length > MAX_HEIGHT) {
                revert ProofPayloadExceedsMaxHeight();
            }
            for (uint256 j = 0; j < p.paths.length; j++) {
                if (p.paths[j].length > MAX_HEIGHT) {
                    revert ProofPayloadExceedsMaxHeight();
                }
            }
        }
    }

    /// @notice Decode stored opaque root key to P-256 (x, y). Once per tx.
    /// @return keyX First 32 bytes, or 0 if root not set / invalid length.
    /// @return keyY Next 32 bytes, or 0 if root not set / invalid length.
    function _decodeLogRootKey(LogState storage log)
        private
        view
        returns (bytes32 keyX, bytes32 keyY)
    {
        bytes memory rk = log.rootKey;
        if (rk.length != 64) return (bytes32(0), bytes32(0));
        assembly {
            keyX := mload(add(rk, 32))
            keyY := mload(add(rk, 64))
        }
    }

    function _leafCommitment(
        bytes8 paymentIDTimestampBe,
        IUnivocity.PaymentGrant calldata g
    ) private pure returns (bytes32) {
        bytes32 inner = sha256(
            abi.encodePacked(
                g.logId,
                g.payer,
                g.checkpointStart,
                g.checkpointEnd,
                g.maxHeight,
                g.minGrowth
            )
        );
        return sha256(abi.encodePacked(paymentIDTimestampBe, inner));
    }

    /// @notice Checkpoint range only; safe to call before any proof/signature
    ///    verification (no dependency on derived size).
    function _checkPaymentGrantBoundsCheckpointRange(
        LogState storage log,
        IUnivocity.PaymentGrant calldata g
    ) private view {
        uint64 cc = log.checkpointCount;
        if (cc < g.checkpointStart) {
            revert CheckpointCountExceeded(cc, g.checkpointStart);
        }
        if (cc >= g.checkpointEnd) {
            revert CheckpointCountExceeded(cc, g.checkpointEnd);
        }
    }

    /// @notice Max height bound only; requires derived size (call after proof
    ///    chain).
    function _checkPaymentGrantBoundsMaxHeight(
        uint64 size,
        IUnivocity.PaymentGrant calldata g
    ) private pure {
        if (g.maxHeight != 0 && size > g.maxHeight) {
            revert MaxHeightExceeded(size, g.maxHeight);
        }
    }

    /// @notice Size must increase (or be initial); no dependency on new
    ///    accumulator. Call after proof chain.
    function _validateCheckpointSizeIncrease(
        LogState storage log,
        uint64 size
    ) private view {
        if (log.initializedAt != 0 && size <= log.size) {
            revert SizeMustIncrease(log.size, size);
        }
    }

    /// @notice Accumulator length must match expected peaks for size (MMR
    ///    profile). Call after proof chain.
    function _validateCheckpointAccumulatorLength(
        uint64 size,
        bytes32[] memory accumulator
    ) private pure {
        uint256 expectedPeaks = size == 0 ? 0 : peaks(uint256(size) - 1).length;
        if (accumulator.length != expectedPeaks) {
            revert InvalidAccumulatorLength(expectedPeaks, accumulator.length);
        }
    }

    /// @notice Update log storage and emit CheckpointPublished with
    ///    payment receipt index and path from InclusionProof.
    function _updateLogState(
        bytes32 logId,
        LogState storage log,
        uint64 size,
        bytes32[] memory accumulator,
        uint64 paymentIndex,
        bytes32[] calldata paymentPath
    ) private {
        bool isNewLog = log.initializedAt == 0;

        if (isNewLog) {
            log.initializedAt = block.number;
            emit LogRegistered(logId, msg.sender, size);
        }

        // Copy accumulator to storage
        delete log.accumulator;
        for (uint256 i = 0; i < accumulator.length; i++) {
            log.accumulator.push(accumulator[i]);
        }

        log.size = size;
        unchecked {
            log.checkpointCount++;
        }

        emit CheckpointPublished(
            logId,
            size,
            log.checkpointCount,
            accumulator,
            paymentIndex,
            paymentPath
        );
    }
}
