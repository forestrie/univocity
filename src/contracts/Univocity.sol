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
    ///    authority and a single bootstrap key (alg + opaque bytes, same
    ///    pattern as rootKey / delegationKey). Plan 0018.
    /// @dev Authority log is set by the first publishCheckpoint from the
    ///    bootstrap authority.
    /// @param _bootstrapAuthority Address allowed to publish the first
    ///    checkpoint and to publish to the authority log. Must not be zero.
    /// @param _bootstrapAlg COSE algorithm: ALG_KS256 (-65799) or ALG_ES256
    ///    (-7). Key format depends on alg.
    /// @param _bootstrapKey Opaque key: KS256 = 20 bytes (Ethereum address);
    ///    ES256 = 64 bytes (P-256 x || y).
    /// @custom:throws OnlyBootstrapAuthority If _bootstrapAuthority is zero.
    /// @custom:throws InvalidBootstrapAlgorithm If alg is not KS256 or ES256.
    /// @custom:throws InvalidBootstrapKeyLength If key length does not match
    ///    alg (20 for KS256, 64 for ES256).
    constructor(
        address _bootstrapAuthority,
        int64 _bootstrapAlg,
        bytes memory _bootstrapKey
    ) {
        if (_bootstrapAuthority == address(0)) {
            revert OnlyBootstrapAuthority();
        }
        if (
            _bootstrapAlg != LibCose.ALG_KS256
                && _bootstrapAlg != LibCose.ALG_ES256
        ) {
            revert InvalidBootstrapAlgorithm(_bootstrapAlg);
        }
        if (_bootstrapAlg == LibCose.ALG_KS256) {
            if (_bootstrapKey.length != 20) {
                revert InvalidBootstrapKeyLength(
                    _bootstrapAlg, _bootstrapKey.length
                );
            }
            address _ks;
            assembly {
                _ks := shr(96, mload(add(_bootstrapKey, 32)))
            }
            if (_ks == address(0)) {
                revert InvalidBootstrapKeyLength(_bootstrapAlg, 0);
            }
            ks256Signer = _ks;
            es256X = bytes32(0);
            es256Y = bytes32(0);
        } else {
            if (_bootstrapKey.length != 64) {
                revert InvalidBootstrapKeyLength(
                    _bootstrapAlg, _bootstrapKey.length
                );
            }
            bytes32 _ex;
            bytes32 _ey;
            assembly {
                _ex := mload(add(_bootstrapKey, 32))
                _ey := mload(add(_bootstrapKey, 64))
            }
            es256X = _ex;
            es256Y = _ey;
            ks256Signer = address(0);
        }
        bootstrapAuthority = _bootstrapAuthority;
    }

    /// @notice Bootstrap key in opaque form (same as constructor). Plan 0018.
    /// @return bootstrapAlg COSE alg (ALG_KS256 or ALG_ES256).
    /// @return bootstrapKey 20 bytes (KS256) or 64 bytes (ES256).
    function getBootstrapKeyConfig()
        external
        view
        returns (int64 bootstrapAlg, bytes memory bootstrapKey)
    {
        if (ks256Signer != address(0)) {
            return (LibCose.ALG_KS256, abi.encodePacked(ks256Signer));
        }
        return (LibCose.ALG_ES256, abi.encodePacked(es256X, es256Y));
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

        int64 alg = LibCbor.extractAlgorithm(consistencyParts.protectedHeader);
        bool sigOk = false;
        if (useDelegation) {
            if (alg != LibCose.ALG_ES256) {
                revert LibCose.UnsupportedAlgorithm(alg);
            }
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
            sigOk = LibCose.verifyES256DetachedPayload(
                consistencyParts.protectedHeader,
                consistencyParts.signature,
                detachedPayload,
                delResult.delegatedKeyX,
                delResult.delegatedKeyY
            );
        } else {
            if (alg == LibCose.ALG_ES256) {
                sigOk = LibCose.verifyES256DetachedPayload(
                    consistencyParts.protectedHeader,
                    consistencyParts.signature,
                    detachedPayload,
                    es256X,
                    es256Y
                );
            } else if (alg == LibCose.ALG_KS256) {
                sigOk = LibCose.verifyKS256DetachedPayload(
                    consistencyParts.protectedHeader,
                    consistencyParts.signature,
                    detachedPayload,
                    ks256Signer
                );
            } else {
                revert LibCose.UnsupportedAlgorithm(alg);
            }
        }
        if (!sigOk) revert ConsistencyReceiptSignatureInvalid();

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
            size,
            accMem,
            paymentGrant.payer,
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

    /// @notice Update log storage and emit CheckpointPublished. Loads log from
    ///    storage by logId to avoid inconsistent log vs logId.
    /// @param logId Log identifier.
    /// @param size MMR size after checkpoint (last mmrIndex + 1).
    /// @param accumulator New peaks.
    /// @param payer Payer from PaymentGrant (who paid).
    /// @param paymentIndex Inclusion proof index (0 when no payment receipt).
    /// @param paymentPath Inclusion proof path (empty when no payment receipt).
    function _updateLogState(
        bytes32 logId,
        uint64 size,
        bytes32[] memory accumulator,
        address payer,
        uint64 paymentIndex,
        bytes32[] calldata paymentPath
    ) private {
        LogState storage log = _logs[logId];
        bool isNewLog = log.initializedAt == 0;

        if (isNewLog) {
            log.initializedAt = block.number;
            emit LogRegistered(logId, _msgSender(), size);
        }

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
            _msgSender(),
            payer,
            size,
            log.checkpointCount,
            accumulator,
            paymentIndex,
            paymentPath
        );
    }

    /// @notice Returns the message sender (override for meta-tx if needed).
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}
