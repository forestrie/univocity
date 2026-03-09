// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    GF_AUTH_LOG,
    GF_CREATE,
    GF_EXTEND,
    GF_GC_MASK,
    GF_DATA_LOG,
    GC_AUTH_LOG,
    GC_DATA_LOG,
    P256_P
} from "@univocity/interfaces/constants.sol";
import {
    LogKind,
    LogConfig,
    LogState,
    ConsistencyProof,
    ConsistencyReceipt,
    InclusionProof,
    DelegationProof,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {
    extractAlgorithm,
    verifyES256DetachedPayload,
    verifyKS256DetachedPayload,
    UnsupportedAlgorithm
} from "@univocity/cosecbor/cosecbor.sol";
import {
    decodeDelegationKeyES256,
    verifyDelegationProofES256
} from "@univocity/checkpoints/lib/delegationVerifier.sol";
import {
    verifyConsistencyProofChain,
    buildDetachedPayloadCommitment
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";
import {MAX_HEIGHT} from "@univocity/algorithms/constants.sol";
import {verifyInclusion} from "@univocity/algorithms/includedRoot.sol";
import {
    LibLogState,
    _leafCommitment
} from "@univocity/algorithms/lib/LibLogState.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @title _Univocity
/// @notice Abstract base for Univocity-style transparency contracts (plan 0027).
///    Implementers supply the bootstrap key via internal getters so that
///    bootstrap can be fixed at construction (immutable) or via an
///    initializer (storage slot for upgradeability).
/// @dev All bootstrap access goes through _bootstrapAlg(), _bootstrapKS256Signer(),
///    _bootstrapES256X(), _bootstrapES256Y(). Concrete contracts implement these.
///    Implementers may fix bootstrap at construction (immutable) or via an
///    initializer (storage). Using storage for bootstrap (e.g. upgradeable path)
///    costs more gas per publishCheckpoint than immutables. Upgradable
///    implementations must set bootstrap before the root log is established and
///    should use a one-shot or carefully guarded initializer.
abstract contract _Univocity is IUnivocity, IUnivocityErrors {
    using LibLogState for LogState;

    // === Bootstrap accessors (implemented by concrete contract) ===

    /// @notice COSE algorithm for the bootstrap key (ALG_KS256 or ALG_ES256).
    function _bootstrapAlg() internal view virtual returns (int64);

    /// @notice Bootstrap key as KS256 signer address; address(0) when alg is ES256.
    function _bootstrapKS256Signer() internal view virtual returns (address);

    /// @notice Bootstrap key as ES256 P-256 x-coordinate; zero when alg is KS256.
    function _bootstrapES256X() internal view virtual returns (bytes32);

    /// @notice Bootstrap key as ES256 P-256 y-coordinate; zero when alg is KS256.
    function _bootstrapES256Y() internal view virtual returns (bytes32);

    // === State (no bootstrap storage on base) ===

    /// @notice The log ID of the root authority log. Set on the first
    ///    successful publishCheckpoint (signed by bootstrap key); zero until then.
    bytes32 public rootLogId;

    mapping(bytes32 => LogState) private _logs;
    mapping(bytes32 => LogConfig) private _logConfigs;

    /// @notice Bootstrap key bytes (same encoding as bootstrapConfig return).
    ///    Used for grantData comparison so the base does not call external.
    function _getBootstrapKeyBytes() internal view returns (bytes memory) {
        if (_bootstrapKS256Signer() != address(0)) {
            return abi.encodePacked(_bootstrapKS256Signer());
        }
        return abi.encodePacked(_bootstrapES256X(), _bootstrapES256Y());
    }

    /// @notice Bootstrap key in opaque form (same as constructor). Plan 0018.
    /// @return bootstrapAlg COSE alg (ALG_KS256 or ALG_ES256).
    /// @return bootstrapKey 20 bytes (KS256) or 64 bytes (ES256).
    function bootstrapConfig()
        external
        view
        returns (int64 bootstrapAlg, bytes memory bootstrapKey)
    {
        bootstrapAlg = _bootstrapAlg();
        bootstrapKey = _getBootstrapKeyBytes();
    }

    // === View Functions ===

    /// @notice Returns the mutable state of a log (accumulator, size).
    function logState(bytes32 logId) external view returns (LogState memory) {
        return _logs[logId];
    }

    /// @notice Returns the immutable config of a log (kind, authLogId, rootKey, initializedAt).
    function logConfig(bytes32 logId)
        external
        view
        returns (LogConfig memory)
    {
        return _logConfigs[logId];
    }

    /// @notice Returns the per-log root public key for delegation (ADR-0032).
    ///    ES256 only: 64-byte rootKey decoded to (x, y).
    function logRootKey(bytes32 logId)
        external
        view
        returns (bytes32 rootKeyX, bytes32 rootKeyY)
    {
        return _decodeLogRootKeyES256(logId);
    }

    /// @notice Returns whether a log has received at least one checkpoint.
    /// @param logId The 32-byte log identifier.
    /// @return True if the log has been initialized (first checkpoint
    ///    published), false otherwise.
    function isLogInitialized(bytes32 logId) external view returns (bool) {
        return _logConfigs[logId].initializedAt != 0;
    }

    // === Checkpoint Publishing ===

    /// @notice Publish a checkpoint from a pre-decoded consistency receipt
    ///    and optional inclusion proof (grant).
    /// @dev Authorization: target = publishGrant.logId. Root not yet set:
    ///   first checkpoint ever; grant = self-inclusion (index 0, path length
    ///   up to MAX_HEIGHT); signer key (from grantData) must match bootstrap
    ///   key; grantData must equal bootstrap key bytes (rule 1).
    ///   First checkpoint to a new log: ownerLogId required; inclusion
    ///   verified against owner; kind from grant (rule 2, 3).
    ///   Extend existing log: inclusion verified against config.authLogId
    ///   (rule 2). Grant bounds minGrowth, maxHeight checked (rule 4).
    function publishCheckpoint(
        ConsistencyReceipt calldata consistencyParts,
        InclusionProof calldata grantInclusionProof,
        bytes8 grantIDTimestampBe,
        PublishGrant calldata publishGrant
    ) external {
        bytes32 logId = publishGrant.logId;
        LogState storage log = _logs[logId];
        LogConfig storage config = _logConfigs[logId];

        if (consistencyParts.consistencyProofs.length == 0) {
            revert InvalidConsistencyProof();
        }
        _validateConsistencyProofBounds(consistencyParts.consistencyProofs);
        // Use final proof's treeSize2 for pre-checks so we can reject bad grants
        // before running the consistency proof chain.
        uint64 claimedSize =
            consistencyParts.consistencyProofs[
            consistencyParts.consistencyProofs.length - 1
        ]
        .treeSize2;

        // New log must have at least one leaf; reject claimed size 0.
        if (config.initializedAt == 0 && claimedSize == 0) {
            revert InvalidConsistencyProof();
        }
        _validateCheckpointSizeIncrease(logId, claimedSize);
        // Rule 4: grant bounds — size must be within maxHeight and meet minGrowth.
        _checkPublishGrantBoundsMaxHeight(claimedSize, publishGrant);
        uint64 currentSize = log.size;
        if (claimedSize < currentSize + publishGrant.minGrowth) {
            revert MinGrowthNotMet(
                currentSize, claimedSize, publishGrant.minGrowth
            );
        }
        bytes32[] memory initialAcc = _accumulatorToMemory(log);
        bytes32[] memory accMem = verifyConsistencyProofChain(
            initialAcc, consistencyParts.consistencyProofs
        );
        _validateCheckpointAccumulatorLength(claimedSize, accMem);

        bytes memory detachedPayload = buildDetachedPayloadCommitment(accMem);

        // If the verification fails the function reverts. rootKeyToSet will
        // have length zero for all checkpoints on a log except the first.
        bytes memory rootKeyToSet = _verifyCheckpointSignature(
            logId,
            claimedSize,
            consistencyParts,
            detachedPayload,
            config,
            consistencyParts.delegationProof,
            publishGrant.grant,
            publishGrant.grantData
        );

        // --- Apply grant: verify inclusion, register new logs (rules 1, 2, 3) ---
        bytes32 authForInclusion = _applyInclusionGrant(
            logId,
            claimedSize,
            grantInclusionProof,
            grantIDTimestampBe,
            publishGrant,
            accMem,
            rootKeyToSet
        );

        _updateLogState(
            logId,
            authForInclusion,
            claimedSize,
            accMem,
            grantIDTimestampBe,
            grantInclusionProof.index,
            grantInclusionProof.path
        );
    }

    /// @notice Apply grant: verify inclusion, set config and emit LogRegistered
    ///    for new logs (rules 1, 2, 3). Reverts on failure.
    /// @return authLogId Log against which inclusion was verified (logId when
    ///    creating the root; rootLogId for root extension; owner for others).
    function _applyInclusionGrant(
        bytes32 logId,
        uint64 claimedSize,
        InclusionProof calldata grantInclusionProof,
        bytes8 grantIDTimestampBe,
        PublishGrant calldata publishGrant,
        bytes32[] memory accMem,
        bytes memory rootKeyToSet
    ) internal returns (bytes32 authLogId) {
        LogConfig storage config = _logConfigs[logId];

        if (rootLogId == bytes32(0)) {
            // Rule 1: First checkpoint ever = root authority log. Grant must
            // have GF_CREATE and GF_AUTH_LOG; request must be GC_AUTH_LOG.
            uint256 g = publishGrant.grant;
            uint256 req = publishGrant.request & GF_GC_MASK;
            if (
                (g & GF_CREATE) == 0 || (g & GF_AUTH_LOG) == 0
                    || req != GC_AUTH_LOG
            ) {
                revert GrantRequirement(GF_CREATE | GF_AUTH_LOG, GC_AUTH_LOG);
            }

            // Grant is inclusion proof against the first leaf (index 0) in the
            // new tree.
            if (claimedSize < 1) revert FirstCheckpointSizeTooSmall();

            // Root's first checkpoint: grant is self-inclusion at index 0;
            // path may be any length up to MAX_HEIGHT (claimedSize >= 1).
            if (grantInclusionProof.index != 0) {
                revert InvalidPaymentReceipt();
            }
            if (grantInclusionProof.path.length > MAX_HEIGHT) {
                revert ProofPayloadExceedsMaxHeight();
            }

            if (!verifyInclusion(
                    0,
                    _leafCommitment(grantIDTimestampBe, publishGrant),
                    grantInclusionProof.path,
                    accMem,
                    claimedSize
                )) {
                revert InvalidReceiptInclusionProof();
            }

            config.initializedAt = block.number;
            config.kind = LogKind.Authority;
            config.authLogId = logId;
            if (rootKeyToSet.length == 64 || rootKeyToSet.length == 20) {
                config.rootKey = rootKeyToSet;
            }
            emit LogRegistered(logId, logId, config.rootKey);

            rootLogId = logId;
            emit Initialized(logId);

            return logId;
        }
        // Root extension (after creation) and extend existing data/child log:
        // grant = inclusion proof against this log's authLogId (root = self).
        // First checkpoint to a non-root log (root already exists; this branch
        // cannot be reached for the root authority log). Resolve the log
        // against which we apply the grant (owner), then same proof checks as
        // for extending an existing log.

        if (config.initializedAt == 0) {
            if (publishGrant.ownerLogId == bytes32(0)) {
                revert InvalidPaymentReceipt();
            }

            authLogId = publishGrant.ownerLogId;

            uint256 g = publishGrant.grant;
            uint256 req = publishGrant.request & GF_GC_MASK;
            if ((g & GF_CREATE) == 0) {
                revert GrantRequirement(
                    GF_CREATE | GF_AUTH_LOG | GF_DATA_LOG, 0
                );
            }
            if (req == GC_AUTH_LOG) {
                if ((g & GF_AUTH_LOG) == 0) {
                    revert GrantRequirement(
                        GF_CREATE | GF_AUTH_LOG | GF_DATA_LOG, GC_AUTH_LOG
                    );
                }

                config.kind = LogKind.Authority;
            } else if (req == GC_DATA_LOG) {
                if ((g & GF_DATA_LOG) == 0) {
                    revert GrantRequirement(
                        GF_CREATE | GF_AUTH_LOG | GF_DATA_LOG, GC_DATA_LOG
                    );
                }

                config.kind = LogKind.Data;
            } else {
                revert GrantRequirement(
                    GF_CREATE | GF_AUTH_LOG | GF_DATA_LOG, 0
                );
            }

            if (logId == rootLogId) {
                if (logId != authLogId) revert BootstrapLogMustUseSelf();
                if (req != GC_AUTH_LOG) revert BootstrapLogMustBeAuthLog();
            }

            config.initializedAt = block.number;
            config.authLogId = authLogId;
            if (rootKeyToSet.length == 64 || rootKeyToSet.length == 20) {
                config.rootKey = rootKeyToSet;
            }

            emit LogRegistered(logId, authLogId, config.rootKey);
        } else {
            authLogId = config.authLogId;

            if ((publishGrant.grant & GF_EXTEND) == 0) {
                revert GrantRequirement(GF_EXTEND, 0);
            }
        }

        LogState storage ownerLog = _logs[authLogId];
        // Empty path is valid only when owner has size 1 and index 0 (peak =
        // leaf); e.g. when creating a child log and the owner has one leaf.
        if (grantInclusionProof.path.length == 0) {
            if (!(ownerLog.size == 1 && grantInclusionProof.index == 0)) {
                revert InvalidPaymentReceipt();
            }
        }
        if (grantInclusionProof.path.length > MAX_HEIGHT) {
            revert ProofPayloadExceedsMaxHeight();
        }
        if (!ownerLog.verifyGrantInclusionStorage(
                publishGrant,
                grantIDTimestampBe,
                grantInclusionProof.index,
                grantInclusionProof.path
            )) {
            revert InvalidPaymentReceipt();
        }
        return authLogId;
    }

    function _verifyCheckpointSignature(
        bytes32 logId,
        uint64 claimedSize,
        ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        LogConfig storage config,
        DelegationProof calldata delegationProof,
        uint256 grant,
        bytes calldata grantData
    ) internal view returns (bytes memory initialRoot) {
        // Rule 5: consistency receipt signature verification.
        // We distinguish (1) the log root key — from grantData (first checkpoint,
        // verify-only) or from storage — and (2) the verifier key — the key that
        // must have signed the consistency receipt.
        // When there is no delegation, the root signs the receipt (verifier == root). When there is
        // delegation, the root signs the delegation; the delegate signs the receipt (verifier == delegate).
        int64 alg = extractAlgorithm(consistencyParts.protectedHeader);

        // NOTICE: verification failures always revert
        if (alg == ALG_ES256) {
            return _verifyCheckpointSignatureES256(
                logId,
                claimedSize,
                consistencyParts,
                detachedPayload,
                config,
                delegationProof,
                grant,
                grantData
            );
        }
        if (alg == ALG_KS256) {
            return _verifyCheckpointSignatureKS256(
                logId,
                claimedSize,
                consistencyParts,
                detachedPayload,
                config,
                delegationProof,
                grant,
                grantData
            );
        }

        revert UnsupportedAlgorithm(alg);
    }

    function _verifyCheckpointSignatureES256(
        bytes32 logId,
        uint64 claimedSize,
        ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        LogConfig storage config,
        DelegationProof calldata delegationProof,
        uint256,
        /* grant */
        bytes calldata grantData
    ) internal view returns (bytes memory initialRoot) {
        // --- Verifier key: the key that must have signed the consistency receipt. ---
        // With delegation: delegate signed the receipt. Without: root signed the receipt.
        (bytes32 rootX, bytes32 rootY, bytes32 verifierX, bytes32 verifierY) = _checkpointSignersES256(
            logId,
            claimedSize,
            consistencyParts,
            detachedPayload,
            config,
            delegationProof,
            grantData
        );

        if (!verifyES256DetachedPayload(
                consistencyParts.protectedHeader,
                consistencyParts.signature,
                detachedPayload,
                verifierX,
                verifierY
            )) {
            revert ConsistencyReceiptSignatureInvalid();
        }
        // Persist the log root key for new logs so future checkpoints can
        // verify against it. First checkpoint always uses grantData as signer key (verify-only).
        if (config.initializedAt == 0) {
            if (rootLogId == bytes32(0)) {
                // Root's first checkpoint: signer must match bootstrap key
                // (allows curve inverse (x, P-y)); grantData must be exact
                // bootstrap bytes (same representation as deployment).
                if (!_es256KeyMatchesBootstrap(rootX, rootY)) {
                    revert RootSignerMustMatchBootstrap();
                }
                bytes memory bootstrapKey = _getBootstrapKeyBytes();
                if (grantData.length != bootstrapKey.length) {
                    revert GrantDataInvalidKeyLength(grantData.length);
                }
                if (keccak256(grantData) != keccak256(bootstrapKey)) {
                    revert GrantDataMustMatchBootstrap();
                }
            }
            // Non-root: rootX, rootY already from grantData and verified.
            return abi.encodePacked(rootX, rootY);
        }
        return new bytes(0);
    }

    function _verifyCheckpointSignatureKS256(
        bytes32 logId,
        uint64,
        /* claimedSize */
        ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        LogConfig storage config,
        DelegationProof calldata delegationProof,
        uint256,
        /* grant */
        bytes calldata grantData
    ) internal view returns (bytes memory initialRoot) {
        // KS256: no delegation support. Verifier key is root (bootstrap for
        // root log) or stored log key; first checkpoint uses key from grantData.
        if (delegationProof.signature.length > 0) {
            revert DelegationUnsupportedForAlg(ALG_KS256);
        }
        address keyAddr = (rootLogId == bytes32(0) || logId == rootLogId)
            ? _bootstrapKS256Signer()
            : _decodeLogRootKeyKS256(logId);
        if (keyAddr == address(0)) {
            if (config.rootKey.length == 64) {
                revert InconsistentReceiptSignature(ALG_KS256, ALG_ES256);
            }
            if (config.initializedAt != 0) revert LogRootKeyNotSet();
            // First checkpoint: key from grantData; verify-only.
            if (grantData.length != 20) {
                revert GrantDataInvalidKeyLength(grantData.length);
            }
            bytes memory gd = grantData;
            assembly {
                keyAddr := shr(96, mload(add(gd, 32)))
            }
        }
        if (!verifyKS256DetachedPayload(
                consistencyParts.protectedHeader,
                consistencyParts.signature,
                detachedPayload,
                keyAddr
            )) {
            revert ConsistencyReceiptSignatureInvalid();
        }
        if (config.initializedAt == 0) {
            if (rootLogId == bytes32(0)) {
                bytes memory bootstrapKey = _getBootstrapKeyBytes();
                if (grantData.length != bootstrapKey.length) {
                    revert GrantDataInvalidKeyLength(grantData.length);
                }
                if (keccak256(grantData) != keccak256(bootstrapKey)) {
                    revert GrantDataMustMatchBootstrap();
                }
            }
            return abi.encodePacked(keyAddr);
        }
        return new bytes(0);
    }

    /// @notice Resolve log root key and receipt verifier key for ES256 (Rule 5).
    /// @return rootX Log root x (authority); stored for new logs.
    /// @return rootY Log root y.
    /// @return verifierX Key that must have signed the receipt (x).
    /// @return verifierY Key that must have signed the receipt (y).
    function _checkpointSignersES256(
        bytes32 logId,
        uint64 claimedSize,
        ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        LogConfig storage config,
        DelegationProof calldata delegationProof,
        bytes calldata grantData
    )
        internal
        view
        returns (
            bytes32 rootX,
            bytes32 rootY,
            bytes32 verifierX,
            bytes32 verifierY
        )
    {
        // Root key from storage, or from grantData on first checkpoint
        // (verify-only; no on-chain recovery). For root's first checkpoint the
        // signer key (from grantData) must match the bootstrap key.
        (rootX, rootY) = _decodeLogRootKeyES256(logId);

        if (rootX == bytes32(0) && rootY == bytes32(0)) {
            // Distinguish unset key from key-type mismatch (log created under
            // KS256 has rootKey.length == 20): receipt is ES256, log is KS256.
            if (config.rootKey.length == 20) {
                revert InconsistentReceiptSignature(ALG_ES256, ALG_KS256);
            }
            if (config.initializedAt != 0) revert LogRootKeyNotSet();

            // First checkpoint: root key from grantData; verify-only (no recovery).
            if (grantData.length != 64) {
                revert GrantDataInvalidKeyLength(grantData.length);
            }
            bytes memory gd = grantData;
            assembly {
                rootX := mload(add(gd, 32))
                rootY := mload(add(gd, 64))
            }

            if (delegationProof.signature.length == 0) {
                if (!verifyES256DetachedPayload(
                        consistencyParts.protectedHeader,
                        consistencyParts.signature,
                        detachedPayload,
                        rootX,
                        rootY
                    )) {
                    revert ConsistencyReceiptSignatureInvalid();
                }
                return (rootX, rootY, rootX, rootY);
            }

            // Delegation present: verify delegation with root from grantData.
            (verifierX, verifierY) =
                decodeDelegationKeyES256(delegationProof.delegationKey);
            verifyDelegationProofES256(
                delegationProof.mmrStart,
                delegationProof.mmrEnd,
                delegationProof.signature,
                logId,
                claimedSize > 0 ? claimedSize - 1 : 0,
                rootX,
                rootY,
                verifierX,
                verifierY
            );
            return (rootX, rootY, verifierX, verifierY);
        }

        // Root key present (from storage or from grantData on first checkpoint). Verifier is
        // delegate if delegation, else root.
        if (delegationProof.signature.length > 0) {
            // Note: We do this twice for the very first checkpoint (root auth log),
            // but that is harmless and cheap.
            (verifierX, verifierY) =
                decodeDelegationKeyES256(delegationProof.delegationKey);
            verifyDelegationProofES256(
                delegationProof.mmrStart,
                delegationProof.mmrEnd,
                delegationProof.signature,
                logId,
                claimedSize > 0 ? claimedSize - 1 : 0,
                rootX,
                rootY,
                verifierX,
                verifierY
            );
        } else {
            verifierX = rootX;
            verifierY = rootY;
        }
        return (rootX, rootY, verifierX, verifierY);
    }

    /// @notice Revert if any consistency proof payload array length exceeds
    ///    MAX_HEIGHT (read from calldata; no copy).
    function _validateConsistencyProofBounds(ConsistencyProof[] calldata decodedProofs)
        private
        pure
    {
        for (uint256 i = 0; i < decodedProofs.length; i++) {
            ConsistencyProof calldata p = decodedProofs[i];
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

    /// @dev True if (qx, qy) is the bootstrap ES256 key or its curve inverse.
    function _es256KeyMatchesBootstrap(bytes32 qx, bytes32 qy)
        internal
        view
        returns (bool)
    {
        if (qx != _bootstrapES256X()) return false;
        uint256 qyU = uint256(qy);
        uint256 eyU = uint256(_bootstrapES256Y());
        return qyU == eyU || qyU == P256_P - eyU;
    }

    /// @notice Decode stored root key for ES256 (64 bytes = P-256 x || y).
    function _decodeLogRootKeyES256(bytes32 logId)
        private
        view
        returns (bytes32 keyX, bytes32 keyY)
    {
        bytes memory rk = _logConfigs[logId].rootKey;
        if (rk.length != 64) return (bytes32(0), bytes32(0));
        assembly {
            keyX := mload(add(rk, 32))
            keyY := mload(add(rk, 64))
        }
    }

    /// @notice Decode stored root key for KS256 (20 bytes = address). Returns
    ///    address(0) if rootKey is not 20 bytes (e.g. log uses ES256 key).
    function _decodeLogRootKeyKS256(bytes32 logId)
        private
        view
        returns (address keyAddr)
    {
        bytes memory rk = _logConfigs[logId].rootKey;
        if (rk.length != 20) return address(0);
        assembly {
            keyAddr := shr(96, mload(add(rk, 32)))
        }
    }

    /// @notice Max height bound only; requires derived size (call after proof
    ///    chain).
    function _checkPublishGrantBoundsMaxHeight(
        uint64 size,
        PublishGrant calldata g
    ) private pure {
        if (g.maxHeight != 0 && size > g.maxHeight) {
            revert MaxHeightExceeded(size, g.maxHeight);
        }
    }

    /// @notice Copy log accumulator from storage to memory for free-function
    ///    consistency proof chain (no storage ref in consistencyReceipt.sol).
    function _accumulatorToMemory(LogState storage log)
        private
        view
        returns (bytes32[] memory out)
    {
        uint256 n = log.accumulator.length;
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = log.accumulator[i];
        }
    }

    /// @notice Size must increase (or be initial). Call after proof chain.
    function _validateCheckpointSizeIncrease(bytes32 logId, uint64 size)
        private
        view
    {
        LogState storage log = _logs[logId];
        if (_logConfigs[logId].initializedAt != 0 && size <= log.size) {
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

    /// @notice Update log storage and emit CheckpointPublished.
    function _updateLogState(
        bytes32 logId,
        bytes32 grantLogId,
        uint64 size,
        bytes32[] memory accumulator,
        bytes8 grantIDTimestampBe,
        uint64 grantIndex,
        bytes32[] calldata grantPath
    ) private {
        LogState storage log = _logs[logId];
        LogConfig storage config = _logConfigs[logId];

        delete log.accumulator;
        for (uint256 i = 0; i < accumulator.length; i++) {
            log.accumulator.push(accumulator[i]);
        }

        log.size = size;

        emit CheckpointPublished(
            logId,
            grantLogId,
            config.rootKey,
            _msgSender(),
            grantIDTimestampBe,
            uint8(config.kind),
            size,
            accumulator,
            grantIndex,
            grantPath
        );
    }

    /// @notice Returns the message sender (override for meta-tx if needed).
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}
