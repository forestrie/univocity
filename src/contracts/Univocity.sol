// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {
    extractAlgorithm,
    verifyES256DetachedPayload,
    verifyKS256DetachedPayload,
    recoverES256FromDetachedPayload,
    UnsupportedAlgorithm
} from "@univocity/cosecbor/cosecbor.sol";
import {
    decodeDelegationKeyES256,
    verifyDelegationProofES256,
    recoverDelegationSignerES256
} from "@univocity/checkpoints/lib/delegationVerifier.sol";
import {
    verifyConsistencyProofChain,
    buildDetachedPayloadCommitment
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";
import {MAX_HEIGHT} from "@univocity/algorithms/constants.sol";
import {verifyInclusion} from "@univocity/algorithms/includedRoot.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @title Univocity
/// @notice Multi-log transparency contract with payment-bounded
///    checkpoint authorization (grant inclusion proof + bounds).
/// @dev Implements permissionless checkpoint submission with SCITT-format
///    receipts.
///
/// ## Authorization model (enforced rules)
/// 1. **First checkpoint ever (root):** The first checkpoint establishes the
///    root authority log. Grant is self-inclusion (index 0; path length up to
///    MAX_HEIGHT). The receipt signer becomes that log's root key; for the
///    root's first checkpoint the recovered signer must match the bootstrap
///    key (no grant-based protection; prevents front-running). Submission is
///    permissionless; bootstrapAuthority is the contract's configured
///    identity (for off-chain use); CheckpointPublished carries the sender.
/// 2. **Grant = inclusion against owner:** To extend any other log, the caller
///    must supply a grant evidenced by an inclusion proof in that log's
///    *owner* (data log → owning authority log; child authority → parent log).
/// 3. **Log creation requires ownerLogId:** The first checkpoint to a new log
///    (data or child authority) requires paymentGrant.ownerLogId and an
///    inclusion proof against that owner; kind (Authority/Data) is set from
///    createAsAuthority.
/// 4. **Grant bounds:** Growth is bounded only by minGrowth and maxHeight
///    (no checkpoint counter); size must satisfy currentSize + minGrowth <=
///    size <= maxHeight (when maxHeight != 0).
/// 5. **Consistency receipt:** Every checkpoint's consistency receipt must
///    verify against the target log's root key (or bootstrap key for the
///    root's first checkpoint).
contract Univocity is IUnivocity, IUnivocityErrors {
    // === State ===

    /// @notice Address of the identity whose key must sign the root's first
    ///    checkpoint (signer constraint, not caller). Emitted in Initialized.
    address public immutable bootstrapAuthority;

    /// @notice Ethereum address used to verify KS256 (secp256k1) signatures on
    ///    COSE receipts.
    address public immutable ks256Signer;

    /// @notice P-256 public key x-coordinate for ES256 (WebAuthn/passkey)
    ///    receipt verification.
    bytes32 public immutable es256X;

    /// @notice P-256 public key y-coordinate for ES256 receipt verification.
    bytes32 public immutable es256Y;

    /// @notice The log ID of the root authority log.
    ///    Set on the first successful publishCheckpoint call
    ///    from the bootstrap authority; zero until then.
    bytes32 public rootLogId;

    mapping(bytes32 => LogState) private _logs;
    mapping(bytes32 => IUnivocity.LogConfig) private _logConfigs;

    // === Constructor ===

    /// @notice Deploys the Univocity transparency contract with bootstrap
    ///    authority and a single bootstrap key (alg + opaque bytes, same
    ///    pattern as rootKey / delegationKey). Plan 0018.
    /// @dev The bootstrap key (from _bootstrapAlg + _bootstrapKey) constrains
    ///    the **signer** of the root's first checkpoint: the consistency receipt
    ///    must be signed by that key (prevents front-running). Calling
    ///    publishCheckpoint is always permissionless (anyone with a valid grant
    ///    and validly signed checkpoint may submit; the caller pays gas).
    ///    _bootstrapAuthority is the address of that identity (emitted in
    ///    Initialized; not checked against msg.sender for publishCheckpoint).
    /// @param _bootstrapAuthority Address of the identity whose key must sign
    ///    the root's first checkpoint. Constrains the signer, not the caller.
    ///    Must not be zero.
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
        if (_bootstrapAlg != ALG_KS256 && _bootstrapAlg != ALG_ES256) {
            revert InvalidBootstrapAlgorithm(_bootstrapAlg);
        }
        if (_bootstrapAlg == ALG_KS256) {
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
            return (ALG_KS256, abi.encodePacked(ks256Signer));
        }
        return (ALG_ES256, abi.encodePacked(es256X, es256Y));
    }

    // === Modifiers ===

    modifier onlyBootstrap() {
        _onlyBootstrap();
        _;
    }

    function _onlyBootstrap() internal view {
        if (msg.sender != bootstrapAuthority) revert OnlyBootstrapAuthority();
    }

    // === View Functions ===

    /// @notice Returns the mutable state of a log (accumulator, size).
    function getLogState(bytes32 logId)
        external
        view
        returns (LogState memory)
    {
        return _logs[logId];
    }

    /// @notice Returns the immutable config of a log (kind, authLogId, rootKey, initializedAt).
    function getLogConfig(bytes32 logId)
        external
        view
        returns (IUnivocity.LogConfig memory)
    {
        return _logConfigs[logId];
    }

    /// @notice Returns the per-log root public key for delegation (ADR-0032).
    ///    ES256 only: 64-byte rootKey decoded to (x, y).
    function getLogRootKey(bytes32 logId)
        external
        view
        returns (bytes32 rootKeyX, bytes32 rootKeyY)
    {
        return _decodeLogRootKeyES256(logId);
    }

    /// @notice Set the root public key for a log (bootstrap only). Plan 0016:
    ///    root is never derived from a delegation cert. P-256 only: 64 bytes.
    /// @param logId The 32-byte log identifier.
    /// @param rootKey Opaque key; must be 64 bytes (P-256 x || y).
    function setLogRoot(bytes32 logId, bytes calldata rootKey) internal {
        if (rootKey.length != 64) {
            revert InvalidRootKeyLength(rootKey.length);
        }
        _logConfigs[logId].rootKey = rootKey;
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
    /// @dev Authorization: target = paymentGrant.logId. Root not yet set:
    ///   first checkpoint ever; grant = self-inclusion (index 0, path length
    ///   up to MAX_HEIGHT); receipt signer must match bootstrap key (rule 1).
    ///   First checkpoint to a new log: ownerLogId required; inclusion
    ///   verified against owner; kind from createAsAuthority (rule 2, 3).
    ///   Extend existing log: inclusion verified against config.authLogId
    ///   (rule 2). Grant bounds minGrowth, maxHeight checked (rule 4).
    function publishCheckpoint(
        IUnivocity.ConsistencyReceipt calldata consistencyParts,
        IUnivocity.InclusionProof calldata paymentInclusionProof,
        bytes8 paymentIDTimestampBe,
        IUnivocity.PaymentGrant calldata paymentGrant
    ) external {
        bytes32 logId = paymentGrant.logId;
        LogState storage log = _logs[logId];
        IUnivocity.LogConfig storage config = _logConfigs[logId];

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
        _checkPaymentGrantBoundsMaxHeight(claimedSize, paymentGrant);
        uint64 currentSize = log.size;
        if (claimedSize < currentSize + paymentGrant.minGrowth) {
            revert MinGrowthNotMet(
                currentSize, claimedSize, paymentGrant.minGrowth
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
            consistencyParts.delegationProof
        );

        // --- Grant / inclusion enforcement (rules 1, 2, 3) ---
        bytes32 authForInclusion = _verifyInclusionGrant(
            logId,
            claimedSize,
            paymentInclusionProof,
            paymentIDTimestampBe,
            paymentGrant,
            accMem
        );

        _updateLogState(
            logId,
            claimedSize,
            accMem,
            paymentGrant.payer,
            paymentInclusionProof.index,
            paymentInclusionProof.path,
            authForInclusion,
            paymentGrant.createAsAuthority,
            rootKeyToSet
        );
    }

    /// @notice Enforce grant/inclusion rules (1, 2, 3). Reverts on failure.
    /// @return authLogId Log against which inclusion was verified (bytes32(0)
    ///    when creating the root; rootLogId for root extension; owner for others).
    function _verifyInclusionGrant(
        bytes32 logId,
        uint64 claimedSize,
        IUnivocity.InclusionProof calldata paymentInclusionProof,
        bytes8 paymentIDTimestampBe,
        IUnivocity.PaymentGrant calldata paymentGrant,
        bytes32[] memory accMem
    ) internal returns (bytes32 authLogId) {
        IUnivocity.LogConfig storage config = _logConfigs[logId];
        bytes32 leafCommitment =
            _leafCommitment(paymentIDTimestampBe, paymentGrant);

        if (rootLogId == bytes32(0)) {
            // Rule 1: First checkpoint ever = root authority log. Grant is
            // inclusion proof against the first leaf (index 0) in the new tree.
            if (claimedSize < 1) revert FirstCheckpointSizeTooSmall();

            // Root's first checkpoint: grant is self-inclusion at index 0;
            // path may be any length up to MAX_HEIGHT (claimedSize >= 1).
            if (paymentInclusionProof.index != 0) {
                revert InvalidPaymentReceipt();
            }
            if (paymentInclusionProof.path.length > MAX_HEIGHT) {
                revert ProofPayloadExceedsMaxHeight();
            }
            if (!verifyInclusion(
                    0,
                    leafCommitment,
                    paymentInclusionProof.path,
                    accMem,
                    claimedSize
                )) {
                revert InvalidReceiptInclusionProof();
            }

            rootLogId = logId;
            // Emit contract's bootstrap identity and new root log id;
            // CheckpointPublished carries the actual sender.
            emit Initialized(bootstrapAuthority, logId);

            return bytes32(0);
        }
        // Root extension (after creation) and extend existing data/child log:
        // grant = inclusion proof against this log's authLogId (root = self).
        // First checkpoint to a non-root log (root already exists; this branch
        // cannot be reached for the root authority log). Resolve the log
        // against which we verify the grant (owner), then use the same
        // proof checks as for extending an existing log.
        bytes32 resolvedAuthLogId = config.initializedAt == 0
            ? paymentGrant.ownerLogId
            : config.authLogId;

        if (paymentGrant.ownerLogId == bytes32(0) && config.initializedAt == 0)
        {
            revert InvalidPaymentReceipt();
        }

        LogState storage ownerLog = _logs[resolvedAuthLogId];
        // Empty path is valid only when owner has size 1 and index 0 (peak =
        // leaf); e.g. when creating a child log and the owner has one leaf.
        if (paymentInclusionProof.path.length == 0) {
            if (!(ownerLog.size == 1 && paymentInclusionProof.index == 0)) {
                revert InvalidPaymentReceipt();
            }
        }
        if (paymentInclusionProof.path.length > MAX_HEIGHT) {
            revert ProofPayloadExceedsMaxHeight();
        }
        if (!verifyInclusion(
                paymentInclusionProof.index,
                leafCommitment,
                paymentInclusionProof.path,
                ownerLog.accumulator,
                ownerLog.size
            )) {
            revert InvalidPaymentReceipt();
        }
        return resolvedAuthLogId;
    }

    function _verifyCheckpointSignature(
        bytes32 logId,
        uint64 claimedSize,
        IUnivocity.ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        IUnivocity.LogConfig storage config,
        IUnivocity.DelegationProof calldata delegationProof
    ) internal view returns (bytes memory initialRoot) {
        // Rule 5: consistency receipt signature verification.
        // We distinguish (1) the log root key — authority for this log, recovered or from storage —
        // and (2) the verifier key — the key that must have signed the consistency receipt.
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
                delegationProof
            );
        }
        if (alg == ALG_KS256) {
            return _verifyCheckpointSignatureKS256(
                logId,
                claimedSize,
                consistencyParts,
                detachedPayload,
                config,
                delegationProof
            );
        }

        revert UnsupportedAlgorithm(alg);
    }

    function _verifyCheckpointSignatureES256(
        bytes32 logId,
        uint64 claimedSize,
        IUnivocity.ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        IUnivocity.LogConfig storage config,
        IUnivocity.DelegationProof calldata delegationProof
    ) internal view returns (bytes memory initialRoot) {
        // --- Verifier key: the key that must have signed the consistency receipt. ---
        // With delegation: delegate signed the receipt. Without: root signed the receipt.
        (bytes32 rootX, bytes32 rootY, bytes32 verifierX, bytes32 verifierY) = _checkpointSignersES256(
            logId,
            claimedSize,
            consistencyParts,
            detachedPayload,
            config,
            delegationProof
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
        // Persist the log root key for new logs so future checkpoints can verify against it.
        if (config.initializedAt == 0) {
            // Root's first checkpoint has no grant-based protection; require
            // recovered signer to match bootstrap key to prevent front-running.
            if (
                rootLogId == bytes32(0) && (rootX != es256X || rootY != es256Y)
            ) {
                revert RootSignerMustMatchBootstrap();
            }
            return abi.encodePacked(rootX, rootY);
        }
        return new bytes(0);
    }

    function _verifyCheckpointSignatureKS256(
        bytes32 logId,
        uint64,
        /* claimedSize */
        IUnivocity.ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        IUnivocity.LogConfig storage config,
        IUnivocity.DelegationProof calldata delegationProof
    ) internal view returns (bytes memory initialRoot) {
        // KS256: no delegation support. Verifier key is root (bootstrap for root log) or stored log key.
        if (delegationProof.signature.length > 0) {
            revert DelegationUnsupportedForAlg(ALG_KS256);
        }
        bool isFirstCheckpointKs = config.initializedAt == 0;
        address keyAddr = (rootLogId == bytes32(0) || logId == rootLogId)
            ? ks256Signer
            : _decodeLogRootKeyKS256(logId);
        if (keyAddr == address(0)) {
            // Distinguish missing key from algorithm mismatch (log created
            // under ES256 has rootKey.length == 64): receipt is KS256, log is ES256.
            if (config.rootKey.length == 64) {
                revert InconsistentReceiptSignature(ALG_KS256, ALG_ES256);
            }
            if (!isFirstCheckpointKs) revert LogRootKeyNotSet();
            keyAddr = ks256Signer;
        }
        if (!verifyKS256DetachedPayload(
                consistencyParts.protectedHeader,
                consistencyParts.signature,
                detachedPayload,
                keyAddr
            )) {
            revert ConsistencyReceiptSignatureInvalid();
        }
        // Persist the log root key for new logs so future checkpoints can verify against it.
        if (config.initializedAt == 0) {
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
        IUnivocity.ConsistencyReceipt calldata consistencyParts,
        bytes memory detachedPayload,
        IUnivocity.LogConfig storage config,
        IUnivocity.DelegationProof calldata delegationProof
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
        // Root key from storage, or recover from receipt/delegation on first
        // checkpoint. Caller enforces for the root's first checkpoint that the
        // recovered signer matches the bootstrap key (no grant-based protection).
        (rootX, rootY) = _decodeLogRootKeyES256(logId);

        if (rootX == bytes32(0) && rootY == bytes32(0)) {
            // Distinguish unset key from key-type mismatch (log created under
            // KS256 has rootKey.length == 20): receipt is ES256, log is KS256.
            if (config.rootKey.length == 20) {
                revert InconsistentReceiptSignature(ALG_ES256, ALG_KS256);
            }
            if (config.initializedAt != 0) revert LogRootKeyNotSet();

            if (delegationProof.signature.length == 0) {
                // No delegation. Root signed the receipt; recover root from receipt signature.
                (rootX, rootY) = recoverES256FromDetachedPayload(
                    consistencyParts.protectedHeader,
                    detachedPayload,
                    consistencyParts.signature
                );
                if (rootX == bytes32(0) && rootY == bytes32(0)) {
                    revert ConsistencyReceiptSignatureInvalid();
                }
                return (rootX, rootY, rootX, rootY);
            }

            // Delegation present. Decode delegate (needed for recovery message
            // hash); recover root from delegation signature; fall through to
            // shared verify + return below.
            (verifierX, verifierY) =
                decodeDelegationKeyES256(delegationProof.delegationKey);
            (rootX, rootY) = recoverDelegationSignerES256(
                logId,
                delegationProof.mmrStart,
                delegationProof.mmrEnd,
                verifierX,
                verifierY,
                delegationProof.signature
            );
            if (rootX == bytes32(0) && rootY == bytes32(0)) {
                revert DelegationSignatureInvalid();
            }
        }

        // Root key present (from storage or just recovered). Verifier is
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
                g.minGrowth,
                g.ownerLogId,
                g.createAsAuthority
            )
        );
        return sha256(abi.encodePacked(paymentIDTimestampBe, inner));
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
    /// @param rootKeyToSet When isNewLog and length 64 (ES256) or 20 (KS256),
    ///    set as log root key.
    function _updateLogState(
        bytes32 logId,
        uint64 size,
        bytes32[] memory accumulator,
        address payer,
        uint64 paymentIndex,
        bytes32[] calldata paymentPath,
        bytes32 authorityLogIdUsed,
        bool createAsAuthority,
        bytes memory rootKeyToSet
    ) private {
        LogState storage log = _logs[logId];
        IUnivocity.LogConfig storage config = _logConfigs[logId];
        bool isNewLog = config.initializedAt == 0;

        if (isNewLog) {
            config.initializedAt = block.number;
            if (logId == rootLogId) {
                config.kind = IUnivocity.LogKind.Authority;
                config.authLogId = logId; // root's parent is self (ADR-0004)
            }
            if (rootKeyToSet.length == 64 || rootKeyToSet.length == 20) {
                config.rootKey = rootKeyToSet;
            }
            if (logId != rootLogId) {
                config.kind = createAsAuthority
                    ? IUnivocity.LogKind.Authority
                    : IUnivocity.LogKind.Data;
                config.authLogId = authorityLogIdUsed;
            }
            emit LogRegistered(logId, _msgSender(), size);
        }

        delete log.accumulator;
        for (uint256 i = 0; i < accumulator.length; i++) {
            log.accumulator.push(accumulator[i]);
        }

        log.size = size;

        emit CheckpointPublished(
            logId,
            _msgSender(),
            payer,
            uint8(config.kind),
            size,
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
