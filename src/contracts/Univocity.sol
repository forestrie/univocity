// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";
import {
    LibCheckpointVerifier
} from "@univocity/checkpoints/lib/LibCheckpointVerifier.sol";
import {
    LibAuthorityVerifier
} from "@univocity/checkpoints/lib/LibAuthorityVerifier.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {
    LibDelegationVerifier
} from "@univocity/checkpoints/lib/LibDelegationVerifier.sol";
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
    /// @dev Used by LibAuthorityVerifier and LibCose for KS256 (ecrecover) and
    ///    ES256 (P-256)
    ///    verification.
    /// @return A struct containing ks256Signer, es256X,
    ///    and es256Y (as in the constructor).
    function getBootstrapKeys()
        public
        view
        returns (LibCose.BootstrapKeys memory)
    {
        return LibCose.BootstrapKeys({
            ks256Signer: ks256Signer, es256X: es256X, es256Y: es256Y
        });
    }

    // === Modifiers ===

    modifier onlyBootstrap() {
        if (msg.sender != bootstrapAuthority) revert OnlyBootstrapAuthority();
        _;
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

    /// @notice Returns the per-log root public key for delegation cert
    ///    verification (ADR-0032).
    /// @param logId The 32-byte log identifier.
    /// @return rootKeyX P-256 x-coordinate; zero if root not yet established.
    /// @return rootKeyY P-256 y-coordinate; zero if root not yet established.
    function getLogRootKey(bytes32 logId)
        external
        view
        returns (bytes32 rootKeyX, bytes32 rootKeyY)
    {
        LogState storage log = _logs[logId];
        return (log.rootKeyX, log.rootKeyY);
    }

    /// @notice Returns whether a log has received at least one checkpoint.
    /// @param logId The 32-byte log identifier.
    /// @return True if the log has been initialized (first checkpoint
    ///    published), false otherwise.
    function isLogInitialized(bytes32 logId) external view returns (bool) {
        return _logs[logId].initializedAt != 0;
    }

    // === Checkpoint Publishing ===

    /// @notice Publishes a checkpoint for a transparency log,
    ///    updating the stored MMR state.
    /// @dev First checkpoint (establishing the authority log) requires size >=
    ///    1, a SCITT receipt signed by the bootstrap authority,
    ///    and proof that the receipt hash is at leaf index 0
    ///    in the submitted accumulator (so the bootstrap receipt is always
    ///    the first entry in the authority log).
    ///    Authority-log and regular-log semantics unchanged; see ADR-0029.
    /// @param logId Identifier of the log to checkpoint (e.g.
    ///    keccak256 of log config).
    /// @param size MMR leaf count at this checkpoint (must be greater than the
    ///    log's current size).
    /// @param accumulator MMR peak hashes for this size;
    ///    length must equal peaks(size - 1).length.
    /// @param receipt COSE_Sign1 SCITT receipt.
    ///    First checkpoint: must be signed by bootstrap and
    ///    provably at leaf index 0 in the new accumulator.
    ///    Authority log: signed by bootstrap.
    ///    Other logs:
    ///    payment receipt plus inclusion proof in authority log.
    /// @param proofAndCose Bundled: consistencyProof, receiptMmrIndex,
    ///    receiptInclusionProof, receiptIdtimestampBe (ADR-0030 leaf), and
    ///    checkpointCoseSign1 (ADR-0032; empty to skip). Avoids stack-too-deep.
    /// @custom:throws FirstCheckpointSizeTooSmall If establishing the
    /// authority log with size < 1.
    /// @custom:throws OnlyBootstrapAuthority If first checkpoint has no
    /// receipt, or authority log
    /// has no receipt.
    /// @custom:throws BootstrapReceiptMustBeFirstEntry If first checkpoint has
    /// receiptMmrIndex !=
    /// 0.
    /// @custom:throws SizeMustIncrease If size is not greater than the log's
    /// current size.
    /// @custom:throws InvalidAccumulatorLength If accumulator length does not
    /// match the peak count
    /// for size.
    /// @custom:throws InvalidConsistencyProof If consistency proof does not
    /// prove the new
    /// accumulator.
    /// @custom:throws ReceiptLogIdMismatch If receipt targets a different log.
    /// @custom:throws CheckpointCountExceeded If checkpoint count is outside
    /// the receipt's range.
    /// @custom:throws MaxHeightExceeded If size exceeds the receipt's
    /// maxHeight.
    /// @custom:throws InvalidReceiptInclusionProof If the receipt is not
    /// included in the authority
    /// log.
    function publishCheckpoint(
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt,
        IUnivocity.ProofAndCoseCalldata calldata proofAndCose
    ) external {
        if (proofAndCose.checkpointCoseSign1.length > 0) {
            _verifyAndStoreCheckpointCose(
                proofAndCose.checkpointCoseSign1,
                logId,
                size,
                accumulator,
                _logs[logId]
            );
        }

        // === Not yet initialized: first checkpoint;
        // bootstrap receipt must be first entry in new
        // accumulator ===
        if (authorityLogId == bytes32(0)) {
            if (size < 1) revert FirstCheckpointSizeTooSmall();
            if (receipt.length == 0) revert OnlyBootstrapAuthority();
            if (proofAndCose.receiptMmrIndex != 0) {
                revert BootstrapReceiptMustBeFirstEntry();
            }
            _verifyBootstrapReceipt(logId, 0, size, receipt);
            // Leaf = H(receiptIdtimestampBe ‖ sha256(receipt)) per ADR-0030
            bytes32 leafHash = sha256(
                abi.encodePacked(
                    proofAndCose.receiptIdtimestampBe, sha256(receipt)
                )
            );
            bytes32[] memory acc = accumulator;
            if (!LibAuthorityVerifier.verifyReceiptInclusion(
                    leafHash,
                    proofAndCose.receiptInclusionProof,
                    acc,
                    0
                )) {
                revert InvalidReceiptInclusionProof();
            }
            _initializeAuthorityLog(logId);
        }

        LogState storage log = _logs[logId];

        // === Validation ===
        _validateCheckpoint(log, size, accumulator);

        // === Authorization ===
        _checkAuthorization(
            logId,
            log,
            size,
            receipt,
            proofAndCose.receiptMmrIndex,
            proofAndCose.receiptInclusionProof,
            proofAndCose.receiptIdtimestampBe
        );

        // === Consistency Verification ===
        if (log.initializedAt != 0) {
            if (!LibCheckpointVerifier.verifyConsistencyProof(
                    log.accumulator,
                    accumulator,
                    log.size,
                    proofAndCose.consistencyProof
                )) {
                revert InvalidConsistencyProof();
            }
        }

        // === State Update ===
        _updateLogState(logId, log, size, accumulator, receipt);
    }

    /// @notice ADR-0032: verify checkpoint COSE and delegation; store root when
    ///    first checkpoint for this log (plan 0013).
    function _verifyAndStoreCheckpointCose(
        bytes calldata checkpointCoseSign1,
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        LogState storage log
    ) private {
        (bytes32 rootX, bytes32 rootY) =
            LibDelegationVerifier.verifyCheckpointCoseAndDelegation(
                checkpointCoseSign1,
                logId,
                size,
                accumulator,
                log.rootKeyX,
                log.rootKeyY
            );
        if (log.rootKeyX == 0 && log.rootKeyY == 0) {
            log.rootKeyX = rootX;
            log.rootKeyY = rootY;
        }
    }

    function _validateCheckpoint(
        LogState storage log,
        uint64 size,
        bytes32[] calldata accumulator
    ) private view {
        // Size must increase (or be initial)
        if (log.initializedAt != 0 && size <= log.size) {
            revert SizeMustIncrease(log.size, size);
        }

        // Validate accumulator length matches expected peaks for size (per MMR
        // profile)
        uint256 expectedPeaks = size == 0 ? 0 : peaks(uint256(size) - 1).length;
        if (accumulator.length != expectedPeaks) {
            revert InvalidAccumulatorLength(expectedPeaks, accumulator.length);
        }
    }

    function _checkAuthorization(
        bytes32 logId,
        LogState storage log,
        uint64 size,
        bytes calldata receipt,
        uint64 receiptMmrIndex,
        bytes32[] calldata receiptInclusionProof,
        bytes8 receiptIdtimestampBe
    ) private {
        if (logId == authorityLogId) {
            // Authority log: SCITT receipt signed by bootstrap;
            // no inclusion proof (receipt need
            // not be in the log)
            if (receipt.length == 0) revert OnlyBootstrapAuthority();
            _verifyBootstrapReceipt(logId, log.checkpointCount, size, receipt);
        } else {
            // Regular log:
            // payment receipt plus inclusion proof in authority log
            _verifyAuthorization(
                logId,
                log.checkpointCount,
                size,
                receipt,
                receiptMmrIndex,
                receiptInclusionProof,
                receiptIdtimestampBe
            );
        }
    }

    /// @notice Verifies a SCITT receipt with the given keys and checks bounds;
    ///    reverts with a typed
    ///    error on failure.
    /// @dev Generic receipt verification: signature + decode with `keys`, then
    ///    logId/checkpoint/height bounds.
    ///    Used for both bootstrap (authority) and regular-log flows;
    ///    caller adds inclusion proof
    ///    check if needed.
    /// @param logId Log being checkpointed (must match receipt targetLogId).
    /// @param checkpointCount Current checkpoint count for the log.
    /// @param size Proposed checkpoint size (must be within receipt maxHeight
    ///    if set).
    /// @param receipt COSE_Sign1 SCITT receipt (payment claims).
    /// @param keys Bootstrap keys used to verify the receipt signature (e.g.
    ///    getBootstrapKeys()).
    /// @return claims Decoded payment claims on success.
    function _verifyReceiptAndCheckBounds(
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size,
        bytes calldata receipt,
        LibCose.BootstrapKeys memory keys
    ) private returns (LibAuthorityVerifier.PaymentClaims memory claims) {
        claims = LibAuthorityVerifier.verifyAndDecode(receipt, keys);

        if (claims.targetLogId != logId) {
            emit AuthorizationFailed(logId, claims.payer, "logId mismatch");
            revert ReceiptLogIdMismatch(logId, claims.targetLogId);
        }

        if (checkpointCount < claims.checkpointStart) {
            emit AuthorizationFailed(logId, claims.payer, "below range start");
            revert CheckpointCountExceeded(
                checkpointCount, claims.checkpointStart
            );
        }

        if (checkpointCount >= claims.checkpointEnd) {
            emit AuthorizationFailed(logId, claims.payer, "above range end");
            revert CheckpointCountExceeded(
                checkpointCount, claims.checkpointEnd
            );
        }

        if (claims.maxHeight != 0 && size > claims.maxHeight) {
            emit AuthorizationFailed(logId, claims.payer, "height exceeded");
            revert MaxHeightExceeded(size, claims.maxHeight);
        }

        return claims;
    }

    /// @notice Verifies that the receipt is signed by the bootstrap keys and
    ///    authorizes this
    ///    checkpoint.
    /// @dev Used for the first checkpoint (establishing authority log) and for
    ///    publishing to the
    ///    authority log.
    ///    Delegates to _verifyReceiptAndCheckBounds with getBootstrapKeys();
    ///    no inclusion proof.
    function _verifyBootstrapReceipt(
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size,
        bytes calldata receipt
    ) private {
        LibAuthorityVerifier.PaymentClaims memory
            claims =
            _verifyReceiptAndCheckBounds(
                logId, checkpointCount, size, receipt, getBootstrapKeys()
            );
        emit CheckpointAuthorized(
            logId,
            claims.payer,
            claims.checkpointStart,
            claims.checkpointEnd,
            claims.maxHeight
        );
    }

    function _updateLogState(
        bytes32 logId,
        LogState storage log,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt
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
            logId, size, log.checkpointCount, accumulator, receipt
        );
    }

    // === Internal Functions ===

    /// @notice Verify R5 authorization using SCITT receipt (signature + bounds
    ///    + inclusion in
    ///    authority log).
    /// @dev Uses _verifyReceiptAndCheckBounds with getBootstrapKeys(),
    ///    then verifies receipt
    ///    inclusion.
    ///    Leaf = H(receiptIdtimestampBe ‖ sha256(receipt)) per ADR-0030.
    function _verifyAuthorization(
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size,
        bytes calldata receipt,
        uint64 receiptMmrIndex,
        bytes32[] calldata receiptInclusionProof,
        bytes8 receiptIdtimestampBe
    ) internal {
        LibAuthorityVerifier.PaymentClaims memory
            claims =
            _verifyReceiptAndCheckBounds(
                logId, checkpointCount, size, receipt, getBootstrapKeys()
            );

        LogState storage authorityLog = _logs[authorityLogId];
        bytes32 leafHash =
            sha256(abi.encodePacked(receiptIdtimestampBe, sha256(receipt)));
        bool included = LibAuthorityVerifier.verifyReceiptInclusion(
            leafHash,
            receiptInclusionProof,
            authorityLog.accumulator,
            receiptMmrIndex
        );
        if (!included) {
            emit AuthorizationFailed(logId, claims.payer, "inclusion failed");
            revert InvalidReceiptInclusionProof();
        }

        emit CheckpointAuthorized(
            logId,
            claims.payer,
            claims.checkpointStart,
            claims.checkpointEnd,
            claims.maxHeight
        );
    }
}
