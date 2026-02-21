// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../checkpoints/interfaces/IUnivocity.sol";
import "../checkpoints/interfaces/IUnivocityErrors.sol";
import "../checkpoints/lib/LibCheckpointVerifier.sol";
import "../checkpoints/lib/LibAuthorityVerifier.sol";
import "../cose/lib/LibCose.sol";

/// @title Univocity
/// @notice Multi-log transparency contract with R5 payment-bounded authorization
/// @dev Implements permissionless checkpoint submission with SCITT-format receipts
contract Univocity is IUnivocity, IUnivocityErrors {
    // === State ===

    address public immutable bootstrapAuthority;

    // Bootstrap keys for dual-algorithm COSE signature verification
    address public immutable ks256Signer;
    bytes32 public immutable es256X;
    bytes32 public immutable es256Y;

    bytes32 public authorityLogId;
    bool private _initialized;

    mapping(bytes32 => LogState) private _logs;

    // === Constructor ===

    /// @notice Deploy Univocity with bootstrap authority keys
    /// @param _bootstrapAuthority Address for msg.sender access control
    /// @param _ks256Signer Ethereum address for KS256 signature verification
    /// @param _es256X P-256 public key x-coordinate for ES256 verification
    /// @param _es256Y P-256 public key y-coordinate for ES256 verification
    constructor(address _bootstrapAuthority, address _ks256Signer, bytes32 _es256X, bytes32 _es256Y) {
        if (_bootstrapAuthority == address(0)) revert OnlyBootstrapAuthority();
        // At least one signing key must be set
        if (_ks256Signer == address(0) && _es256X == bytes32(0)) {
            revert OnlyBootstrapAuthority();
        }

        bootstrapAuthority = _bootstrapAuthority;
        ks256Signer = _ks256Signer;
        es256X = _es256X;
        es256Y = _es256Y;
    }

    /// @notice Get bootstrap keys for signature verification
    function getBootstrapKeys() public view returns (LibCose.BootstrapKeys memory) {
        return LibCose.BootstrapKeys({ks256Signer: ks256Signer, es256X: es256X, es256Y: es256Y});
    }

    // === Modifiers ===

    modifier onlyBootstrap() {
        if (msg.sender != bootstrapAuthority) revert OnlyBootstrapAuthority();
        _;
    }

    modifier whenInitialized() {
        if (!_initialized) revert NotInitialized();
        _;
    }

    // === Initialization ===

    function initialize(bytes32 _authorityLogId) external onlyBootstrap {
        if (_initialized) revert AlreadyInitialized();

        authorityLogId = _authorityLogId;
        _initialized = true;

        emit Initialized(bootstrapAuthority, _authorityLogId);
    }

    // === View Functions ===

    function getLogState(bytes32 logId) external view returns (LogState memory) {
        return _logs[logId];
    }

    function isLogInitialized(bytes32 logId) external view returns (bool) {
        return _logs[logId].initializedAt != 0;
    }

    // === Checkpoint Publishing ===

    function publishCheckpoint(
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt,
        bytes calldata consistencyProof,
        bytes calldata receiptInclusionProof
    ) external whenInitialized {
        LogState storage log = _logs[logId];

        // === Validation ===
        _validateCheckpoint(log, size, accumulator);

        // === Authorization ===
        _checkAuthorization(logId, log, size, receipt, receiptInclusionProof);

        // === Consistency Verification ===
        if (log.initializedAt != 0) {
            if (!LibCheckpointVerifier.verifyConsistencyProof(log.accumulator, accumulator, log.size, consistencyProof))
            {
                revert InvalidConsistencyProof();
            }
        }

        // === State Update ===
        _updateLogState(logId, log, size, accumulator, receipt);
    }

    function _validateCheckpoint(LogState storage log, uint64 size, bytes32[] calldata accumulator) private view {
        // Size must increase (or be initial)
        if (log.initializedAt != 0 && size <= log.size) {
            revert SizeMustIncrease(log.size, size);
        }

        // Validate accumulator length matches expected peaks for size
        uint256 expectedPeaks = _countPeaks(size);
        if (accumulator.length != expectedPeaks) {
            revert InvalidAccumulatorLength(expectedPeaks, accumulator.length);
        }
    }

    function _checkAuthorization(
        bytes32 logId,
        LogState storage log,
        uint64 size,
        bytes calldata receipt,
        bytes calldata receiptInclusionProof
    ) private {
        bool isBootstrap = msg.sender == bootstrapAuthority;

        if (logId == authorityLogId) {
            // Authority log: only bootstrap can publish
            if (!isBootstrap) revert OnlyBootstrapAuthority();
        } else if (!isBootstrap) {
            // Regular log, non-bootstrap: verify R5 receipt
            _verifyAuthorization(logId, log.checkpointCount, size, receipt, receiptInclusionProof);
        }
        // Bootstrap can publish to any log without receipt
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

        emit CheckpointPublished(logId, size, log.checkpointCount, accumulator, receipt);
    }

    // === Internal Functions ===

    /// @notice Verify R5 authorization using SCITT receipt
    /// @dev IMPORTANT: msg.sender is NOT checked against claims.payer.
    ///      Submission is permissionless given valid signature + receipt.
    ///      The payer claim identifies who PAID, not who may SUBMIT.
    /// @dev Receipt is standard COSE_Sign1 with CBOR payload (SCITT format).
    function _verifyAuthorization(
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size,
        bytes calldata receipt,
        bytes calldata inclusionProof
    ) internal {
        // 1. Verify signature and decode SCITT receipt (COSE_Sign1)
        //    This confirms the receipt was signed by bootstrap authority
        //    Supports both ES256 (passkeys) and KS256 (Ethereum native)
        LibAuthorityVerifier.PaymentClaims memory claims =
            LibAuthorityVerifier.verifyAndDecode(receipt, getBootstrapKeys());

        // NOTE: We do NOT check msg.sender == claims.payer
        // Submission is permissionless. The receipt authorizes the CHECKPOINT,
        // not the SUBMITTER. Anyone can be the courier.

        // 2. Pre-check bounds (cheap, before expensive inclusion proof)
        if (claims.targetLogId != logId) {
            emit AuthorizationFailed(logId, claims.payer, "logId mismatch");
            revert ReceiptLogIdMismatch(logId, claims.targetLogId);
        }

        if (checkpointCount < claims.checkpointStart) {
            emit AuthorizationFailed(logId, claims.payer, "below range start");
            revert CheckpointCountExceeded(checkpointCount, claims.checkpointStart);
        }

        if (checkpointCount >= claims.checkpointEnd) {
            emit AuthorizationFailed(logId, claims.payer, "above range end");
            revert CheckpointCountExceeded(checkpointCount, claims.checkpointEnd);
        }

        // Check maxHeight (0 = unlimited)
        if (claims.maxHeight != 0 && size > claims.maxHeight) {
            emit AuthorizationFailed(logId, claims.payer, "height exceeded");
            revert MaxHeightExceeded(size, claims.maxHeight);
        }

        // 3. Verify receipt inclusion in authority log (expensive, do last)
        LogState storage authorityLog = _logs[authorityLogId];
        bytes32 receiptHash = keccak256(receipt);

        // Parse inclusion proof
        (uint64 leafIndex, bytes32[] memory proofPath) = _parseInclusionProof(inclusionProof);

        bool included =
            LibAuthorityVerifier.verifyReceiptInclusion(receiptHash, proofPath, authorityLog.accumulator, leafIndex);

        if (!included) {
            emit AuthorizationFailed(logId, claims.payer, "inclusion failed");
            revert InvalidReceiptInclusionProof();
        }

        // 4. Emit authorization event (payer = who paid, not msg.sender)
        emit CheckpointAuthorized(logId, claims.payer, claims.checkpointStart, claims.checkpointEnd, claims.maxHeight);
    }

    /// @notice Parse inclusion proof from bytes to bytes32 array
    /// @dev The proof format: uint64 leafIndex (8 bytes) + concatenated bytes32 path elements
    function _parseInclusionProof(bytes calldata proof)
        internal
        pure
        returns (uint64 leafIndex, bytes32[] memory path)
    {
        if (proof.length < 8) {
            return (0, new bytes32[](0));
        }

        // Extract leaf index from first 8 bytes
        leafIndex = uint64(bytes8(proof[0:8]));

        // Remaining bytes are the path (each element is 32 bytes)
        uint256 pathLength = (proof.length - 8) / 32;
        path = new bytes32[](pathLength);

        for (uint256 i = 0; i < pathLength; i++) {
            uint256 start = 8 + (i * 32);
            path[i] = bytes32(proof[start:start + 32]);
        }
    }

    function _countPeaks(uint64 size) internal pure returns (uint256) {
        // Number of peaks = number of 1-bits in binary representation
        uint256 count = 0;
        uint64 s = size;
        while (s > 0) {
            count += s & 1;
            s >>= 1;
        }
        return count;
    }
}
