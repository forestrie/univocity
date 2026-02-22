// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocityEvents} from "./IUnivocityEvents.sol";

/// @title IUnivocity
/// @notice Interface for univocity transparency log contract with R5
///    authorization
interface IUnivocity is IUnivocityEvents {
    struct LogState {
        bytes32[] accumulator;
        uint64 size;
        uint64 checkpointCount;
        uint256 initializedAt;
        /// @dev Root public key (P-256) for delegation cert verification.
        ///    Zero until the log's first checkpoint with checkpoint COSE.
        bytes32 rootKeyX;
        bytes32 rootKeyY;
    }

    /// @notice Caller-supplied payment grant for leaf commitment and bounds.
    ///    Leaf = SHA256(paymentIDTimestampBe || SHA256(logId||payer||
    ///    checkpointStart||checkpointEnd||maxHeight||minGrowth)). Plan 0015.
    struct PaymentGrant {
        bytes32 logId;
        address payer;
        uint64 checkpointStart;
        uint64 checkpointEnd;
        uint64 maxHeight;
        uint64 minGrowth;
    }

    // === View Functions ===

    function bootstrapAuthority() external view returns (address);
    function authorityLogId() external view returns (bytes32);
    function getLogState(bytes32 logId) external view returns (LogState memory);
    function getLogRootKey(bytes32 logId)
        external
        view
        returns (bytes32 rootKeyX, bytes32 rootKeyY);
    function isLogInitialized(bytes32 logId) external view returns (bool);

    // === State-Changing Functions ===

    /// @notice Publish a checkpoint from a consistency receipt and a payment
    ///    receipt (COSE Receipt of Inclusion). Plan 0014/0015. The log to
    ///    checkpoint is paymentGrant.logId. Delegation (root key) is optional
    ///    via consistency receipt unprotected label 1000.
    /// @param consistencyReceipt COSE Receipt of Consistency (MMR profile);
    ///    may include optional delegation cert at unprotected 1000.
    /// @param paymentReceipt COSE Receipt of Inclusion proving payment leaf
    ///    is in the authority log.
    /// @param paymentIDTimestampBe Big-endian idtimestamp of included content.
    /// @param paymentGrant LogId, payer, checkpoint range, max_height,
    ///    min_growth for leaf commitment and bounds.
    function publishCheckpoint(
        bytes calldata consistencyReceipt,
        bytes calldata paymentReceipt,
        bytes8 paymentIDTimestampBe,
        PaymentGrant calldata paymentGrant
    ) external;
}
