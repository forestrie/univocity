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
        /// @dev Root public key: alg-specific opaque bytes. P-256/ES256 =
        ///    64 bytes (x || y). Set by bootstrap via setLogRoot (plan 0016).
        ///    Decoded once per publishCheckpoint when needed.
        bytes rootKey;
    }

    /// @notice Pre-decoded consistency proof payload (MMR profile). One
    ///    element per consistency proof; no CBOR decode on-chain.
    struct ConsistencyProof {
        uint64 treeSize1;
        uint64 treeSize2;
        bytes32[][] paths;
        bytes32[] rightPeaks;
    }

    /// @notice Pre-decoded inclusion proof (index + path). Empty path means
    ///    no payment proof.
    struct InclusionProof {
        uint64 index;
        bytes32[] path;
    }

    /// @notice Pre-decoded consistency receipt (plan 0016). No COSE envelope
    ///    parse on-chain. Consistency proofs are pre-decoded (no CBOR).
    struct ConsistencyReceipt {
        bytes protectedHeader;
        bytes signature;
        ConsistencyProof[] consistencyProofs;
        DelegationProof delegationProof;
    }

    /// @notice Minimal delegation proof (plan 0016). No cert decode.
    ///    delegationKey is alg-specific opaque bytes; for P-256/ES256 it is
    ///    64 bytes (x || y). Decoding requires alg == P-256/ES256.
    struct DelegationProof {
        bytes delegationKey;
        uint64 mmrStart;
        uint64 mmrEnd;
        uint64 alg;
        bytes signature;
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

    /// @notice Set the root public key for a log (bootstrap only). Plan 0016.
    ///    rootKey must be 64 bytes (P-256 x || y) for the only supported alg.
    function setLogRoot(bytes32 logId, bytes calldata rootKey) external;

    /// @notice Publish a checkpoint from pre-decoded consistency receipt and
    ///    optional pre-decoded inclusion proof (plan 0016).
    /// @param consistencyParts Pre-decoded (protectedHeader, signature,
    ///    consistencyProofs, delegationProof). No COSE/CBOR parse.
    /// @param paymentInclusionProof Pre-decoded (index, path). path.length == 0
    ///    when not required (bootstrap or authority log).
    /// @param paymentIDTimestampBe Big-endian idtimestamp of included content.
    /// @param paymentGrant LogId, payer, checkpoint range, max_height,
    ///    min_growth for leaf commitment and bounds.
    function publishCheckpoint(
        ConsistencyReceipt calldata consistencyParts,
        InclusionProof calldata paymentInclusionProof,
        bytes8 paymentIDTimestampBe,
        PaymentGrant calldata paymentGrant
    ) external;
}
