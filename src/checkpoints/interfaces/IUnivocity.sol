// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocityEvents} from "./IUnivocityEvents.sol";

/// @title IUnivocity
/// @notice Interface for univocity transparency log contract (payment-bounded
///    checkpoint authorization via grant inclusion proof and bounds).
interface IUnivocity is IUnivocityEvents {
    /// @notice Log role in the hierarchy (ARC-0017). 0 = not set.
    enum LogKind {
        Authority,
        Data
    }

    /// @notice Immutable per-log config (set at first checkpoint).
    struct LogConfig {
        LogKind kind;
        bytes32 authLogId;
        bytes rootKey;
        uint256 initializedAt;
    }

    /// @notice Mutable log state only (config in separate mapping).
    struct LogState {
        bytes32[] accumulator;
        uint64 size;
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
    ///    Leaf inner hash includes logId, payer, checkpointStart, checkpointEnd,
    ///    maxHeight, minGrowth, ownerLogId, createAsAuthority (ARC-0017 Phase 0).
    ///    ownerLogId = owning auth for data log creation, parent for authority creation.
    struct PaymentGrant {
        bytes32 logId;
        address payer;
        uint64 checkpointStart;
        uint64 checkpointEnd;
        uint64 maxHeight;
        uint64 minGrowth;
        bytes32 ownerLogId;
        bool createAsAuthority;
    }

    // === View Functions ===

    function bootstrapAuthority() external view returns (address);
    /// @notice Bootstrap key in opaque form (same as constructor). Plan 0018.
    /// @return bootstrapAlg COSE alg (ALG_KS256 or ALG_ES256).
    /// @return bootstrapKey 20 bytes (KS256) or 64 bytes (ES256).
    function getBootstrapKeyConfig()
        external
        view
        returns (int64 bootstrapAlg, bytes memory bootstrapKey);
    function authorityLogId() external view returns (bytes32);
    function getLogState(bytes32 logId) external view returns (LogState memory);
    function getLogConfig(bytes32 logId) external view returns (LogConfig memory);
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
    /// @param paymentGrant LogId, payer (who paid; any sender may submit),
    ///    checkpoint range, max_height, min_growth for leaf commitment and
    ///    bounds.
    function publishCheckpoint(
        ConsistencyReceipt calldata consistencyParts,
        InclusionProof calldata paymentInclusionProof,
        bytes8 paymentIDTimestampBe,
        PaymentGrant calldata paymentGrant
    ) external;
}
