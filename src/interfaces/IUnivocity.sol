// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocityEvents} from "./IUnivocityEvents.sol";

/// @title IUnivocity
/// @notice Interface for univocity transparency log contract (payment-bounded
///    checkpoint authorization via grant inclusion proof and bounds).
interface IUnivocity is IUnivocityEvents {
    /// @notice Log role in the hierarchy (ARC-0017). 0 = not set (uninitialized).
    enum LogKind {
        Undefined,
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

    /// @notice Caller-supplied publish grant for leaf commitment and bounds.
    ///    grant (in commitment): GF_CREATE (1<<32), GF_EXTEND (1<<33),
    ///    GF_AUTH_LOG (1), GF_DATA_LOG (2). request is NOT in the commitment;
    ///    high 32 bits = GC_AUTH_LOG or GC_DATA_LOG (mutually exclusive), must
    ///    be allowed by grant. Log kind for new logs is set from request.
    ///    Leaf inner hash: logId, grant, maxHeight, minGrowth, ownerLogId,
    ///    grantData (no request). First checkpoint: grantData supplies the
    ///    signer (root) key; receipt verified against it (verify-only; no
    ///    on-chain recovery).
    struct PublishGrant {
        bytes32 logId;
        uint256 grant;
        uint256 request;
        uint64 maxHeight;
        uint64 minGrowth;
        bytes32 ownerLogId;
        bytes grantData;
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
    function rootLogId() external view returns (bytes32);
    function getLogState(bytes32 logId) external view returns (LogState memory);
    function getLogConfig(bytes32 logId)
        external
        view
        returns (LogConfig memory);
    function getLogRootKey(bytes32 logId)
        external
        view
        returns (bytes32 rootKeyX, bytes32 rootKeyY);
    function isLogInitialized(bytes32 logId) external view returns (bool);

    // === State-Changing Functions ===

    /// @notice Publish a checkpoint from pre-decoded consistency receipt and
    ///    optional pre-decoded inclusion proof (plan 0016).
    /// @param consistencyParts Pre-decoded (protectedHeader, signature,
    ///    consistencyProofs, delegationProof). No COSE/CBOR parse.
    /// @param grantInclusionProof Pre-decoded (index, path). Root's first
    ///    checkpoint: index 0, path length up to MAX_HEIGHT. Other checkpoints:
    ///    inclusion in grant's owner (path length up to MAX_HEIGHT).
    /// @param grantIDTimestampBe Big-endian idtimestamp of included grant
    ///    content (for leaf commitment).
    /// @param publishGrant LogId, grant flags, max_height, min_growth for leaf
    ///    commitment and bounds; any sender may submit.
    function publishCheckpoint(
        ConsistencyReceipt calldata consistencyParts,
        InclusionProof calldata grantInclusionProof,
        bytes8 grantIDTimestampBe,
        PublishGrant calldata publishGrant
    ) external;
}
