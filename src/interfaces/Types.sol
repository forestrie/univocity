// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

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

/// @notice Pre-decoded consistency receipt (plan 0016). No COSE envelope
///    parse on-chain. Consistency proofs are pre-decoded (no CBOR).
struct ConsistencyReceipt {
    bytes protectedHeader;
    bytes signature;
    ConsistencyProof[] consistencyProofs;
    DelegationProof delegationProof;
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
