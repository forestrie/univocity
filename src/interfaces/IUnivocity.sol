// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IUnivocityEvents} from "./IUnivocityEvents.sol";
import {
    LogConfig,
    LogState,
    ConsistencyReceipt,
    InclusionProof,
    PublishGrant
} from "@univocity/interfaces/types.sol";

/// @title IUnivocity
/// @notice Interface for univocity transparency log contract (payment-bounded
///    checkpoint authorization via grant inclusion proof and bounds).
interface IUnivocity is IUnivocityEvents {
    // === View Functions ===

    /// @notice Bootstrap key in opaque form (same as constructor). Plan 0018.
    /// @return bootstrapAlg COSE alg (ALG_KS256 or ALG_ES256).
    /// @return bootstrapKey 20 bytes (KS256) or 64 bytes (ES256).
    function bootstrapConfig()
        external
        view
        returns (int64 bootstrapAlg, bytes memory bootstrapKey);
    function rootLogId() external view returns (bytes32);
    function logState(bytes32 logId) external view returns (LogState memory);
    function logConfig(bytes32 logId) external view returns (LogConfig memory);
    function logRootKey(bytes32 logId)
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
