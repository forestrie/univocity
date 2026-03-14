// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PublishGrant} from "@univocity/interfaces/types.sol";

/// @notice Encoding helpers for leaf commitment: inner preimage and leaf hash.
/// @dev Canonical encoding matches _leafCommitment (LibLogState): inner =
///      abi.encodePacked(logId, grant, maxHeight, minGrowth, ownerLogId, grantData).
///      Sizes: logId 32, grant 32, maxHeight 8, minGrowth 8, ownerLogId 32, grantData variable.
///      Padding convention: logId and ownerLogId are bytes32 (32 bytes); 16-byte UUIDs
///      are right-padded to 32. grant is uint256 (32 bytes); 8-byte grant flags use the
///      low 8 bytes (big-endian), high 24 bytes zero.
library LibLeafEncoding {
    /// @notice Returns the inner preimage bytes (input to the inner sha256).
    function innerPreimage(PublishGrant memory g)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            g.logId,
            g.grant,
            g.maxHeight,
            g.minGrowth,
            g.ownerLogId,
            g.grantData
        );
    }

    /// @notice Returns leaf = sha256(grantIDTimestampBe || sha256(innerPreimage(g))).
    function leafCommitment(bytes8 grantIDTimestampBe, PublishGrant memory g)
        internal
        pure
        returns (bytes32)
    {
        bytes memory inner = innerPreimage(g);
        bytes32 innerHash = sha256(inner);
        return sha256(abi.encodePacked(grantIDTimestampBe, innerHash));
    }
}
