// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LogState, PublishGrant} from "@univocity/interfaces/types.sol";
import {
    verifyInclusion as _verifyInclusion,
    verifyInclusionAtSize as _verifyInclusionAtSize,
    verifyInclusionStorage as _verifyInclusionStorage
} from "@univocity/algorithms/includedRoot.sol";

function _leafCommitment(bytes8 grantIDTimestampBe, PublishGrant calldata g)
    pure
    returns (bytes32)
{
    bytes32 inner = sha256(
        abi.encodePacked(
            g.logId,
            g.grant,
            g.maxHeight,
            g.minGrowth,
            g.ownerLogId,
            g.grantData
        )
    );
    return sha256(abi.encodePacked(grantIDTimestampBe, inner));
}

library LibLogState {
    function verifyInclusion(
        LogState memory log,
        uint256 index,
        bytes32 node,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        return _verifyInclusion(index, node, proof, log.accumulator, log.size);
    }

    /// @notice Leaf inclusion at the log's anchored size, accepting a path
    ///    built at a later size (includedRoot.verifyInclusionAtSize).
    function verifyInclusionAtAnchored(
        LogState memory log,
        uint256 index,
        bytes32 leaf,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        if (log.size == 0) return false;
        return
            _verifyInclusionAtSize(
                index, leaf, proof, log.accumulator, log.size
            );
    }

    /// @notice Storage variant: reads accumulator/size from storage (uses
    ///    proofLengthRootStorage; no full accumulator copy to memory).
    function verifyInclusionStorage(
        LogState storage log,
        uint256 index,
        bytes32 node,
        bytes32[] calldata proof
    ) internal view returns (bool) {
        return _verifyInclusionStorage(
            index, node, proof, log.accumulator, log.size
        );
    }

    function verifyGrantInclusion(
        LogState memory log,
        PublishGrant calldata publishGrant,
        bytes8 grantIDTimestampBe,
        uint256 index,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        bytes32 leafCommitment = _leafCommitment(
            grantIDTimestampBe, publishGrant
        );
        return _verifyInclusion(
            index, leafCommitment, proof, log.accumulator, log.size
        );
    }

    /// @notice Storage variant: reads accumulator/size from storage (uses
    ///    proofLengthRootStorage; no full accumulator copy to memory).
    function verifyGrantInclusionStorage(
        LogState storage log,
        PublishGrant calldata publishGrant,
        bytes8 grantIDTimestampBe,
        uint256 index,
        bytes32[] calldata proof
    ) internal view returns (bool) {
        bytes32 leafCommitment = _leafCommitment(
            grantIDTimestampBe, publishGrant
        );
        return _verifyInclusionStorage(
            index, leafCommitment, proof, log.accumulator, log.size
        );
    }
}

