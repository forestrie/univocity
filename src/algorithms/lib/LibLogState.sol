// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LogState, PublishGrant} from "@univocity/interfaces/types.sol";
import {
    verifyInclusion as _verifyInclusion,
    verifyInclusionAtSize as _verifyInclusionAtSize,
    verifyInclusionStorage as _verifyInclusionStorage
} from "@univocity/algorithms/includedRoot.sol";
import {committingPeakIndex} from "@univocity/algorithms/peaks.sol";

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
    /// @notice Accumulator slot of the peak that commits MMR node `index` in
    ///    the complete MMR(size): the peak whose tree holds the node. The
    ///    one formula behind both committing-peak readers, found in one pass
    ///    over the peaks by committingPeakIndex.
    /// @param index Zero-based MMR index of the node; index < size.
    /// @param size Number of nodes in the complete MMR; size > 0.
    /// @return Index into the accumulator of the committing peak.
    function committingPeakSlot(uint256 index, uint256 size)
        internal
        pure
        returns (uint256)
    {
        return committingPeakIndex(index, size);
    }

    /// @notice Storage variant: the anchored size and the peak committing
    ///    node `index`, read without copying the accumulator to memory.
    /// @param log The log's stored state.
    /// @param index Zero-based MMR index of the node.
    /// @return size The log's anchored size; 0 for an uninitialised log.
    /// @return peak The committing peak; zero when index >= size.
    function committingPeakStorage(LogState storage log, uint256 index)
        internal
        view
        returns (uint64 size, bytes32 peak)
    {
        size = log.size;
        if (index >= size) return (size, bytes32(0));
        uint256 slot = committingPeakSlot(index, size);
        if (slot < log.accumulator.length) peak = log.accumulator[slot];
    }

    /// @notice Memory variant of committingPeakStorage, for a state fetched
    ///    through logState.
    /// @param log The log's state.
    /// @param index Zero-based MMR index of the node.
    /// @return size The log's anchored size; 0 for an uninitialised log.
    /// @return peak The committing peak; zero when index >= size.
    function committingPeak(LogState memory log, uint256 index)
        internal
        pure
        returns (uint64 size, bytes32 peak)
    {
        size = log.size;
        if (index >= size) return (size, bytes32(0));
        uint256 slot = committingPeakSlot(index, size);
        if (slot < log.accumulator.length) peak = log.accumulator[slot];
    }

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

