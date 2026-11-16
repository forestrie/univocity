// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IUnivocityVerifier
/// @notice Leaf inclusion against a univocity instance's anchored log state,
///    as the publication enforcer consumes it (devdocs ARC-0032 §4.2).
interface IUnivocityVerifier {
    /// @notice Verifies that `leaf` is the leaf at MMR index `index` of the
    ///    log, as anchored on chain now.
    /// @param logId Log whose anchored accumulator and size are used.
    /// @param index Zero-based MMR index of the leaf.
    /// @param leaf Leaf hash: sha256(idTimestamp ‖ sha256(statement)).
    /// @param path Inclusion path built at the anchored size or any later
    ///    one; only its prefix to the anchored committing peak is used.
    /// @return True if the leaf is anchored at that index; false otherwise,
    ///    including a leaf beyond the anchored size.
    function verifyInclusionAtAnchored(
        bytes32 logId,
        uint256 index,
        bytes32 leaf,
        bytes32[] calldata path
    ) external view returns (bool);
}
