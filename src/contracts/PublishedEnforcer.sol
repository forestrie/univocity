// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ICaveatEnforcer} from "@univocity/interfaces/ICaveatEnforcer.sol";
import {
    IUnivocityVerifier
} from "@univocity/interfaces/IUnivocityVerifier.sol";
import {
    IUnivocityVerifierFactory
} from "@univocity/interfaces/IUnivocityVerifierFactory.sol";

/// @title PublishedEnforcer
/// @notice ERC-7710 caveat enforcer that refuses a delegation unless a
///    statement committing to it is anchored in the univocity log its
///    signed terms name (devdocs ARC-0032 §4.1). Stateless, holds no funds,
///    and serves every forest on its chain.
/// @dev The statement is never parsed on chain. The delegation manager
///    supplies the delegation's EIP-712 struct hash; the enforcer rebuilds
///    the statement as prefix ‖ DELEGATION_TAG ‖ delegationHash ‖ suffix from
///    unsigned redeemer arguments, rebuilds the frozen log leaf
///    sha256(idTimestamp ‖ sha256(statement)) (ARC-0032 §4.4), and asks the
///    instance's verifier whether that leaf is anchored. The arguments can
///    only reproduce a leaf that is already anchored, so they need no
///    trust. It proves the tagged hash is in the log, not that the
///    statement is well formed (ARC-0032 §9).
///    MMR leaf and path shapes: draft-bryce-cose-receipts-mmr-profile.
contract PublishedEnforcer is ICaveatEnforcer {
    /// @notice Domain tag preceding the delegation hash in a delegation
    ///    statement: sha256("univocity/erc7710-delegation/v1").
    /// @dev Provisional: protocol's delegation statement type fixes the
    ///    value with vectors.
    bytes32 public constant DELEGATION_TAG =
        0xb09bc7d90e4fa6b305d213aa3f89a5df627c8bace691cabe3ccbe1bd85251649;

    /// @notice Finds the verifier of the instance a hop names.
    IUnivocityVerifierFactory public immutable factory;

    /// @notice Redeemer arguments, abi-encoded in the caveat's `args`.
    /// @param prefix Statement bytes before DELEGATION_TAG ‖ delegationHash.
    /// @param suffix Statement bytes after them.
    /// @param idTimestamp The statement's log idtimestamp; packs to the
    ///    8 big-endian bytes the leaf needs.
    /// @param mmrIndex MMR index of the statement's leaf.
    /// @param path Inclusion path, built at the anchored size or later.
    struct PublishedArgs {
        bytes prefix;
        bytes suffix;
        uint64 idTimestamp;
        uint256 mmrIndex;
        bytes32[] path;
    }

    /// @notice Terms are not abi.encode(address instance, bytes32 logId).
    error InvalidTerms();

    /// @notice The named instance has no verifier yet (ARC-0032 §13,
    ///    verifier backfill).
    /// @param delegationHash The refused delegation's struct hash; it
    ///    identifies the hop.
    /// @param instance The instance the hop's terms name.
    error VerifierMissing(bytes32 delegationHash, address instance);

    /// @notice No anchored statement in `logId` commits to the delegation.
    /// @param delegationHash The refused delegation's struct hash; it
    ///    identifies the hop.
    /// @param logId The log its terms name.
    error NotPublished(bytes32 delegationHash, bytes32 logId);

    /// @param factory_ Verifier lookup for univocity instances on this chain.
    constructor(IUnivocityVerifierFactory factory_) {
        factory = factory_;
    }

    /// @notice Reverts unless the delegation's statement is anchored.
    /// @param terms abi.encode(address instance, bytes32 logId), signed by
    ///    the delegator. A wrong instance only weakens its own delegation.
    /// @param args abi.encode(PublishedArgs); unsigned.
    /// @param delegationHash Struct hash the manager computed.
    function beforeHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32,
        bytes calldata,
        bytes32 delegationHash,
        address,
        address
    ) external view {
        if (terms.length != 64) revert InvalidTerms();
        (address instance, bytes32 logId) =
            abi.decode(terms, (address, bytes32));
        PublishedArgs memory a = abi.decode(args, (PublishedArgs));

        bytes32 statementHash = sha256(
            abi.encodePacked(
                a.prefix, DELEGATION_TAG, delegationHash, a.suffix
            )
        );
        bytes32 leaf = sha256(abi.encodePacked(a.idTimestamp, statementHash));

        address verifier = factory.verifierFor(instance);
        if (verifier.code.length == 0) {
            revert VerifierMissing(delegationHash, instance);
        }
        if (!IUnivocityVerifier(verifier)
                .verifyInclusionAtAnchored(logId, a.mmrIndex, leaf, a.path)) {
            revert NotPublished(delegationHash, logId);
        }
    }

    /// @notice No check before all executions.
    function beforeAllHook(
        bytes calldata,
        bytes calldata,
        bytes32,
        bytes calldata,
        bytes32,
        address,
        address
    ) external pure {}

    /// @notice No check after the execution.
    function afterHook(
        bytes calldata,
        bytes calldata,
        bytes32,
        bytes calldata,
        bytes32,
        address,
        address
    ) external pure {}

    /// @notice No check after all executions.
    function afterAllHook(
        bytes calldata,
        bytes calldata,
        bytes32,
        bytes calldata,
        bytes32,
        address,
        address
    ) external pure {}
}
