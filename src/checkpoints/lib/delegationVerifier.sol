// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {
    buildSigStructure,
    extractAlgorithm,
    verifyKS256Raw
} from "@univocity/cosecbor/cosecbor.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Verifies COSE-shaped delegation proofs (no cert decode). ADR-0006.
///    Aligns with algorithms as free functions. Per-alg variants take
///    pre-decoded keys; caller uses decodeDelegationKey* in the appropriate
///    alg branch.

// === Errors ===

error InvalidDelegationKeyLength(uint256 length);
error InvalidDelegationSignatureLength(uint256 length);
error DelegationSignatureInvalid();
error CheckpointIndexOutOfDelegationRange();

bytes constant DELEGATION_DOMAIN = "forestrie.univocity.delegation.v1";

/// @notice Decode ES256 delegation key (64 bytes = P-256 x || y).
///    Caller is responsible for being in the ES256 alg branch; no alg check.
/// @param delegationKey Must be exactly 64 bytes.
function decodeDelegationKeyES256(bytes calldata delegationKey)
    pure
    returns (bytes32 keyX, bytes32 keyY)
{
    if (delegationKey.length != 64) {
        revert InvalidDelegationKeyLength(delegationKey.length);
    }
    assembly {
        keyX := calldataload(delegationKey.offset)
        keyY := calldataload(add(delegationKey.offset, 32))
    }
}

/// @notice Verify ES256 delegation proof: root (storedRootX, storedRootY)
///    signed a COSE Sign1 Sig_structure binding
///    (domain, logId, mmrStart, mmrEnd, delegatedKey).
///    Delegation key is pre-decoded; use decodeDelegationKeyES256 first.
function verifyDelegationProofES256(
    bytes calldata protectedHeader,
    uint64 mmrStart,
    uint64 mmrEnd,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    bytes32 storedRootX,
    bytes32 storedRootY,
    bytes32 delegatedKeyX,
    bytes32 delegatedKeyY
) view {
    if (extractAlgorithm(protectedHeader) != ALG_ES256) {
        revert DelegationSignatureInvalid();
    }
    if (signature.length != 64) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (storedRootX == 0 && storedRootY == 0) {
        revert DelegationSignatureInvalid();
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    bytes memory payload = abi.encodePacked(
        DELEGATION_DOMAIN,
        logId,
        mmrStart,
        mmrEnd,
        delegatedKeyX,
        delegatedKeyY
    );
    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
    bytes32 canonicalHash = sha256(sigStructure);
    bytes32 r;
    bytes32 s;
    assembly {
        r := calldataload(signature.offset)
        s := calldataload(add(signature.offset, 32))
    }
    if (!P256.verify(canonicalHash, r, s, storedRootX, storedRootY)) {
        revert DelegationSignatureInvalid();
    }
}

/// @notice Verify KS256 delegation proof: root (storedRoot address) signed a
///    COSE Sign1 Sig_structure binding
///    (domain, logId, mmrStart, mmrEnd, delegatedKey).
///    Delegated key is pre-decoded ES256 (x, y); use
///    decodeDelegationKeyES256 first.
function verifyDelegationProofKS256(
    bytes calldata protectedHeader,
    uint64 mmrStart,
    uint64 mmrEnd,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    address storedRoot,
    bytes32 delegatedKeyX,
    bytes32 delegatedKeyY
) view {
    if (extractAlgorithm(protectedHeader) != ALG_KS256) {
        revert DelegationSignatureInvalid();
    }
    if (storedRoot == address(0)) {
        revert DelegationSignatureInvalid();
    }
    if (storedRoot.code.length == 0 && signature.length != 65) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    bytes memory payload = abi.encodePacked(
        DELEGATION_DOMAIN,
        logId,
        mmrStart,
        mmrEnd,
        delegatedKeyX,
        delegatedKeyY
    );
    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
    if (!verifyKS256Raw(sigStructure, signature, storedRoot)) {
        revert DelegationSignatureInvalid();
    }
}
