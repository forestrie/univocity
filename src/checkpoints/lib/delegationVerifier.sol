// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Verifies delegation: minimal proof (no COSE cert decode). Plan 0016.
///    Aligns with algorithms as free functions. Per-alg variants take
///    pre-decoded keys; caller uses decodeDelegationKey* in the appropriate
///    alg branch.

// === Errors ===

error InvalidDelegationKeyLength(uint256 length);
error InvalidDelegationSignatureLength(uint256 length);
error DelegationSignatureInvalid();
error CheckpointIndexOutOfDelegationRange();

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
        keyX := calldataload(add(delegationKey.offset, 32))
        keyY := calldataload(add(delegationKey.offset, 64))
    }
}

/// @notice Verify ES256 delegation proof: root (storedRootX, storedRootY)
///    signed canonical message binding (logId, mmrStart, mmrEnd, delegatedKey).
///    Delegation key is pre-decoded; use decodeDelegationKeyES256 first.
function verifyDelegationProofES256(
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
    if (signature.length != 64) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (storedRootX == 0 && storedRootY == 0) {
        revert DelegationSignatureInvalid();
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    bytes32 canonicalHash = sha256(
        abi.encodePacked(logId, mmrStart, mmrEnd, delegatedKeyX, delegatedKeyY)
    );
    bytes32 r;
    bytes32 s;
    assembly {
        r := calldataload(add(signature.offset, 32))
        s := calldataload(add(signature.offset, 64))
    }
    if (!P256.verify(canonicalHash, r, s, storedRootX, storedRootY)) {
        revert DelegationSignatureInvalid();
    }
}
